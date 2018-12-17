#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import signal
import sys
import time
import json
from queue import Queue
from threading import Lock
from threading import Event
from threading import Thread

import requests
import tldextract
import yaml
from boto3.session import Session
from certstream.core import CertStreamClient
from requests.adapters import HTTPAdapter
from termcolor import cprint

ARGS = argparse.Namespace()
CONFIG = yaml.safe_load(open("config.yaml"))
KEYWORDS = [line.strip() for line in open("keywords.txt")]
S3_URL = "http://s3-1-w.amazonaws.com"
BUCKET_HOST = "%s.s3.amazonaws.com"
QUEUE_SIZE = CONFIG['queue_size']
UPDATE_INTERVAL = CONFIG['update_interval']  # seconds
RATE_LIMIT_SLEEP = CONFIG['rate_limit_sleep']  # seconds
THREADS = list()
THREAD_EVENT = Event()
FOUND_COUNT = 0


class UpdateThread(Thread):
    def __init__(self, q, perms_count, *args, **kwargs):
        self.q = q
        self.perms_count = perms_count
        self.num_possible_buckets_since_last_update = 0
        self.num_checked_buckets_since_last_update = 0
        self.found_count_since_last_update = 0

        super().__init__(*args, **kwargs)

    def run(self):
        global THREAD_EVENT

        while not THREAD_EVENT.is_set():
            num_possible_buckets = len(self.q.discovered_domains) * self.perms_count
            num_checked_buckets = self.q.num_checked_buckets

            cprint("{0} new buckets possible ({1:.0f}b/s), {2} new buckets checked ({3:.0f}b/s), {4} new buckets "
                   "found, queue size = {5}, rate limited = {6}".format(
                num_possible_buckets - self.num_possible_buckets_since_last_update,
                (num_possible_buckets - self.num_possible_buckets_since_last_update) / UPDATE_INTERVAL,
                num_checked_buckets - self.num_checked_buckets_since_last_update,
                (num_checked_buckets - self.num_checked_buckets_since_last_update) / UPDATE_INTERVAL,
                FOUND_COUNT - self.found_count_since_last_update,
                len(self.q.queue),
                self.q.rate_limited
            ), "cyan")

            if len(self.q.queue) > QUEUE_SIZE * 0.99:
                cprint("Queue is filled! Discovery of new domains and possible buckets will slow down...", "red")

            self.num_possible_buckets_since_last_update = num_possible_buckets
            self.num_checked_buckets_since_last_update = num_checked_buckets
            self.found_count_since_last_update = FOUND_COUNT
            THREAD_EVENT.wait(UPDATE_INTERVAL)


class CertStreamThread(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.c = CertStreamClient(
            self.process, skip_heartbeats=True, on_open=None, on_error=None)

        super().__init__(*args, **kwargs)

    def run(self):
        global THREAD_EVENT
        while not THREAD_EVENT.is_set():
            cprint("Waiting for Certstream events - this could take a few minutes to queue up...",
                   "yellow", attrs=["bold"])
            self.c.run_forever()
            THREAD_EVENT.wait(10)

    def process(self, message, context):
        if message["message_type"] == "heartbeat":
            return

        if message["message_type"] == "certificate_update":
            all_domains = message["data"]["leaf_cert"]["all_domains"]

            if ARGS.skip_lets_encrypt and "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
                return

            for domain in set(all_domains):
                # cut the crap
                if not domain.startswith("*.") \
                        and "cloudflaressl" not in domain \
                        and "xn--" not in domain \
                        and domain.count("-") < 4 \
                        and domain.count(".") < 4:

                    parts = tldextract.extract(domain)

                    if parts.domain not in self.q.discovered_domains:
                        for permutation in get_permutations(parts.domain, parts.subdomain):
                            self.q.put(BUCKET_HOST % permutation)
                        self.q.discovered_domains.add(parts.domain)


class BucketQueue(Queue):
    def __init__(self, maxsize):
        self.lock = Lock()
        self.discovered_domains = set()
        self.num_checked_buckets = 0
        self.rate_limited = False
        self.next_yield = 0

        super().__init__(maxsize)

    def put(self, bucket_url):
        super().put(bucket_url)

    def get(self):
        global THREAD_EVENT
        with self.lock:
            t = time.monotonic()
            if self.rate_limited and t < self.next_yield:
                cprint("You have hit the AWS rate limit - slowing down... (tip: enter credentials in config.yaml)",
                       "yellow")
                THREAD_EVENT.wait(self.next_yield - t)
                t = time.monotonic()
                self.rate_limited = False

            self.next_yield = t + RATE_LIMIT_SLEEP

        item = super().get()
        self.num_checked_buckets += 1
        return item


class BucketWorker(Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.use_aws = CONFIG["aws_access_key"] and CONFIG["aws_secret"]

        if self.use_aws:
            self.session = Session(
                aws_access_key_id=CONFIG["aws_access_key"], aws_secret_access_key=CONFIG["aws_secret"]).resource("s3")
        else:
            self.session = requests.Session()
            self.session.mount(
                "http://", HTTPAdapter(pool_connections=ARGS.threads, pool_maxsize=QUEUE_SIZE, max_retries=0))

        super().__init__(*args, **kwargs)

    def run(self):
        global THREAD_EVENT
        while not THREAD_EVENT.is_set():
            try:
                bucket_url = self.q.get()
                self.__check_boto(
                    bucket_url) if self.use_aws else self.__check_http(bucket_url)
            except Exception as e:
                print(e)
                pass
            finally:
                self.q.task_done()

    def __check_http(self, bucket_url):
        check_response = self.session.head(
            S3_URL, timeout=3, headers={"Host": bucket_url})

        if not ARGS.ignore_rate_limiting \
                and (check_response.status_code == 503 and check_response.reason == "Slow Down"):
            self.q.rate_limited = True
            # add it back to the queue for re-processing
            self.q.put(bucket_url)
        elif check_response.status_code == 307:  # valid bucket, lets check if its public
            new_bucket_url = check_response.headers["Location"]
            bucket_response = requests.request(
                "GET" if ARGS.only_interesting else "HEAD", new_bucket_url, timeout=3)

            if bucket_response.status_code == 200 \
                    and (not ARGS.only_interesting or
                         (ARGS.only_interesting and any(keyword in bucket_response.text for keyword in KEYWORDS))):
                self.__output("Found bucket '{}'".format(new_bucket_url), "green")
                self.__log(new_bucket_url)

    def __check_boto(self, bucket_url):
        bucket_name = bucket_url.replace(".s3.amazonaws.com", "")

        try:
            # just to check if the bucket exists. Throws NoSuchBucket exception if not
            self.session.meta.client.head_bucket(Bucket=bucket_name)

            if not ARGS.only_interesting or \
                    (ARGS.only_interesting and self.__bucket_contains_any_keywords(bucket_name)):
                owner = None
                acls = None

                try:
                    # todo: also check IAM policy as it can override ACLs
                    acl = self.session.meta.client.get_bucket_acl(Bucket=bucket_name)
                    owner = acl["Owner"]["DisplayName"]
                    acls = ". ACLs = {} | {}".format(self.__get_group_acls(acl, "AllUsers"),
                                                     self.__get_group_acls(acl, "AuthenticatedUsers"))
                except:
                    acls = ". ACLS = (could not read)"

                color = "green" if not owner else "magenta"
                self.__output("Found bucket '{}'. Owned by '{}'{}".format(
                    bucket_url, owner if owner else "(unknown)", acls), color)
                self.__log(bucket_url)
        except Exception as e:
            pass

    def __get_group_acls(self, acl, group):
        group_uri = "http://acs.amazonaws.com/groups/global/%s" % group
        perms = [g["Permission"] for g in acl["Grants"]
                 if g["Grantee"]["Type"] == "Group" and g["Grantee"]["URI"] == group_uri]

        return "{}: {}".format(group, ", ".join(perms) if perms else "(none)")

    def __bucket_contains_any_keywords(self, bucket_name):
        try:
            objects = [o.key for o in self.session.Bucket(bucket_name).objects.all()]
            return any(keyword in ",".join(objects) for keyword in KEYWORDS)
        except:
            return False

    def __log(self, new_bucket_url):
        global FOUND_COUNT
        FOUND_COUNT += 1

        if ARGS.log_to_file:
            with open("buckets.log", "a+") as log:
                log.write("%s%s" % (new_bucket_url, os.linesep))

    def __output(self, line, color=None):
        cprint(line, color, attrs=["bold"])

        if CONFIG["slack_webhook"]:
            resp = requests.post(CONFIG['slack_webhook'], data=json.dumps({'text': line}),
                                 headers={'Content-Type': 'application/json'})
            if resp.status_code != 200:
                cprint("Could not send to your Slack Webhook. Server returned: %s" % resp.status_code, "red")


def get_permutations(domain, subdomain=None):
    perms = [
        "%s" % domain,
        "www-%s" % domain,
        "%s-www" % domain,
    ]

    perms.extend([line.strip() % domain for line in open(ARGS.permutations)])

    if subdomain is not None:
        perms.extend([
            "%s-%s" % (subdomain, domain) if subdomain else "",
            "%s-%s" % (domain, subdomain) if subdomain else ""
        ])

    return filter(None, perms)


def stop():
    global THREAD_EVENT
    cprint("Kill commanded received - Quitting...", "yellow", attrs=["bold"])
    THREAD_EVENT.set()
    sys.exit(0)


def __signal_handler(signal, frame):
    stop()


def main():
    global THREADS

    signal.signal(signal.SIGINT, __signal_handler)

    parser = argparse.ArgumentParser(
        description="Find interesting Amazon S3 Buckets by watching certificate transparency logs.",
        usage="python bucket-stream.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--only-interesting", action="store_true", dest="only_interesting", default=False,
                        help="Only log 'interesting' buckets whose contents match anything within keywords.txt")
    parser.add_argument("--skip-lets-encrypt", action="store_true", dest="skip_lets_encrypt", default=False,
                        help="Skip certs (and thus listed domains) issued by Let's Encrypt CA")
    parser.add_argument("-t", "--threads", metavar="", type=int, dest="threads", default=20,
                        help="Number of threads to spawn. More threads = more power. Limited to 5 threads if unauthenticated.")
    parser.add_argument("--ignore-rate-limiting", action="store_true", dest="ignore_rate_limiting", default=False,
                        help="If you ignore rate limits not all buckets will be checked")
    parser.add_argument("-l", "--log", dest="log_to_file", default=False, action="store_true",
                        help="Log found buckets to a file buckets.log")
    parser.add_argument("-p", "--permutations", dest="permutations", default="permutations\default.txt",
                        help="Path of file containing a list of permutations to try (see permutations/ dir).")

    parser.parse_args(namespace=ARGS)
    logging.disable(logging.WARNING)

    if not CONFIG["aws_access_key"] or not CONFIG["aws_secret"]:
        cprint("It is highly recommended to enter AWS keys in config.yaml otherwise you will be severely rate limited!" \
               "You might want to run with --ignore-rate-limiting", "red")

        if ARGS.threads > 5:
            cprint("No AWS keys, reducing threads to 5 to help with rate limiting.", "red")
            ARGS.threads = 5

    perms_count = len([x for x in get_permutations("")])
    THREADS = list()

    cprint("Starting bucket-stream with {0} threads. Loaded {1} permutations." \
           .format(ARGS.threads, perms_count), "green")

    q = BucketQueue(maxsize=QUEUE_SIZE)
    THREADS.extend([BucketWorker(q) for _ in range(0, ARGS.threads)])
    THREADS.extend([UpdateThread(q, perms_count)])

    THREADS.extend([CertStreamThread(q)])

    for t in THREADS:
        t.daemon = True
        t.start()

    while True:
        try:
            signal.pause()
        except AttributeError:
            # signal.pause() not implemented on windows
            while not THREAD_EVENT.is_set():
                time.sleep(1)

        stop()


if __name__ == "__main__":
    main()
