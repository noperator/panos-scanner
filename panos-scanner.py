#!/usr/bin/env python3

"""
Developed with <3 by the Bishop Fox Continuous Attack Surface Testing (CAST) team.
https://www.bishopfox.com/continuous-attack-surface-testing/how-cast-works/

Author:     @noperator
Purpose:    Determine the software version of a remote PAN-OS target.
Notes:      - Requires version-table.txt in the same directory.
            - Usage of this tool for attacking targets without prior mutual
              consent is illegal. It is the end user's responsibility to obey
              all applicable local, state, and federal laws. Developers assume
              no liability and are not responsible for any misuse or damage
              caused by this program.
Usage:      python3 panos-scanner.py [-h] [-v] [-s] -t TARGET
"""

import argparse
import datetime
import json
import logging
import requests
import requests.exceptions
import sys
import time
import urllib3
import urllib3.exceptions

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

verbose = False

# Set up logging.
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.Formatter.converter = time.gmtime


def etag_to_datetime(etag):
    epoch_hex = etag[-8:]
    return datetime.datetime.fromtimestamp(int(epoch_hex, 16)).date()


def last_modified_to_datetime(last_modified):
    return datetime.datetime.strptime(last_modified[:-4], "%a, %d %b %Y %X").date()


def get_resource(target, resource, date_headers, errors):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0",
        "Connection": "close",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade-Insecure-Requests": "1",
    }
    logger.debug(resource)
    try:
        resp = requests.get(
            "%s/%s" % (target, resource), headers=headers, timeout=5, verify=False
        )
        resp.raise_for_status()
        return {
            h: resp.headers[h].strip('"') for h in date_headers if h in resp.headers
        }
    except (requests.exceptions.HTTPError, requests.exceptions.ReadTimeout) as e:
        logger.warning(type(e).__name__)
        return None
    except errors as e:
        raise e


def load_version_table(version_table):
    with open(version_table, "r") as f:
        entries = [line.strip().split() for line in f.readlines()]
    return {
        e[0]: datetime.datetime.strptime(" ".join(e[1:]), "%b %d %Y").date()
        for e in entries
    }


def check_date(version_table, date):
    matches = {}
    for n in [0, 1, -1, 2, -2]:
        nearby_date = date + datetime.timedelta(n)
        versions = [
            version for version, date in version_table.items() if date == nearby_date
        ]
        if n == 0:
            key = "exact"
        else:
            key = "approximate"
        if key not in matches:
            matches[key] = {"date": nearby_date, "versions": versions}
    return matches


def get_matches(date_headers, resp_headers, version_table):
    matches = {}
    for header in date_headers.keys():
        if header in resp_headers:
            date = globals()[date_headers[header]](resp_headers[header])
            date_matches = check_date(version_table, date)
            for precision, match in date_matches.items():
                if match["versions"]:
                    if precision not in matches.keys():
                        matches[precision] = []
                    matches[precision].append(match)
                    if date != match["date"]:
                        date_str = f"{date} ~ {match['date']}"
                    else:
                        date_str = date
                    logger.debug(
                        f"date {date_str} matches version(s) {','.join(match['versions'])}"
                    )
    return matches


def main():

    # Parse arguments.
    parser = argparse.ArgumentParser(
        """
        Determine the software version of a remote PAN-OS target. Requires
        version-table.txt in the same directory. Usage of this tool for
        attacking targets without prior mutual consent is illegal. It is the
        end user's responsibility to obey all applicable local, state, and
        federal laws. Developers assume no liability and are not responsible
        for any misuse or damage caused by this program.
        """
    )
    parser.add_argument(
        "-v", dest="verbose", action="store_true", help="verbose output"
    )
    parser.add_argument(
        "-s", dest="stop", action="store_true", help="stop after one exact match"
    )
    parser.add_argument(
        "-c",
        dest="link_cve_url",
        action="store_true",
        help="link to PAN-OS CVE URL for discovered versions",
    )
    parser.add_argument("-t", dest="target", required=True, help="https://example.com")
    args = parser.parse_args()

    static_resources = [
        "global-protect/login.esp",
        "php/login.php",
        "global-protect/portal/css/login.css",
        "js/Pan.js",
        "global-protect/portal/images/favicon.ico",
        "login/images/favicon.ico",
        "global-protect/portal/images/logo-pan-48525a.svg",
    ]

    version_table = load_version_table("version-table.txt")

    # The keys in "date_headers" represent HTTP response headers that we're
    # looking for. Each of those headers maps to a function in this namespace
    # that knows how to decode that header value into a datetime.
    date_headers = {
        "ETag": "etag_to_datetime",
        "Last-Modified": "last_modified_to_datetime",
    }

    # A match is a dictionary containing a date/version pair. When populated,
    # each precision key (i.e., "exact" and "approximate") in this
    # "total_matches" data structure will map to a single list of possibly
    # several match dictionaries.
    total_matches = {"exact": [], "approximate": []}

    # These errors are indicative of target-level issues. Don't continue
    # requesting other resources when encountering these; instead, bail.
    target_errors = (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.SSLError,
        requests.exceptions.ConnectionError,
    )

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"scanning target: {args.target}")

    # Check for the presence of each static resource.
    for resource in static_resources:
        try:
            resp_headers = get_resource(
                args.target,
                resource,
                date_headers.keys(),
                target_errors,
            )
        except target_errors as e:
            logger.error(f"could not connect to target: {type(e).__name__}")
            sys.exit(1)
        if resp_headers == None:
            continue

        # Convert date-related HTTP headers to a standardized format, and
        # store any matching version strings.
        total_matches.update(get_matches(date_headers, resp_headers, version_table))
        if args.stop and len(total_matches["exact"]):
            break

    # Print results.
    if not len(sum(total_matches.values(), [])):
        logger.info("no matching versions found")
    else:
        printed = []
        for precision, matches in total_matches.items():
            for match in matches:
                if match["versions"] and match not in printed:
                    printed.append(match)
                    if args.link_cve_url:
                        cve_url = "https://security.paloaltonetworks.com/?product=PAN-OS&version=PAN-OS+"
                        for version in match["versions"]:
                            major, minor = version.split(".")[:2]
                            logger.info(
                                "CVEs for PAN-OS v{}.{}: {}{}.{}".format(
                                    major, minor, cve_url, major, minor
                                ),
                            )
                    logger.info(
                        f"{precision} match: versions(s) {','.join(match['versions'])} for date {match['date']}"
                    )

    print(json.dumps(total_matches, default=str))


if __name__ == "__main__":
    main()
