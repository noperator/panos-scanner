#!/usr/bin/env python3

'''
Developed with <3 by the Bishop Fox Continuous Attack Surface Testing (CAST) team.
https://www.bishopfox.com/continuous-attack-surface-testing/how-cast-works/

Author:     @noperator
Purpose:    Determine the software version of a remote PAN-OS target.
Notes:      Requires version-table.txt in the same directory.
Usage:      python3 -t panos-scanner.py <TARGET>
'''

from argparse import ArgumentParser
from datetime import datetime, timedelta
from pprint import pprint
from requests import get
from requests.exceptions import HTTPError, ConnectTimeout, SSLError, ConnectionError, ReadTimeout
from sys import argv, stderr, exit
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

def etag_to_datetime(etag):
    epoch_hex = etag[-8:]
    return datetime.fromtimestamp(
               int(epoch_hex, 16)
           ).date()

def last_modified_to_datetime(last_modified):
    return datetime.strptime(
               last_modified[:-4],
               '%a, %d %b %Y %X'
           ).date()

def get_resource(target, resources, date_headers, errors):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
            'Connection': 'close',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Upgrade-Insecure-Requests': '1'
        }
        resp = get(
            '%s/%s' % (target, resource),
            headers=headers,
            timeout=10,
            verify=False
        )
        print(resp.status_code, resource, file=stderr)
        resp.raise_for_status()
        return {h: resp.headers[h].strip('"') for h in date_headers
                if h in resp.headers}
    except (HTTPError, ReadTimeout) as e:
        pass
    except errors as e:
        raise e

def load_version_table(version_table):
    with open(version_table, 'r') as f:
        entries = [line.strip().split() for line in f.readlines()]
    return {e[0]: datetime.strptime(' '.join(e[1:]), '%b %d %Y').date()
            for e in entries}

def check_date(version_table, date):
    matches = {}
    for n in [0, 1, -1, 2, -2]:
        nearby_date = date + timedelta(n)
        versions = [version for version, date in version_table.items()
                    if date == nearby_date]
        if n == 0:
            key = 'exact'
        else:
            key = 'approximate'
        matches[key] = versions
        if versions:
            print('[+]', nearby_date, '=>', ','.join(versions))
    return matches
    
if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true', help='detailed output')
    parser.add_argument('-t', dest='target', required=True, help='https://example.com')
    args = parser.parse_args()

    static_resources = [
        'global-protect/login.esp',
        'global-protect/portal/css/login.css',
        'global-protect/portal/images/favicon.ico',
        'global-protect/portal/images/logo-pan-48525a.svg',
        'php/login.php',
        'login/images/favicon.ico',
        'js/Pan.js',
    ]
    
    version_table = load_version_table('version-table.txt')

    date_headers = {
        'ETag':          'etag_to_datetime',
        'Last-Modified': 'last_modified_to_datetime'
    }

    matches = {
        'exact': [],
        'approximate': []
    }

    errors = (ConnectTimeout, SSLError, ConnectionError)

    print('[*]', args.target)

    for resource in static_resources:
        try:
            resp_headers = get_resource(args.target, resource, date_headers.keys(), errors)
        except errors as e:
            print('[-]', args.target, type(e).__name__)
            exit(1)
        if resp_headers == None:
            continue

        for header in date_headers.keys():
            if header in resp_headers:
                date = globals()[date_headers[header]](resp_headers[header])
                versions = check_date(version_table, date)
                for key in matches.keys():
                    matches[key] += list(set(versions[key]) - set(matches[key]))

    if matches['exact']:
        print('[=]', args.target, ','.join(matches['exact']))
    elif matches['approximate']:
        print('[~]', args.target, ','.join(matches['approximate']))
    else:
        print('[?]', args.target)
