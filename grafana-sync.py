#!/usr/bin/env python3
# grafana API reference: https://grafana.com/docs/grafana/latest/developers/http_api/

import argparse
from datetime import datetime
import json
import logging
import os
import re
import requests
from sys import argv, exit

LOGGER = logging.getLogger(argv[0])

SOURCE_GRAFANA_TOKEN = os.getenv('SOURCE_GRAFANA_TOKEN')
SOURCE_GRAFANA_USER = os.getenv('SOURCE_GRAFANA_USER')
SOURCE_GRAFANA_PASSWORD = os.getenv('SOURCE_GRAFANA_PASSWORD')

TARGET_GRAFANA_TOKEN = os.getenv('TARGET_GRAFANA_TOKEN')
TARGET_GRAFANA_USER = os.getenv('TARGET_GRAFANA_USER')
TARGET_GRAFANA_PASSWORD = os.getenv('TARGET_GRAFANA_PASSWORD')

USER = os.getenv('USER')

def sanitize(text: str) -> str:
    """Replace any not-ascii, dash or underscore character with the underscore character"""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', text)


def ls(base_url, session):
    """List all Grafana server's dashboards"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#dashboard-search
    request = session.get(base_url + '/api/search?type=dash-db') # type excludes folders
    request.raise_for_status()
    dashboards = request.json()
    return dashboards


def get_dashboard(base_url, session, uid: str):
    """Download dashboard by uid from Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#get-dashboard-by-uid
    request = session.get(base_url + f'/api/dashboards/uid/{uid}')
    request.raise_for_status()
    data = request.json()
    for field in data:
        LOGGER.debug(f'"{field}": "{data[field]}"')
    return data


def set_dashboard(base_url, session, data_json, overwrite=False):
    """Create new dashboard in Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#create--update-dashboard
    if 'dashboard' not in data_json:
        raise ValueError("JSON contains no dashboard")

    dashboard_json = data_json
    if 'meta' in dashboard_json:
        # 'meta' is info specific to permissions that can not be set via this API
        del dashboard_json['meta']
    message = f'Dashboard upload with {argv[0]}'
    if USER:
        message += f" by {USER}"
    dashboard_json['Message'] = message
    dashboard_json['overwrite'] = overwrite
    for field in dashboard_json:
        LOGGER.debug(f'"{field}": "{dashboard_json[field]}"')
    request = session.post(base_url + f'/api/dashboards/db', json=dashboard_json)
    request.raise_for_status()


def save(data: str, folder=None, exist_skip=True):
    """Save dashboard to a JSON file under a common "dashboard" folder"""
    dashboard = data['dashboard']
    filename_pattern = f'{dashboard["title"]}_{dashboard["uid"]}'
    filename_sanitized = sanitize(filename_pattern) + '.json'
    if not folder:
        folder = 'dashboards'
    os.makedirs(folder, exist_ok=True)
    file_path = folder + os.sep + filename_sanitized
    if exist_skip and os.path.exists(file_path):
        LOGGER.info('skipped existing file %s', file_path)
        return
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)


def load(file_name: str):
    """Load dashboard JSON from file_name"""
    with open(file_name, 'r') as f:
        return json.load(f)


def create_token(base_url, session, password, role='Viewer', user='admin'):
    # https only by design
    url = base_url + '/api/login/ping'
    basic_auth_session = requests.Session()
    basic_auth_session.auth = requests.auth.HTTPBasicAuth(user, password)
    request = basic_auth_session.get(url)
    request.raise_for_status()

    request = basic_auth_session.get(base_url + '/api/auth/keys',
        auth=requests.auth.HTTPBasicAuth(user, password))
    keys = request.json()
    if keys:
        for key in keys:
            if key.get('role') == role and key.get('expiration') \
            and datetime.strptime(key.get('expiration'), '%Y-%m-%dT%H:%M:%SZ') > datetime.utcnow():
                LOGGER.warning('There is already an active API key for this role and server.'
                    ' Please try to avoid having many active keys: %s', key)
    key_name = f"{argv[0]}"
    if USER:
        key_name += '-' + USER
    request = basic_auth_session.post(
        base_url + '/api/auth/keys',
        json={"name": key_name, "secondsToLive": 3600, "role": role},
        auth=requests.auth.HTTPBasicAuth(user, password))
    request.raise_for_status()
    key = request.json()
    LOGGER.warning("Your API key, please save it: %s", key)
    session.headers = {"Authorization": f"Bearer {key['key']}"}


def auth_keys(base_url, session):
    # permission level needed for seeing auth keys is admin
    request = session.get(base_url + '/api/auth/keys')
    request.raise_for_status()
    print(request.json())


def main():
    parser = argparse.ArgumentParser(
        description='Copies dashboards and / or alerts between local storage and Grafana server')
    parser.add_argument('-s', '--source', required=True, help="Copy source: Grafana server HTTPS URL, or path to local folder or file")
    parser.add_argument('-t', '--target', required=True, help="Copy target: Grafana server HTTPS URL, or path to local folder")
    parser.add_argument('-f', '--force-overwrite', action='store_true')
    parser.add_argument('items', help='What should be copied from source to destination?',
        nargs='+', choices=['dashboards', 'alerts'])
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_true')
    verbosity.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    source_dashboards = []

    if args.source and args.source.startswith('http'):
        source_session = requests.Session()
        if all((not SOURCE_GRAFANA_TOKEN, not SOURCE_GRAFANA_USER, not SOURCE_GRAFANA_PASSWORD)):
            logging.error(
                'Please either set SOURCE_GRAFANA_USER and SOURCE_GRAFANA_PASSWORD or SOURCE_GRAFANA_TOKEN in your environment')
            return 1

        if SOURCE_GRAFANA_TOKEN:
            source_session.headers = {"Authorization": f"Bearer {SOURCE_GRAFANA_TOKEN}"}
        else:
            create_token(args.source, source_session, user=SOURCE_GRAFANA_USER, password=SOURCE_GRAFANA_PASSWORD)

    if args.target and args.target.startswith('http'):
        target_session = requests.Session()
        if all((not TARGET_GRAFANA_TOKEN, not TARGET_GRAFANA_USER, not TARGET_GRAFANA_PASSWORD)):
            logging.error(
                'Please either set TARGET_GRAFANA_USER and TARGET_GRAFANA_PASSWORD or TARGET_GRAFANA_TOKEN in your environment')
            return 1

        if TARGET_GRAFANA_TOKEN:
            target_session.headers = {"Authorization": f"Bearer {TARGET_GRAFANA_TOKEN}"}
        else:
            create_token(args.target, target_session, user=TARGET_GRAFANA_USER, password=TARGET_GRAFANA_PASSWORD)

    if 'dashboards' in args.items:
        LOGGER.info('Loading dashboards')
        if args.source.startswith('https://'):
            for d in ls(args.source, source_session):
                source_dashboards.append(get_dashboard(args.source, source_session, d['uid']))
        else:
            if not os.path.exists(args.source):
                raise FileNotFoundError('Source path does not exist: %s', args.source)
            if os.path.isdir(args.source):
                for item in os.listdir(args.source):
                    if os.path.isfile(item):
                        source_dashboards.append(load(item))
            elif os.path.isfile(args.source):
                source_dashboards.append(load(args.source))
            else:
                raise ValueError('Source path is not a folder or file: %s', args.source)

        LOGGER.info('Saving dashboards')
        if args.target.startswith('https://'):
            for d in source_dashboards:
                set_dashboard(args.target, target_session, d, args.force_overwrite)
        else:
            if os.path.isfile(args.target):
                raise FileExistsError('Target folder %s is a file', args.target)
            for d in source_dashboards:
                save(d, args.target, exist_skip=not args.force_overwrite)

    if 'items' in args.items:
        raise NotImplementedError('Not implemented... yet!')


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    exit(main())
