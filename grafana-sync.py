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

GRAFANA_TOKEN = os.getenv('GRAFANA_TOKEN')
GRAFANA_URL = os.getenv('GRAFANA_URL', 'https://grafana.sts.midocloud.net')
GRAFANA_USER = os.getenv('GRAFANA_USER', 'admin')
GRAFANA_PASSWORD = os.getenv('GRAFANA_PASSWORD')

AUTH_HEADER = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}

USER = os.getenv('USER')

def sanitize(text: str) -> str:
    """Replace any not-ascii, dash or underscore character with the underscore character"""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', text)


def ls(session):
    """List all Grafana server's dashboards"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#dashboard-search
    request = session.get(GRAFANA_URL + '/api/search?query=&')
    request.raise_for_status()
    dashboards = request.json()
    return dashboards


def get_dashboard(session, uid: str):
    """Download dashboard by uid from Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#get-dashboard-by-uid
    request = session.get(GRAFANA_URL + f'/api/dashboards/uid/{uid}')
    request.raise_for_status()
    data = request.json()
    return data


def set_dashboard(session, data_json, overwrite=False):
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

    request = session.post(GRAFANA_URL + f'/api/dashboards/db', json=dashboard_json)
    request.raise_for_status()


def save(data: str, exist_skip=True):
    """Save dashboard to a JSON file under a common "dashboard" folder"""
    dashboard = data['dashboard']
    filename_pattern = f'{dashboard["title"]}_{GRAFANA_URL}_{dashboard["uid"]}'
    filename_sanitized = sanitize(filename_pattern) + '.json'
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


def create_token(session, role='Viewer'):
    # https only by design
    url = GRAFANA_URL + '/api/login/ping'
    basic_auth_session = requests.Session(auth=requests.auth.HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD))
    request = basic_auth_session.get(url)
    request.raise_for_status()

    request = basic_auth_session.get(GRAFANA_URL + '/api/auth/keys',
        auth=requests.auth.HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD))
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
        GRAFANA_URL + '/api/auth/keys',
        json={"name": key_name, "secondsToLive": 3600, "role": role},
        auth=requests.auth.HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD))
    request.raise_for_status()
    key = request.json()
    LOGGER.warning("Your API key, please save it: %s", key)
    session.headers = {"Authorization": f"Bearer {key['key']}"}


def auth_keys(session):
    # permission level needed for seeing auth keys is admin
    request = session.get(GRAFANA_URL + '/api/auth/keys')
    request.raise_for_status()
    print(request.json())


def main():
    parser = argparse.ArgumentParser(
        description='Copies dashboards and / or alerts between local storage and Grafana server')
    parser.add_argument('--source')
    parser.add_argument('--destination')
    parser.add_argument('--dashboards', type=bool, default=True)
    parser.add_argument('--alerts', type=bool, default=False)
    args = parser.parse_args()

    session = requests.Session()
    if any((not GRAFANA_TOKEN, not GRAFANA_USER, not GRAFANA_PASSWORD)):
        logging.error(
            'Please either set GRAFANA_USER and GRAFANA_PASSWORD or GRAFANA_TOKEN in your environment')
        return 1
    if GRAFANA_TOKEN:
        session.headers = AUTH_HEADER
    else:
        create_token(session)

    for d in ls(session):
        print(d)
        save(get_dashboard(session, d['uid']))

    auth_keys(session)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    exit(main())
