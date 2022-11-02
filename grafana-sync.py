#!/usr/bin/env python3
# grafana API reference: https://grafana.com/docs/grafana/latest/developers/http_api/

DOC_EPILOG = '''environment variables:

SOURCE_GRAFANA_TOKEN    token for the source Grafana server
SOURCE_GRAFANA_USER     Username for the source Grafana server (when no token is given)
SOURCE_GRAFANA_PASSWORD Password for the source Grafana server (when no token is given)

TARGET_GRAFANA_TOKEN    token for the target Grafana server
TARGET_GRAFANA_USER     Username for the target Grafana server (when no token is given)
TARGET_GRAFANA_PASSWORD Password for the target Grafana server (when no token is given)

USER                    Username to save dashboard changes under (usually, your Unix username)
'''

import argparse
from datetime import datetime
import json
import logging
import os
from pprint import pformat
import re
import requests
import sys
from typing import List, Optional

from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments.lexers import PythonLexer

LOGGER = logging.getLogger(sys.argv[0])

pprint_size = 120

def pretty_json(json_text: str) -> str:
    pfmt = pformat(json_text, compact=True, width=pprint_size)
    if not sys.stdout.isatty():
        return pfmt
    return highlight(pfmt, PythonLexer(), TerminalFormatter(bg='dark'))

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


def ls_dashboards(base_url, session):
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
    LOGGER.debug('get_dashboard:\n%s', pretty_json(data))
    return data


def set_dashboard(base_url, session, data_json, overwrite=False, adapt_uid=False):
    """Create new dashboard in Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#create--update-dashboard
    if 'dashboard' not in data_json:
        raise ValueError("JSON contains no dashboard")

    dashboard_json = data_json
    if 'meta' in dashboard_json:
        # 'meta' is info specific to permissions that can not be set via this API
        del dashboard_json['meta']
    message = f'Dashboard upload with {sys.argv[0]}'
    if USER:
        message += f" by {USER}"
    dashboard_json['Message'] = message
    dashboard_json['overwrite'] = overwrite
    if adapt_uid:
        if 'dashboard' in dashboard_json and ['panels'] in dashboard_json['dashboard']:
            for panel in dashboard_json['dashboard']['panels']:
                if 'datasource' in panel:
                    name = panel['datasource']['type']
                    # get datasource uid
                    print(name)
                    # panel['datasource']['uid'] = uid

    LOGGER.debug('set_dashboard:\n%s', pretty_json(dashboard_json))
    request = session.post(base_url + '/api/dashboards/db', json=dashboard_json)
    request.raise_for_status()


def is_alert(data_json):
    """basic sanity check of a few required fields"""
    return all(item in data_json for item in {'ruleGroup', 'title'})


def set_alert(base_url, session, data_json, overwrite=False, adapt_uid=False) -> Optional[str]:
    """Create new alert in Grafana server.
    Requires admin access level
    https://grafana.com/docs/grafana/v9.1/developers/http_api/alerting_provisioning/#alert-rule
    """
    if not is_alert(data_json):
        raise ValueError("JSON contains no alert rule")
    if overwrite:
        raise NotImplementedError('Can not overwrite alerts yet')
    elif 'uid' in data_json:
        data = get_alert_rule(base_url, session, data_json['uid'], check_status=False)
        if is_alert(data):
            LOGGER.debug('Skipped already existing alert: %s "%s"',
                data_json['uid'], data_json['title'])
            return
    if 'annotations' in data_json:
        # annotations may reference UIDs of not existing dashboards...
        # TODO: adapt dashboard uids, or only allow setting the alert with its dashboard maybe
        del data_json['annotations']
    # TODO: adapt datasource uids
    request = session.post(base_url + '/api/v1/provisioning/alert-rules', json=data_json)
    request.raise_for_status()
    new_alert = request.json()
    LOGGER.debug('set_alert:\n%s', pretty_json(new_alert))
    return new_alert     
    

def ls_legacy_alerts(base_url, session) -> dict:
    """Deprecated endpoint"""
    request = session.get(f"{base_url}/api/alerts")
    request.raise_for_status()
    return request.json()


def get_rule_provisioning_templates(base_url, session) -> dict:
    request = session.get(f"{base_url}/api/v1/provisioning/templates")
    data = request.json()
    LOGGER.debug('get_rule_provisioning_templates:\n%s', pretty_json(data))
    return data 

def get_internal_ruler_rules(base_url, session) -> dict:
    """Query internal endpoint to export all alert rules """
    request = session.get(f"{base_url}/api/ruler/grafana/api/v1/rules")
    request.raise_for_status()
    data = request.json()
    LOGGER.debug('get_internal_ruler_rules:\n%s', pretty_json(data))
    return data 


def ls_alerts(base_url, session) -> set:
    """there is no "official" endpoint to list alert rules.
    we do this using an undocumented endpoint to get everything,
    and then keep only alert uids"""
    alerts_list = get_internal_ruler_rules(base_url, session)
    uids = set()

    # we need JSONPath to make this prettier...
    for group in alerts_list:
        for alert in alerts_list[group]:
            for rule in alert.get("rules", {}):
                alert_uid = rule["grafana_alert"].get("uid")
                uids.add(alert_uid)
    return uids


def get_alert_rule(base_url, session, uid: str, check_status=True) -> dict:
    """Query public endpoint to export alert rule. UID is required. 
    Permission level required: admin"""
    LOGGER.debug(f"Getting alert rule {uid}")
    if not uid:
        raise ValueError("UID cannot be empty!")
    request = session.get(f"{base_url}/api/v1/provisioning/alert-rules/{uid}")
    if check_status:
        request.raise_for_status()
    data = request.json()
    LOGGER.debug('get_alert_rule:\n%s', pretty_json(data))
    return data


def save_json(json_text: str, filename, folder, exist_skip=True):
    """Save JSON file under a common folder"""
    os.makedirs(folder, exist_ok=True)
    file_path = folder + os.sep + filename
    if exist_skip and os.path.exists(file_path):
        LOGGER.info('Skipped existing file %s', file_path)
        return
    with open(file_path, 'w') as f:
        json.dump(json_text, f, indent=2)


def save_alert(alert: str, folder=None, exist_skip=True):
    filename_pattern = f'{alert["title"]}_{alert["uid"]}'
    filename_sanitized = f"{sanitize(filename_pattern)}.json"
    return save_json(alert, filename_sanitized, folder or 'alerts', exist_skip)


def save_dashboard(data: str, folder=None, exist_skip=True):
    dashboard = data['dashboard']
    filename_pattern = f'{dashboard["title"]}_{dashboard["uid"]}'
    filename_sanitized = f"{sanitize(filename_pattern)}.json"
    return save_json(dashboard, filename_sanitized, folder or 'dashboards', exist_skip)


def load_from_path(path: str) -> List[str]:
    loaded = []
    if not os.path.exists(path):
        raise FileNotFoundError('Source path does not exist: %s', path)
    if os.path.isdir(path):
        for item in os.listdir(path):
            if os.path.isfile(item):
                loaded.append(load(item))
    elif os.path.isfile(path):
        loaded.append(load(path))
    else:
        raise ValueError('Source path is not a folder or file: %s', path)
    return loaded


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
    key_name = f"{sys.argv[0]}"
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
        description='Copies dashboards and / or alerts between local storage and Grafana server',
        epilog=DOC_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter # do not remove newlines from DOC_EPILOG
    )
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
        if args.source.startswith('http'):
            for d in ls_dashboards(args.source, source_session):
                source_dashboards.append(get_dashboard(args.source, source_session, d['uid']))
        else:
            source_dashboards = load_from_path(args.source)

        LOGGER.info('Saving dashboards')
        if args.target.startswith('https'):
            for d in source_dashboards:
                set_dashboard(args.target, target_session, d, args.force_overwrite)
        else:
            for d in source_dashboards:
                save_dashboard(d, args.target, exist_skip=not args.force_overwrite)

    elif 'alerts' in args.items:
        LOGGER.info('Loading alerts')
        source_alerts = list()

        if args.source.startswith("http"):
            uids = ls_alerts(args.source, source_session)

            LOGGER.debug(f"List of alert {uids=}")

            for uid in uids:
                alert = get_alert_rule(args.source, source_session, uid)
                source_alerts.append(alert)
        else:
            source_alerts = load_from_path(args.source)

        LOGGER.info("Saving alerts")
        if args.target.startswith("http"):
            for a in source_alerts:
                set_alert(args.target, target_session, a)
        else:
            for a in source_alerts:
                save_alert(a, args.target, exist_skip=not args.force_overwrite)

    else:
        raise NotImplementedError('Not implemented... yet!')


if __name__ == '__main__':
    if sys.stdout.isatty():
        RST = '\u001b[0m'
        RED = '\u001b[31m'
        GRN = '\u001b[32m'
        YLW = '\u001b[33m'
        MGN = '\u001b[35m'
        CYA = '\u001b[36m'
        logging.addLevelName(logging.DEBUG,    CYA + 'DEBUG'    + RST)
        logging.addLevelName(logging.INFO,     GRN + 'INFO'     + RST)
        logging.addLevelName(logging.WARNING,  YLW + 'WARNING'  + RST)
        logging.addLevelName(logging.ERROR,    RED + 'ERROR'    + RST)
        logging.addLevelName(logging.CRITICAL, MGN + 'CRITICAL' + RST)

        pprint_size = os.get_terminal_size().columns
    
    logging.basicConfig(level=logging.DEBUG)
    sys.exit(main())
