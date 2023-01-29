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
from typing import List, Optional, Callable

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
    """Replace any not-{alphanumerical, dash or underscore} character with the
    underscore character"""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', text)

def simple_get(base_url, session, api_path):
    """helper to send a GET request and return the parsed JSON response"""
    request = session.get(base_url + '/api/' + api_path)
    request.raise_for_status()
    data = request.json()
    LOGGER.debug('%s:\n%s', api_path, pretty_json(data))
    return data

def ls_dashboards(base_url, session):
    """List all Grafana server's dashboards"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#dashboard-search
    return simple_get(base_url, session, 'search?type=dash-db') # type excludes folders

def get_dashboard(base_url, session, uid: str):
    """Download dashboard by uid from Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#get-dashboard-by-uid
    return simple_get(base_url, session, f'dashboards/uid/{uid}')

def set_dashboard(base_url, session, data_json, overwrite=False, adapt_uid=False):
    """Create new dashboard in Grafana server"""
    # https://grafana.com/docs/grafana/latest/developers/http_api/dashboard/#create--update-dashboard
    if 'dashboard' not in data_json:
        raise ValueError("JSON contains no dashboard")

    dashboard_json = data_json
    # Ensure it is a creation
    if not overwrite:
        data_json['dashboard'].pop('id',None)
    if 'meta' in dashboard_json:
        if 'folderUid' in data_json['meta']:
            data_json['folderUid'] = data_json['meta']['folderUid']
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

################################################################################

def list_folders(base_url, session):
    """List folders of Grafana server
    https://grafana.com/docs/grafana/v9.1/developers/http_api/folder/#get-all-folders
    """
    return simple_get(base_url, session, 'folders')

def get_folder(base_url, session, uid):
    """
    https://grafana.com/docs/grafana/v9.1/developers/http_api/folder/#get-folder-by-uid
    """
    return simple_get(base_url, session, f'folders/{uid}')

def update_folder(base_url, session, folder: dict):
    """
    https://grafana.com/docs/grafana/v9.1/developers/http_api/folder/#update-folder
    """
    allowed_fields = {'uid', 'title'}
    new_folder = {k: folder[k] for k in folder if k in allowed_fields}
    new_folder['overwrite'] = True
    request = session.put(base_url + '/api/folders/' + folder['uid'], json=folder)
    request.raise_for_status()
    data = request.json()
    LOGGER.debug('set_folder:\n%s', pretty_json(data))
    return data

def create_folder(base_url, session, folder: dict):
    """
    https://grafana.com/docs/grafana/v9.1/developers/http_api/folder/#create-folder
    """
    LOGGER.debug(f'{folder=}')
    allowed_fields = {'uid', 'title'}
    new_folder = {k: folder[k] for k in folder if k in allowed_fields}
    request = session.post(base_url + '/api/folders', json=new_folder)
    request.raise_for_status()
    data = request.json()
    LOGGER.debug('set_folder:\n%s', pretty_json(data))
    return data

def get_folder_of_dashboard(dashboard: dict) -> str:
    """returns UID of dashboard that the 'alert' belongs to"""
    return dashboard['meta']['folderUid']


def save_folder(f: dict, path, exist_skip=True):
    filename_pattern = f'{f["title"]}_{f["uid"]}'
    filename_sanitized = f"{sanitize(filename_pattern)}.json"
    return save_json(f, filename_sanitized, os.path.join(path, 'folders'), exist_skip)

################################################################################

def is_alert(data_json):
    """basic sanity check of a few required fields"""
    return 'uid' in data_json and all(item in data_json for item in {'ruleGroup', 'title'})

def set_alert(base_url, session, data_json, overwrite=False, adapt_uid=False) -> Optional[str]:
    """Create new alert in Grafana server.
    Requires admin access level
    https://grafana.com/docs/grafana/v9.1/developers/http_api/alerting_provisioning/#alert-rule
    """
    if not is_alert(data_json):
        raise ValueError("JSON contains no alert rule")
    data = get_alert_rule(base_url, session, data_json['uid'], check_status=False)
    if not overwrite and is_alert(data):
        LOGGER.debug('Skipped already existing alert: %s "%s"',
                     data_json['uid'], data_json['title'])
        return
    if not overwrite and 'annotations' in data_json:
        # annotations may reference UIDs of not existing dashboards...
        # TODO: adapt dashboard uids, or only allow setting the alert with its dashboard maybe
        del data_json['annotations']
    # TODO: adapt datasource uids
    create_url = base_url + '/api/v1/provisioning/alert-rules'
    if is_alert(data):
        update_url = create_url + f"/{data['uid']}"
        request = session.put(update_url, json=data_json)
    else:
        request = session.post(create_url, json=data_json)
    new_alert = request.json()
    LOGGER.debug('set_alert:\n%s', pretty_json(new_alert))
    request.raise_for_status()
    return new_alert

def ls_legacy_alerts(base_url, session) -> dict:
    """Deprecated endpoint"""
    return simple_get(base_url, session, 'alerts')

def get_rule_provisioning_templates(base_url, session) -> dict:
    return simple_get(base_url, session, 'v1/provisioning/templates')

def get_internal_ruler_rules(base_url, session) -> dict:
    """Query internal endpoint to export all alert rules """
    return simple_get(base_url, session, 'ruler/grafana/api/v1/rules')

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

def save_json(json_text: str, filename, path, exist_skip=True):
    """Save JSON file under a common path"""
    os.makedirs(path, exist_ok=True)
    file_path = path + os.sep + filename
    if exist_skip and os.path.exists(file_path):
        LOGGER.info('Skipped existing file %s', file_path)
        return
    with open(file_path, 'w') as f:
        json.dump(json_text, f, indent=2)

def save_alert_in_file(a: dict, path, exist_skip=True):
    filename_pattern = f'{a["title"]}_{a["uid"]}'
    filename_sanitized = f"{sanitize(filename_pattern)}.json"
    return save_json(a, filename_sanitized, path, exist_skip)

def save_dashboard_in_file(d: dict, path, exist_skip=True):
    dashboard = d['dashboard']
    filename_pattern = f'{dashboard["title"]}_{dashboard["uid"]}'
    filename_sanitized = f"{sanitize(filename_pattern)}.json"
    return save_json(dashboard, filename_sanitized, path, exist_skip)

def load_from_path(path: str) -> List[str]:
    loaded = []
    if not os.path.exists(path):
        raise FileNotFoundError('Source path does not exist: %s', path)
    if os.path.isdir(path):
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isfile(full_path):
                loaded.append(load(full_path))
            else:
                LOGGER.debug('Ignored path %s', full_path)
    elif os.path.isfile(path):
        loaded.append(load(path))
    else:
        raise ValueError('Source path is not a folder or file: %s', path)
    LOGGER.info("Loaded %d alerts from %s", len(loaded), path)
    return loaded

def load(file_name: str):
    """Load dashboard JSON from file_name"""
    LOGGER.debug('Opening %s', file_name)
    with open(file_name, 'r') as f:
        return json.load(f)

def create_token(base_url: str, session, password, role='Admin', user='admin'):
    """Use http basic auth to create a token for further API usage"""
    if base_url.startswith('http://'):
        if not base_url.startswith('http://192.168.'):
            LOGGER.fatal('Refusing to use basic auth on WAN over HTTP to avoid leaking credentials')
            sys.exit(1)
        else:
            LOGGER.warning('Using insecure HTTP basic auth over http to %s', base_url)

    session.auth = requests.auth.HTTPBasicAuth(user, password)
    request = session.get(base_url + '/api/login/ping')
    request.raise_for_status()

    request = session.get(base_url + '/api/auth/keys',
        auth=requests.auth.HTTPBasicAuth(user, password))
    keys = request.json()
    if keys:
        for key in keys:
            if key.get('role') == role and key.get('expiration') \
            and datetime.strptime(key.get('expiration'), '%Y-%m-%dT%H:%M:%SZ') > datetime.utcnow():
                LOGGER.warning('There is already an active API key for this role and server.'
                    ' Please try to avoid having many active keys: %s', key)
    key_name = f"{sys.argv[0]}-{role}"
    if USER:
        key_name += '-' + USER
    request = session.post(
        base_url + '/api/auth/keys',
        json={"name": key_name, "secondsToLive": 3600, "role": role},
        auth=requests.auth.HTTPBasicAuth(user, password))
    request.raise_for_status()
    key = request.json()
    LOGGER.warning("Your API key, please save it: %s", key)
    session.headers = {"Authorization": f"Bearer {key['key']}"}
    session.auth = None # stop using HTTP basic auth

def auth_keys(base_url, session):
    # permission level needed for seeing auth keys is admin
    request = session.get(base_url + '/api/auth/keys')
    request.raise_for_status()
    print(request.json())

class GrafanaLogin:

    def __init__(self, token:str, user:str, password: str, base_url: str):
        self.session = requests.Session()
        if token:
            self.session.headers = {"Authorization": f"Bearer {token}"}
        else:
            create_token(base_url, self.session, user=user, password=password)

class GrafanaClient:

    def __init__(self, base_url: str, session: GrafanaLogin, overwrite: bool) -> None:
        super().__init__()
        self.url = base_url
        self.session = session.session
        self.folders = self.__load_folders()
        self.dashboards = self.__load_dashboard()
        self.alerts = self.__load_alerts()
        self.overwrite = overwrite

    def copy_dashboard_from(self, source: 'GrafanaClient'):
        if self.url.startswith("http"):
            dashboards = source.dashboards.copy()
            update_folder = lambda s_folder, t_folder: self.__update_dashboard_folders(s_folder, t_folder,dashboards)
            self.__sync_folders_with(source, update_folder)
            self.__save_dashboards_to_grafana(dashboards)
        else:
            self.__save_dashboards_to_file(source.folders, source.alerts)
    def copy_alerts_from(self, source: 'GrafanaClient'):
        if self.url.startswith("http"):
            alerts = source.alerts.copy()
            update_folder = lambda s_folder, t_folder: self.__update_alerts_folders(s_folder, t_folder, alerts)
            self.__sync_folders_with(source, update_folder)
            self.__save_alert_to_grafana(alerts)
        else:
            self.__save_alerts_to_file(source.folders, source.alerts)

    def save_alert(self, alert: dict, overwrite: bool = None) -> None:
        if not overwrite:
            overwrite = self.overwrite
        if self.url.startswith('http'):
            set_alert(self.url, self.session, alert, overwrite=overwrite)
        else:
            save_alert_in_file(alert, self.url, exist_skip=self.overwrite)

    def save_dashboard(self, dashboard: dict, overwrite: bool = None) -> None:
        if not overwrite:
            overwrite = self.overwrite
        if self.url.startswith('http'):
            set_dashboard(self.url, self.session, dashboard, overwrite=overwrite)
        else:
            save_dashboard_in_file(dashboard, self.url, exist_skip=self.overwrite)

    def __sync_folders_with(self, source: 'GrafanaClient', update_childs: Callable[[dict, dict], None])-> None:
        for source_folder in source.folders:
            current_folder = self.__find_folder(source_folder)
            if not current_folder:
                create_folder(self.url, self.session, source_folder)
            elif self.overwrite and current_folder is not None and not current_folder['title'] == source_folder['title']:
                current_folder['title'] = source_folder['title']
                update_folder(self.url, self.session, current_folder)
            elif not current_folder['uid'] == source_folder['uid']:
                update_childs(source_folder, current_folder)

    def __save_dashboards_to_grafana(self, dashboards:list):
        LOGGER.info(f"Saving dashboards to {self.url}")
        for a in dashboards:
           self.save_dashboard(a)
    
    def __save_dashboards_to_file(self, folders: dict, dashboards: list):
        LOGGER.info(f"Saving dashboards file {self.url}")
        for f in folders:
            save_folder(f, self.url, exist_skip=self.overwrite)
        for a in dashboards:
            self.save_dashboard(a)
    def __save_alert_to_grafana(self, alerts:list):
        LOGGER.info(f"Saving alerts to {self.url}")
        for a in alerts:
           self.save_alert(a)

    def __save_alerts_to_file(self, folders: dict, alerts: list):
        LOGGER.info(f"Saving alerts file {self.url}")
        for f in folders:
            save_folder(f, self.url, exist_skip=self.overwrite)
        for a in alerts:
            self.save_alert(a)

    def __load_folders(self)-> dict:
        if self.url.startswith('http'):
            return list_folders(self.url, self.session)
        else:
            return load_from_path(self.url + os.sep + '/folders')

    def __load_dashboard(self) -> list:
        LOGGER.info(f'Loading dashboards from {self.url}')
        if self.url.startswith('http'):
            source_dashboards = list()
            for d in ls_dashboards(self.url, self.session):
                dashboard = get_dashboard(self.url, self.session, d['uid'])
                source_dashboards.append(dashboard)
            return source_dashboards
        else:
            return load_from_path(self.url)

    def __load_alerts(self) -> list:
        LOGGER.info(f'Loading alerts from {self.url}')
        if self.url.startswith('http'):
            source_alerts = list()
            uids = ls_alerts(self.url, self.session)
            LOGGER.debug(f"List of alert {uids=}")
            for uid in uids:
                alert = get_alert_rule(self.url, self.session, uid)
                source_alerts.append(alert)
            return source_alerts
        else:
            return load_from_path(self.url)

    def __find_folder(self,source:dict)-> dict:
        for folder in self.folders:
            if folder['uid'] == source['uid'] or folder['title'] == source['title']:
                return folder
        return None

    def __update_alerts_folders(self, source_folder: dict, target_folder: dict, source_alerts: list):
        for alert in source_alerts:
            if alert['folderUID'] == source_folder['uid']:
                alert['folderUID'] = target_folder['uid']

    def __update_dashboard_folders(self, source_folder: dict, target_folder: dict, source: list):
        sf_uid = source_folder['uid']
        tf_uid = target_folder['uid']
        for dashboard in source:
            meta = dashboard["meta"]
            if meta['folderUID'] == sf_uid:
                meta['folderUID'] = tf_uid
                meta['folderUrl'] = meta['folderUrl'].replace(sf_uid,tf_uid)


def config_logging(args: argparse.Namespace) -> None:
    global pprint_size
    if sys.stdout.isatty():
        RST = '\u001b[0m'
        RED = '\u001b[31m'
        GRN = '\u001b[32m'
        YLW = '\u001b[33m'
        MGN = '\u001b[35m'
        CYA = '\u001b[36m'
        logging.addLevelName(logging.DEBUG, CYA + 'DEBUG' + RST)
        logging.addLevelName(logging.INFO, GRN + 'INFO' + RST)
        logging.addLevelName(logging.WARNING, YLW + 'WARNING' + RST)
        logging.addLevelName(logging.ERROR, RED + 'ERROR' + RST)
        logging.addLevelName(logging.CRITICAL, MGN + 'CRITICAL' + RST)

        pprint_size = os.get_terminal_size().columns
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

def main():
    parser = argparse.ArgumentParser(
        description='Copies dashboards and / or alerts between local storage and Grafana server',
        epilog=DOC_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter # do not remove newlines from DOC_EPILOG
    )
    parser.add_argument('-s', '--source', required=True, help="Copy source: Grafana server HTTPS URL, or path to local folder or file")
    parser.add_argument('-t', '--target', required=True, help="Copy target: Grafana server HTTPS URL, or path to local folder")
    parser.add_argument('-f', '--force-overwrite', action='store_true')
    parser.add_argument('items', help='What items should be copied from source to destination?',
                        nargs='+', choices=['dashboards', 'alerts'])
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_true')
    verbosity.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    config_logging(args)

    if args.source and args.source.startswith('http'):
        if all((not SOURCE_GRAFANA_TOKEN, not SOURCE_GRAFANA_USER, not SOURCE_GRAFANA_PASSWORD)):
            logging.error(
                'Please either set SOURCE_GRAFANA_USER and SOURCE_GRAFANA_PASSWORD or SOURCE_GRAFANA_TOKEN in your environment')
            return 1

        source_session = GrafanaLogin(SOURCE_GRAFANA_TOKEN,SOURCE_GRAFANA_USER,SOURCE_GRAFANA_PASSWORD, args.source)
        source = GrafanaClient(args.source, source_session, overwrite=args.force_overwrite)

    if args.target and args.target.startswith('http'):
        if all((not TARGET_GRAFANA_TOKEN, not TARGET_GRAFANA_USER, not TARGET_GRAFANA_PASSWORD)):
            logging.error(
                'Please either set TARGET_GRAFANA_USER and TARGET_GRAFANA_PASSWORD or TARGET_GRAFANA_TOKEN in your environment')
            return 1

        target_session = GrafanaLogin(TARGET_GRAFANA_TOKEN, TARGET_GRAFANA_USER, TARGET_GRAFANA_PASSWORD, args.target)
        target = GrafanaClient(args.target, target_session, overwrite=args.force_overwrite)

    if 'dashboards' in args.items:
        target.copy_dashboard_from(source)

    elif 'alerts' in args.items:
        target.copy_alerts_from(source)

    else:
        raise NotImplementedError('Item not implemented... yet!')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except requests.exceptions.HTTPError as error:
        logging.error(f"REST call has failed. The request is {error.request.url} Status is {error.response.status_code} and error is {error.response.text}", error)
        sys.exit(1)