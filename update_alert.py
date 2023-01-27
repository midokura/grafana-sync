import logging

import grafana_sync
import sys
import requests
import argparse

EXIT_SUCCESS = 0
EXIT_ERROR = 1

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Change source namespace to target namespace on all alerts',
        epilog=grafana_sync.DOC_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter  # do not remove newlines from DOC_EPILOG
    )
    parser.add_argument('-g', '--grafana_url', required=True,
                        help="URL of the Grafana server whose alerts shall be updated")
    parser.add_argument('-o', '--origin_namespace', required=True,
                        help="The namespace to be renamed from")
    parser.add_argument('-d', '--destination_namespace', required=True,
                        help="The namespace to be renamed to")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument('-q', '--quiet', action='store_true')
    verbosity.add_argument('-v', '--verbose', action='store_true')
    return parser.parse_args()

def __get_models_with_expression(alert: dict) -> list:
    expressions = list()
    if alert and 'data' in alert:
        for data in alert['data']:
            if 'model' in data and 'expr' in data['model']:
                expressions.append(data['model'])
    return expressions

def __change_namespace(grafana: grafana_sync.GrafanaClient, origin_namespace: str, destination_namespace: str) -> None:
    for alert in grafana.alerts:
        alert_needs_update = False
        for model in __get_models_with_expression(alert):
            namespace_pattern = f'="{origin_namespace}"'
            if namespace_pattern in model['expr']:
                alert_needs_update = True
                logging.debug(f"on alert '{alert['title']}' we will modify { model['expr']}")
                model['expr'] = model['expr'].replace(namespace_pattern,f'="{destination_namespace}"')
        if alert_needs_update:
            logging.info(f"alert {alert['uid']}('{alert['title']}') has been modified")
            grafana.save_alert(alert, overwrite=True)

def change_namespace(grafana: grafana_sync.GrafanaClient, origin_namespace, destination_namespace) -> int:
    try:
        logging.info("Changing namespace to alerts")
        __change_namespace(grafana, origin_namespace, destination_namespace)
        return EXIT_SUCCESS
    except requests.exceptions.HTTPError as error:
        logging.error(
            f"REST call has failed. The request is {error.request.url} Status is {error.response.status_code} and error is {error.response.text}",
            error)
        return EXIT_ERROR

def login_to_grafana(args: argparse.Namespace) -> grafana_sync.GrafanaClient:
    grafana_url = args.grafana_url
    token = grafana_sync.SOURCE_GRAFANA_TOKEN
    username = grafana_sync.SOURCE_GRAFANA_USER
    password = grafana_sync.SOURCE_GRAFANA_PASSWORD
    login = grafana_sync.GrafanaLogin(token, username, password, grafana_url)
    return grafana_sync.GrafanaClient(grafana_url,login, False)

if __name__ == '__main__':
    args = parse_args()
    grafana_sync.config_logging(args)
    client = login_to_grafana(args)

    sys.exit(change_namespace(client, args.origin_namespace, args.destination_namespace))
