#!/usr/bin/env python3

from os import getenv
from sys import exit

import requests

GRAFANA_TOKEN = getenv('GRAFANA_TOKEN')
GRAFANA_URL = getenv('GRAFANA_URL', 'https://grafana.sts.midocloud.net')

if not GRAFANA_TOKEN:
    print('please set GRAFANA_TOKEN in your env')
    exit(1)

def main():
    auth_header = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}

    session = requests.Session()
    session.headers = auth_header
    request = session.get(GRAFANA_URL + '/api/search?query=&', headers=auth_header)
    dashboards = request.json()
    print(dashboards)

if __name__ == '__main__':
    exit(main())
