#!/usr/bin/env python3

import re
from os import getenv, makedirs, sep
from sys import exit

import json
import requests

GRAFANA_TOKEN = getenv('GRAFANA_TOKEN')
GRAFANA_URL = getenv('GRAFANA_URL', 'https://grafana.sts.midocloud.net')

AUTH_HEADER = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}

def ls(session):
    request = session.get(GRAFANA_URL + '/api/search?query=&')
    dashboards = request.json()
    return dashboards

def get(session, uid: str):
    request = session.get(GRAFANA_URL + f'/api/dashboards/uid/{uid}')
    data = request.json()
    return data

def save(data: str):
    dashboard = data['dashboard']
    filename_pattern = f'{dashboard["title"]}_{GRAFANA_URL}_{dashboard["uid"]}.json'
    filename_sanitized = re.sub(r'[^\w_.-]', '_', filename_pattern)
    folder = 'dashboards'
    makedirs(folder, exist_ok=True)
    file_path = folder + sep + filename_sanitized
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

def load(file_name: str):
    with open(file_name, 'r') as f:
        return json.load(f)


if not GRAFANA_TOKEN:
    print('please set GRAFANA_TOKEN in your env')
    exit(1)

def main():
    session = requests.Session()
    session.headers = AUTH_HEADER

    for d in ls(session):
        print(d)
        save(get(session, d['uid']))

if __name__ == '__main__':
    exit(main())
