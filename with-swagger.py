#!/usr/bin/env python3
from __future__ import print_function
import logging
import os
import time
from sys import argv, exit


from pprint import pprint

import swagger_client
from swagger_client.api.datasources_api import DatasourcesApi
from swagger_client.rest import ApiException

logging.basicConfig(level=logging.INFO)

LOGGER = logging.getLogger(argv[0])
SOURCE_GRAFANA_TOKEN = os.getenv('SOURCE_GRAFANA_TOKEN')
GRAFANA_URL = os.getenv('GRAFANA_URL')

def make_config():
    # Configure API key authorization: api_key
    configuration = swagger_client.Configuration()
    configuration.debug = True # very verbose!
    configuration.api_key = {'Authorization': SOURCE_GRAFANA_TOKEN}
    # Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
    configuration.api_key_prefix = {'Authorization': 'Bearer'}
    configuration.host = GRAFANA_URL
    return configuration

configuration = make_config()

# dirty workaround to fix url issue with some endpoints
configuration_workaround = make_config()
configuration_workaround.host = GRAFANA_URL + "/api"

# create an instance of the API class
# for alerts. there is no method to list alerts currently.
provisioning_api = swagger_client.ProvisioningApi(swagger_client.ApiClient(configuration))
# list dashboards
search_api = swagger_client.SearchApi(swagger_client.ApiClient(configuration_workaround))
# get dashboards
dashboards_api = swagger_client.DashboardsApi(swagger_client.ApiClient(configuration))
# get, list data sources
datasources_api = swagger_client.DatasourcesApi(swagger_client.ApiClient(configuration_workaround))

if __name__ == '__main__':
    

    try:
        pprint(search_api.search(type='dash-db'))
        datasources = datasources_api.get_data_sources()
        print("\ndatasources")
        pprint(datasources)
        for d in datasources:
            uid = d["uid"]
            print('\n', 'datasource', d['name'])
            pprint(datasources_api.get_data_source_by_uid(uid=uid))
        # pprint(provisioning_api.route_get_policy_tree())
        # pprint(provisioning_api.route_get_templates())
                # https://grafana.com/docs/grafana/latest/alerting/migrating-alerts/roll-back/

    except ApiException as e:
        LOGGER.exception("Exception when calling API")