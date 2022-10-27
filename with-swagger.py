#!/usr/bin/env python3
from __future__ import print_function
import logging
import os
import time
import swagger_client
from swagger_client.rest import ApiException
from pprint import pprint
from sys import argv, exit

LOGGER = logging.getLogger(argv[0])
SOURCE_GRAFANA_TOKEN = os.getenv('SOURCE_GRAFANA_TOKEN')
GRAFANA_URL = os.getenv('GRAFANA_URL')

# Configure API key authorization: api_key
configuration = swagger_client.Configuration()
configuration.api_key['Authorization'] = SOURCE_GRAFANA_TOKEN
configuration.host = GRAFANA_URL
# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
configuration.api_key_prefix['Authorization'] = 'Bearer'

# create an instance of the API class
api_instance = swagger_client.AccessControlApi(swagger_client.ApiClient(configuration))
search_api = swagger_client.SearchApi(swagger_client.ApiClient(configuration))
# body = swagger_client.AddBuiltInRoleCommand() # AddBuiltInRoleCommand | 

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    try:
        pprint(search_api.search(query=''))
        # Create a built-in role assignment.
        #api_response = api_instance.add_builtin_role(body)
        #pprint(api_response)
    except ApiException as e:
        LOGGER.exception("Exception when calling API")