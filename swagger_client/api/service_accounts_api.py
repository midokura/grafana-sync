# coding: utf-8

"""
    Grafana HTTP API.

    The Grafana backend exposes an HTTP API, the same API is used by the frontend to do everything from saving dashboards, creating users and updating data sources.  # noqa: E501

    OpenAPI spec version: 0.0.1
    Contact: hello@grafana.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from swagger_client.api_client import ApiClient


class ServiceAccountsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def create_service_account(self, **kwargs):  # noqa: E501
        """Create service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:*`  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_service_account(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param CreateServiceAccountForm body:
        :return: ServiceAccountDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_service_account_with_http_info(**kwargs)  # noqa: E501
        else:
            (data) = self.create_service_account_with_http_info(**kwargs)  # noqa: E501
            return data

    def create_service_account_with_http_info(self, **kwargs):  # noqa: E501
        """Create service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:*`  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_service_account_with_http_info(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param CreateServiceAccountForm body:
        :return: ServiceAccountDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['body']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method create_service_account" % key
                )
            params[key] = val
        del params['kwargs']

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        if 'body' in params:
            body_params = params['body']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ServiceAccountDTO',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def create_token(self, service_account_id, **kwargs):  # noqa: E501
        """CreateNewToken adds a token to a service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_token(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :param AddServiceAccountTokenCommand body:
        :return: NewApiKeyResult
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_token_with_http_info(service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.create_token_with_http_info(service_account_id, **kwargs)  # noqa: E501
            return data

    def create_token_with_http_info(self, service_account_id, **kwargs):  # noqa: E501
        """CreateNewToken adds a token to a service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_token_with_http_info(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :param AddServiceAccountTokenCommand body:
        :return: NewApiKeyResult
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['service_account_id', 'body']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method create_token" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `create_token`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        if 'body' in params:
            body_params = params['body']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}/tokens', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='NewApiKeyResult',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_service_account(self, service_account_id, **kwargs):  # noqa: E501
        """Delete service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:delete` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_service_account(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
            return data

    def delete_service_account_with_http_info(self, service_account_id, **kwargs):  # noqa: E501
        """Delete service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:delete` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_service_account_with_http_info(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['service_account_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_service_account" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `delete_service_account`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='SuccessResponseBody',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_token(self, token_id, service_account_id, **kwargs):  # noqa: E501
        """DeleteToken deletes service account tokens  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_token(token_id, service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int token_id: (required)
        :param int service_account_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_token_with_http_info(token_id, service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_token_with_http_info(token_id, service_account_id, **kwargs)  # noqa: E501
            return data

    def delete_token_with_http_info(self, token_id, service_account_id, **kwargs):  # noqa: E501
        """DeleteToken deletes service account tokens  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_token_with_http_info(token_id, service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int token_id: (required)
        :param int service_account_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['token_id', 'service_account_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_token" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'token_id' is set
        if self.api_client.client_side_validation and ('token_id' not in params or
                                                       params['token_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `token_id` when calling `delete_token`")  # noqa: E501
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `delete_token`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'token_id' in params:
            path_params['tokenId'] = params['token_id']  # noqa: E501
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}/tokens/{tokenId}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='SuccessResponseBody',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_tokens(self, service_account_id, **kwargs):  # noqa: E501
        """Get service account tokens  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `global:serviceaccounts:id:1` (single service account)  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_tokens(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: TokenDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_tokens_with_http_info(service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.list_tokens_with_http_info(service_account_id, **kwargs)  # noqa: E501
            return data

    def list_tokens_with_http_info(self, service_account_id, **kwargs):  # noqa: E501
        """Get service account tokens  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `global:serviceaccounts:id:1` (single service account)  Requires basic authentication and that the authenticated user is a Grafana Admin.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_tokens_with_http_info(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: TokenDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['service_account_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_tokens" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `list_tokens`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}/tokens', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='TokenDTO',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def retrieve_service_account(self, service_account_id, **kwargs):  # noqa: E501
        """Get single serviceaccount by Id  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.retrieve_service_account(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: ServiceAccountDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.retrieve_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.retrieve_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
            return data

    def retrieve_service_account_with_http_info(self, service_account_id, **kwargs):  # noqa: E501
        """Get single serviceaccount by Id  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.retrieve_service_account_with_http_info(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :return: ServiceAccountDTO
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['service_account_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method retrieve_service_account" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `retrieve_service_account`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ServiceAccountDTO',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def search_org_service_accounts_with_paging(self, **kwargs):  # noqa: E501
        """Search service accounts with paging  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `serviceaccounts:*`  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_org_service_accounts_with_paging(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param bool disabled:
        :param bool expired_tokens:
        :param str query: It will return results where the query value is contained in one of the name. Query values with spaces need to be URL encoded.
        :param int perpage: The default value is 1000.
        :param int page: The default value is 1.
        :return: SearchServiceAccountsResult
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.search_org_service_accounts_with_paging_with_http_info(**kwargs)  # noqa: E501
        else:
            (data) = self.search_org_service_accounts_with_paging_with_http_info(**kwargs)  # noqa: E501
            return data

    def search_org_service_accounts_with_paging_with_http_info(self, **kwargs):  # noqa: E501
        """Search service accounts with paging  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:read` scope: `serviceaccounts:*`  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_org_service_accounts_with_paging_with_http_info(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param bool disabled:
        :param bool expired_tokens:
        :param str query: It will return results where the query value is contained in one of the name. Query values with spaces need to be URL encoded.
        :param int perpage: The default value is 1000.
        :param int page: The default value is 1.
        :return: SearchServiceAccountsResult
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['disabled', 'expired_tokens', 'query', 'perpage', 'page']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method search_org_service_accounts_with_paging" % key
                )
            params[key] = val
        del params['kwargs']

        collection_formats = {}

        path_params = {}

        query_params = []
        if 'disabled' in params:
            query_params.append(('Disabled', params['disabled']))  # noqa: E501
        if 'expired_tokens' in params:
            query_params.append(('expiredTokens', params['expired_tokens']))  # noqa: E501
        if 'query' in params:
            query_params.append(('query', params['query']))  # noqa: E501
        if 'perpage' in params:
            query_params.append(('perpage', params['perpage']))  # noqa: E501
        if 'page' in params:
            query_params.append(('page', params['page']))  # noqa: E501

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/search', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='SearchServiceAccountsResult',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def update_service_account(self, service_account_id, **kwargs):  # noqa: E501
        """Update service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_service_account(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :param UpdateServiceAccountForm body:
        :return: InlineResponse20014
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.update_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
        else:
            (data) = self.update_service_account_with_http_info(service_account_id, **kwargs)  # noqa: E501
            return data

    def update_service_account_with_http_info(self, service_account_id, **kwargs):  # noqa: E501
        """Update service account  # noqa: E501

        Required permissions (See note in the [introduction](https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/#service-account-api) for an explanation): action: `serviceaccounts:write` scope: `serviceaccounts:id:1` (single service account)  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_service_account_with_http_info(service_account_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int service_account_id: (required)
        :param UpdateServiceAccountForm body:
        :return: InlineResponse20014
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['service_account_id', 'body']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method update_service_account" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'service_account_id' is set
        if self.api_client.client_side_validation and ('service_account_id' not in params or
                                                       params['service_account_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `service_account_id` when calling `update_service_account`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'service_account_id' in params:
            path_params['serviceAccountId'] = params['service_account_id']  # noqa: E501

        query_params = []

        header_params = {}

        form_params = []
        local_var_files = {}

        body_params = None
        if 'body' in params:
            body_params = params['body']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/serviceaccounts/{serviceAccountId}', 'PATCH',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='InlineResponse20014',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
