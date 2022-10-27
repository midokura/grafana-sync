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


class CorrelationsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def create_correlation(self, body, source_uid, **kwargs):  # noqa: E501
        """Add correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_correlation(body, source_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param CreateCorrelationCommand body: (required)
        :param str source_uid: (required)
        :return: CreateCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_correlation_with_http_info(body, source_uid, **kwargs)  # noqa: E501
        else:
            (data) = self.create_correlation_with_http_info(body, source_uid, **kwargs)  # noqa: E501
            return data

    def create_correlation_with_http_info(self, body, source_uid, **kwargs):  # noqa: E501
        """Add correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_correlation_with_http_info(body, source_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param CreateCorrelationCommand body: (required)
        :param str source_uid: (required)
        :return: CreateCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['body', 'source_uid']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method create_correlation" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `create_correlation`")  # noqa: E501
        # verify the required parameter 'source_uid' is set
        if self.api_client.client_side_validation and ('source_uid' not in params or
                                                       params['source_uid'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `source_uid` when calling `create_correlation`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'source_uid' in params:
            path_params['sourceUID'] = params['source_uid']  # noqa: E501

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
            '/datasources/uid/{sourceUID}/correlations', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='CreateCorrelationResponseBody',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_correlation(self, uid, correlation_uid, **kwargs):  # noqa: E501
        """Delete a correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_correlation(uid, correlation_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str uid: (required)
        :param str correlation_uid: (required)
        :return: DeleteCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_correlation_with_http_info(uid, correlation_uid, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_correlation_with_http_info(uid, correlation_uid, **kwargs)  # noqa: E501
            return data

    def delete_correlation_with_http_info(self, uid, correlation_uid, **kwargs):  # noqa: E501
        """Delete a correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_correlation_with_http_info(uid, correlation_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str uid: (required)
        :param str correlation_uid: (required)
        :return: DeleteCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['uid', 'correlation_uid']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_correlation" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'uid' is set
        if self.api_client.client_side_validation and ('uid' not in params or
                                                       params['uid'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `uid` when calling `delete_correlation`")  # noqa: E501
        # verify the required parameter 'correlation_uid' is set
        if self.api_client.client_side_validation and ('correlation_uid' not in params or
                                                       params['correlation_uid'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `correlation_uid` when calling `delete_correlation`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'uid' in params:
            path_params['uid'] = params['uid']  # noqa: E501
        if 'correlation_uid' in params:
            path_params['correlationUID'] = params['correlation_uid']  # noqa: E501

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
            '/datasources/uid/{uid}/correlations/{correlationUID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='DeleteCorrelationResponseBody',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def update_correlation(self, source_uid, correlation_uid, **kwargs):  # noqa: E501
        """Updates a correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_correlation(source_uid, correlation_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str source_uid: (required)
        :param str correlation_uid: (required)
        :param UpdateCorrelationCommand body:
        :return: UpdateCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.update_correlation_with_http_info(source_uid, correlation_uid, **kwargs)  # noqa: E501
        else:
            (data) = self.update_correlation_with_http_info(source_uid, correlation_uid, **kwargs)  # noqa: E501
            return data

    def update_correlation_with_http_info(self, source_uid, correlation_uid, **kwargs):  # noqa: E501
        """Updates a correlation.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_correlation_with_http_info(source_uid, correlation_uid, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str source_uid: (required)
        :param str correlation_uid: (required)
        :param UpdateCorrelationCommand body:
        :return: UpdateCorrelationResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['source_uid', 'correlation_uid', 'body']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method update_correlation" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'source_uid' is set
        if self.api_client.client_side_validation and ('source_uid' not in params or
                                                       params['source_uid'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `source_uid` when calling `update_correlation`")  # noqa: E501
        # verify the required parameter 'correlation_uid' is set
        if self.api_client.client_side_validation and ('correlation_uid' not in params or
                                                       params['correlation_uid'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `correlation_uid` when calling `update_correlation`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'source_uid' in params:
            path_params['sourceUID'] = params['source_uid']  # noqa: E501
        if 'correlation_uid' in params:
            path_params['correlationUID'] = params['correlation_uid']  # noqa: E501

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
            '/datasources/uid/{sourceUID}/correlations/{correlationUID}', 'PATCH',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='UpdateCorrelationResponseBody',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
