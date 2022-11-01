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


class RecordingRulesApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def create_recording_rule(self, body, **kwargs):  # noqa: E501
        """create_recording_rule  # noqa: E501

        Create a recording rule that is then registered and started  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_recording_rule(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: RecordingRuleJSON
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
        else:
            (data) = self.create_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
            return data

    def create_recording_rule_with_http_info(self, body, **kwargs):  # noqa: E501
        """create_recording_rule  # noqa: E501

        Create a recording rule that is then registered and started  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_recording_rule_with_http_info(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: RecordingRuleJSON
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
                    " to method create_recording_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `create_recording_rule`")  # noqa: E501

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
            '/recording-rules', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='RecordingRuleJSON',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def create_recording_rule_write_target(self, body, **kwargs):  # noqa: E501
        """Create a remote write target.  # noqa: E501

        It returns a 422 if there is not an existing prometheus data source configured  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_recording_rule_write_target(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param PrometheusRemoteWriteTargetJSON body: (required)
        :return: PrometheusRemoteWriteTargetJSON
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_recording_rule_write_target_with_http_info(body, **kwargs)  # noqa: E501
        else:
            (data) = self.create_recording_rule_write_target_with_http_info(body, **kwargs)  # noqa: E501
            return data

    def create_recording_rule_write_target_with_http_info(self, body, **kwargs):  # noqa: E501
        """Create a remote write target.  # noqa: E501

        It returns a 422 if there is not an existing prometheus data source configured  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_recording_rule_write_target_with_http_info(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param PrometheusRemoteWriteTargetJSON body: (required)
        :return: PrometheusRemoteWriteTargetJSON
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
                    " to method create_recording_rule_write_target" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `create_recording_rule_write_target`")  # noqa: E501

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
            '/recording-rules/writer', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='PrometheusRemoteWriteTargetJSON',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_recording_rule(self, recording_rule_id, **kwargs):  # noqa: E501
        """Delete removes the rule from the registry and stops it.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_recording_rule(recording_rule_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int recording_rule_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_recording_rule_with_http_info(recording_rule_id, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_recording_rule_with_http_info(recording_rule_id, **kwargs)  # noqa: E501
            return data

    def delete_recording_rule_with_http_info(self, recording_rule_id, **kwargs):  # noqa: E501
        """Delete removes the rule from the registry and stops it.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_recording_rule_with_http_info(recording_rule_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int recording_rule_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['recording_rule_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_recording_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'recording_rule_id' is set
        if self.api_client.client_side_validation and ('recording_rule_id' not in params or
                                                       params['recording_rule_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `recording_rule_id` when calling `delete_recording_rule`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'recording_rule_id' in params:
            path_params['recordingRuleID'] = params['recording_rule_id']  # noqa: E501

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
            '/recording-rules/{recordingRuleID}', 'DELETE',
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

    def delete_recording_rule_write_target(self, **kwargs):  # noqa: E501
        """Delete the remote write target.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_recording_rule_write_target(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_recording_rule_write_target_with_http_info(**kwargs)  # noqa: E501
        else:
            (data) = self.delete_recording_rule_write_target_with_http_info(**kwargs)  # noqa: E501
            return data

    def delete_recording_rule_write_target_with_http_info(self, **kwargs):  # noqa: E501
        """Delete the remote write target.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_recording_rule_write_target_with_http_info(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = []  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_recording_rule_write_target" % key
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
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/recording-rules/writer', 'DELETE',
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

    def get_recording_rule_write_target(self, **kwargs):  # noqa: E501
        """get_recording_rule_write_target  # noqa: E501

        Return the prometheus remote write target  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_recording_rule_write_target(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: PrometheusRemoteWriteTargetJSON
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.get_recording_rule_write_target_with_http_info(**kwargs)  # noqa: E501
        else:
            (data) = self.get_recording_rule_write_target_with_http_info(**kwargs)  # noqa: E501
            return data

    def get_recording_rule_write_target_with_http_info(self, **kwargs):  # noqa: E501
        """get_recording_rule_write_target  # noqa: E501

        Return the prometheus remote write target  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_recording_rule_write_target_with_http_info(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: PrometheusRemoteWriteTargetJSON
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = []  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method get_recording_rule_write_target" % key
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
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/recording-rules/writer', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='PrometheusRemoteWriteTargetJSON',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_recording_rules(self, **kwargs):  # noqa: E501
        """list_recording_rules  # noqa: E501

        Lists all rules in the database: active or deleted  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_recording_rules(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: list[RecordingRuleJSON]
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_recording_rules_with_http_info(**kwargs)  # noqa: E501
        else:
            (data) = self.list_recording_rules_with_http_info(**kwargs)  # noqa: E501
            return data

    def list_recording_rules_with_http_info(self, **kwargs):  # noqa: E501
        """list_recording_rules  # noqa: E501

        Lists all rules in the database: active or deleted  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_recording_rules_with_http_info(async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :return: list[RecordingRuleJSON]
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = []  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_recording_rules" % key
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
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['api_key', 'basic']  # noqa: E501

        return self.api_client.call_api(
            '/recording-rules', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='list[RecordingRuleJSON]',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def test_create_recording_rule(self, body, **kwargs):  # noqa: E501
        """Test a recording rule.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.test_create_recording_rule(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.test_create_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
        else:
            (data) = self.test_create_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
            return data

    def test_create_recording_rule_with_http_info(self, body, **kwargs):  # noqa: E501
        """Test a recording rule.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.test_create_recording_rule_with_http_info(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: SuccessResponseBody
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
                    " to method test_create_recording_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `test_create_recording_rule`")  # noqa: E501

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
            '/recording-rules/test', 'POST',
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

    def update_recording_rule(self, body, **kwargs):  # noqa: E501
        """update_recording_rule  # noqa: E501

        Update the active status of a rule  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_recording_rule(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: RecordingRuleJSON
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.update_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
        else:
            (data) = self.update_recording_rule_with_http_info(body, **kwargs)  # noqa: E501
            return data

    def update_recording_rule_with_http_info(self, body, **kwargs):  # noqa: E501
        """update_recording_rule  # noqa: E501

        Update the active status of a rule  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.update_recording_rule_with_http_info(body, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param RecordingRuleJSON body: (required)
        :return: RecordingRuleJSON
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
                    " to method update_recording_rule" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `update_recording_rule`")  # noqa: E501

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
            '/recording-rules', 'PUT',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='RecordingRuleJSON',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)