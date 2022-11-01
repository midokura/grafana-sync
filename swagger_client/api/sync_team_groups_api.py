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


class SyncTeamGroupsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def add_team_group_api(self, body, team_id, **kwargs):  # noqa: E501
        """Add External Group.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_team_group_api(body, team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param TeamGroupMapping body: (required)
        :param int team_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.add_team_group_api_with_http_info(body, team_id, **kwargs)  # noqa: E501
        else:
            (data) = self.add_team_group_api_with_http_info(body, team_id, **kwargs)  # noqa: E501
            return data

    def add_team_group_api_with_http_info(self, body, team_id, **kwargs):  # noqa: E501
        """Add External Group.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_team_group_api_with_http_info(body, team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param TeamGroupMapping body: (required)
        :param int team_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['body', 'team_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method add_team_group_api" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'body' is set
        if self.api_client.client_side_validation and ('body' not in params or
                                                       params['body'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `body` when calling `add_team_group_api`")  # noqa: E501
        # verify the required parameter 'team_id' is set
        if self.api_client.client_side_validation and ('team_id' not in params or
                                                       params['team_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `team_id` when calling `add_team_group_api`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'team_id' in params:
            path_params['teamId'] = params['team_id']  # noqa: E501

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
            '/teams/{teamId}/groups', 'POST',
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

    def get_team_groups_api(self, team_id, **kwargs):  # noqa: E501
        """Get External Groups.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_team_groups_api(team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int team_id: (required)
        :return: list[TeamGroupDTO]
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.get_team_groups_api_with_http_info(team_id, **kwargs)  # noqa: E501
        else:
            (data) = self.get_team_groups_api_with_http_info(team_id, **kwargs)  # noqa: E501
            return data

    def get_team_groups_api_with_http_info(self, team_id, **kwargs):  # noqa: E501
        """Get External Groups.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.get_team_groups_api_with_http_info(team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int team_id: (required)
        :return: list[TeamGroupDTO]
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['team_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method get_team_groups_api" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'team_id' is set
        if self.api_client.client_side_validation and ('team_id' not in params or
                                                       params['team_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `team_id` when calling `get_team_groups_api`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'team_id' in params:
            path_params['teamId'] = params['team_id']  # noqa: E501

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
            '/teams/{teamId}/groups', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='list[TeamGroupDTO]',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def remove_team_group_api(self, group_id, team_id, **kwargs):  # noqa: E501
        """Remove External Group.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.remove_team_group_api(group_id, team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str group_id: (required)
        :param int team_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.remove_team_group_api_with_http_info(group_id, team_id, **kwargs)  # noqa: E501
        else:
            (data) = self.remove_team_group_api_with_http_info(group_id, team_id, **kwargs)  # noqa: E501
            return data

    def remove_team_group_api_with_http_info(self, group_id, team_id, **kwargs):  # noqa: E501
        """Remove External Group.  # noqa: E501

        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.remove_team_group_api_with_http_info(group_id, team_id, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str group_id: (required)
        :param int team_id: (required)
        :return: SuccessResponseBody
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['group_id', 'team_id']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method remove_team_group_api" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'group_id' is set
        if self.api_client.client_side_validation and ('group_id' not in params or
                                                       params['group_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `group_id` when calling `remove_team_group_api`")  # noqa: E501
        # verify the required parameter 'team_id' is set
        if self.api_client.client_side_validation and ('team_id' not in params or
                                                       params['team_id'] is None):  # noqa: E501
            raise ValueError("Missing the required parameter `team_id` when calling `remove_team_group_api`")  # noqa: E501

        collection_formats = {}

        path_params = {}
        if 'group_id' in params:
            path_params['groupId'] = params['group_id']  # noqa: E501
        if 'team_id' in params:
            path_params['teamId'] = params['team_id']  # noqa: E501

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
            '/teams/{teamId}/groups/{groupId}', 'DELETE',
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