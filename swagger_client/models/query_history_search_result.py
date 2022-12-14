# coding: utf-8

"""
    Grafana HTTP API.

    The Grafana backend exposes an HTTP API, the same API is used by the frontend to do everything from saving dashboards, creating users and updating data sources.  # noqa: E501

    OpenAPI spec version: 0.0.1
    Contact: hello@grafana.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six

from swagger_client.configuration import Configuration


class QueryHistorySearchResult(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'page': 'int',
        'per_page': 'int',
        'query_history': 'list[QueryHistoryDTO]',
        'total_count': 'int'
    }

    attribute_map = {
        'page': 'page',
        'per_page': 'perPage',
        'query_history': 'queryHistory',
        'total_count': 'totalCount'
    }

    def __init__(self, page=None, per_page=None, query_history=None, total_count=None, _configuration=None):  # noqa: E501
        """QueryHistorySearchResult - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._page = None
        self._per_page = None
        self._query_history = None
        self._total_count = None
        self.discriminator = None

        if page is not None:
            self.page = page
        if per_page is not None:
            self.per_page = per_page
        if query_history is not None:
            self.query_history = query_history
        if total_count is not None:
            self.total_count = total_count

    @property
    def page(self):
        """Gets the page of this QueryHistorySearchResult.  # noqa: E501


        :return: The page of this QueryHistorySearchResult.  # noqa: E501
        :rtype: int
        """
        return self._page

    @page.setter
    def page(self, page):
        """Sets the page of this QueryHistorySearchResult.


        :param page: The page of this QueryHistorySearchResult.  # noqa: E501
        :type: int
        """

        self._page = page

    @property
    def per_page(self):
        """Gets the per_page of this QueryHistorySearchResult.  # noqa: E501


        :return: The per_page of this QueryHistorySearchResult.  # noqa: E501
        :rtype: int
        """
        return self._per_page

    @per_page.setter
    def per_page(self, per_page):
        """Sets the per_page of this QueryHistorySearchResult.


        :param per_page: The per_page of this QueryHistorySearchResult.  # noqa: E501
        :type: int
        """

        self._per_page = per_page

    @property
    def query_history(self):
        """Gets the query_history of this QueryHistorySearchResult.  # noqa: E501


        :return: The query_history of this QueryHistorySearchResult.  # noqa: E501
        :rtype: list[QueryHistoryDTO]
        """
        return self._query_history

    @query_history.setter
    def query_history(self, query_history):
        """Sets the query_history of this QueryHistorySearchResult.


        :param query_history: The query_history of this QueryHistorySearchResult.  # noqa: E501
        :type: list[QueryHistoryDTO]
        """

        self._query_history = query_history

    @property
    def total_count(self):
        """Gets the total_count of this QueryHistorySearchResult.  # noqa: E501


        :return: The total_count of this QueryHistorySearchResult.  # noqa: E501
        :rtype: int
        """
        return self._total_count

    @total_count.setter
    def total_count(self, total_count):
        """Sets the total_count of this QueryHistorySearchResult.


        :param total_count: The total_count of this QueryHistorySearchResult.  # noqa: E501
        :type: int
        """

        self._total_count = total_count

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(QueryHistorySearchResult, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, QueryHistorySearchResult):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, QueryHistorySearchResult):
            return True

        return self.to_dict() != other.to_dict()
