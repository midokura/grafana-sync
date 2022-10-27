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


class SearchServiceAccountsResult(object):
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
        'service_accounts': 'list[ServiceAccountDTO]',
        'total_count': 'int'
    }

    attribute_map = {
        'page': 'page',
        'per_page': 'perPage',
        'service_accounts': 'serviceAccounts',
        'total_count': 'totalCount'
    }

    def __init__(self, page=None, per_page=None, service_accounts=None, total_count=None, _configuration=None):  # noqa: E501
        """SearchServiceAccountsResult - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._page = None
        self._per_page = None
        self._service_accounts = None
        self._total_count = None
        self.discriminator = None

        if page is not None:
            self.page = page
        if per_page is not None:
            self.per_page = per_page
        if service_accounts is not None:
            self.service_accounts = service_accounts
        if total_count is not None:
            self.total_count = total_count

    @property
    def page(self):
        """Gets the page of this SearchServiceAccountsResult.  # noqa: E501


        :return: The page of this SearchServiceAccountsResult.  # noqa: E501
        :rtype: int
        """
        return self._page

    @page.setter
    def page(self, page):
        """Sets the page of this SearchServiceAccountsResult.


        :param page: The page of this SearchServiceAccountsResult.  # noqa: E501
        :type: int
        """

        self._page = page

    @property
    def per_page(self):
        """Gets the per_page of this SearchServiceAccountsResult.  # noqa: E501


        :return: The per_page of this SearchServiceAccountsResult.  # noqa: E501
        :rtype: int
        """
        return self._per_page

    @per_page.setter
    def per_page(self, per_page):
        """Sets the per_page of this SearchServiceAccountsResult.


        :param per_page: The per_page of this SearchServiceAccountsResult.  # noqa: E501
        :type: int
        """

        self._per_page = per_page

    @property
    def service_accounts(self):
        """Gets the service_accounts of this SearchServiceAccountsResult.  # noqa: E501


        :return: The service_accounts of this SearchServiceAccountsResult.  # noqa: E501
        :rtype: list[ServiceAccountDTO]
        """
        return self._service_accounts

    @service_accounts.setter
    def service_accounts(self, service_accounts):
        """Sets the service_accounts of this SearchServiceAccountsResult.


        :param service_accounts: The service_accounts of this SearchServiceAccountsResult.  # noqa: E501
        :type: list[ServiceAccountDTO]
        """

        self._service_accounts = service_accounts

    @property
    def total_count(self):
        """Gets the total_count of this SearchServiceAccountsResult.  # noqa: E501

        It can be used for pagination of the user list E.g. if totalCount is equal to 100 users and the perpage parameter is set to 10 then there are 10 pages of users.  # noqa: E501

        :return: The total_count of this SearchServiceAccountsResult.  # noqa: E501
        :rtype: int
        """
        return self._total_count

    @total_count.setter
    def total_count(self, total_count):
        """Sets the total_count of this SearchServiceAccountsResult.

        It can be used for pagination of the user list E.g. if totalCount is equal to 100 users and the perpage parameter is set to 10 then there are 10 pages of users.  # noqa: E501

        :param total_count: The total_count of this SearchServiceAccountsResult.  # noqa: E501
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
        if issubclass(SearchServiceAccountsResult, dict):
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
        if not isinstance(other, SearchServiceAccountsResult):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, SearchServiceAccountsResult):
            return True

        return self.to_dict() != other.to_dict()
