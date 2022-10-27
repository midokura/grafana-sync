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


class DiscoveryBase(object):
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
        'error': 'str',
        'error_type': 'ErrorType',
        'status': 'str'
    }

    attribute_map = {
        'error': 'error',
        'error_type': 'errorType',
        'status': 'status'
    }

    def __init__(self, error=None, error_type=None, status=None, _configuration=None):  # noqa: E501
        """DiscoveryBase - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._error = None
        self._error_type = None
        self._status = None
        self.discriminator = None

        if error is not None:
            self.error = error
        if error_type is not None:
            self.error_type = error_type
        self.status = status

    @property
    def error(self):
        """Gets the error of this DiscoveryBase.  # noqa: E501


        :return: The error of this DiscoveryBase.  # noqa: E501
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error):
        """Sets the error of this DiscoveryBase.


        :param error: The error of this DiscoveryBase.  # noqa: E501
        :type: str
        """

        self._error = error

    @property
    def error_type(self):
        """Gets the error_type of this DiscoveryBase.  # noqa: E501


        :return: The error_type of this DiscoveryBase.  # noqa: E501
        :rtype: ErrorType
        """
        return self._error_type

    @error_type.setter
    def error_type(self, error_type):
        """Sets the error_type of this DiscoveryBase.


        :param error_type: The error_type of this DiscoveryBase.  # noqa: E501
        :type: ErrorType
        """

        self._error_type = error_type

    @property
    def status(self):
        """Gets the status of this DiscoveryBase.  # noqa: E501


        :return: The status of this DiscoveryBase.  # noqa: E501
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this DiscoveryBase.


        :param status: The status of this DiscoveryBase.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and status is None:
            raise ValueError("Invalid value for `status`, must not be `None`")  # noqa: E501

        self._status = status

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
        if issubclass(DiscoveryBase, dict):
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
        if not isinstance(other, DiscoveryBase):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DiscoveryBase):
            return True

        return self.to_dict() != other.to_dict()
