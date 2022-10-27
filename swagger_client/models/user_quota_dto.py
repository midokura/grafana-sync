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


class UserQuotaDTO(object):
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
        'limit': 'int',
        'target': 'str',
        'used': 'int',
        'user_id': 'int'
    }

    attribute_map = {
        'limit': 'limit',
        'target': 'target',
        'used': 'used',
        'user_id': 'user_id'
    }

    def __init__(self, limit=None, target=None, used=None, user_id=None, _configuration=None):  # noqa: E501
        """UserQuotaDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._limit = None
        self._target = None
        self._used = None
        self._user_id = None
        self.discriminator = None

        if limit is not None:
            self.limit = limit
        if target is not None:
            self.target = target
        if used is not None:
            self.used = used
        if user_id is not None:
            self.user_id = user_id

    @property
    def limit(self):
        """Gets the limit of this UserQuotaDTO.  # noqa: E501


        :return: The limit of this UserQuotaDTO.  # noqa: E501
        :rtype: int
        """
        return self._limit

    @limit.setter
    def limit(self, limit):
        """Sets the limit of this UserQuotaDTO.


        :param limit: The limit of this UserQuotaDTO.  # noqa: E501
        :type: int
        """

        self._limit = limit

    @property
    def target(self):
        """Gets the target of this UserQuotaDTO.  # noqa: E501


        :return: The target of this UserQuotaDTO.  # noqa: E501
        :rtype: str
        """
        return self._target

    @target.setter
    def target(self, target):
        """Sets the target of this UserQuotaDTO.


        :param target: The target of this UserQuotaDTO.  # noqa: E501
        :type: str
        """

        self._target = target

    @property
    def used(self):
        """Gets the used of this UserQuotaDTO.  # noqa: E501


        :return: The used of this UserQuotaDTO.  # noqa: E501
        :rtype: int
        """
        return self._used

    @used.setter
    def used(self, used):
        """Sets the used of this UserQuotaDTO.


        :param used: The used of this UserQuotaDTO.  # noqa: E501
        :type: int
        """

        self._used = used

    @property
    def user_id(self):
        """Gets the user_id of this UserQuotaDTO.  # noqa: E501


        :return: The user_id of this UserQuotaDTO.  # noqa: E501
        :rtype: int
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """Sets the user_id of this UserQuotaDTO.


        :param user_id: The user_id of this UserQuotaDTO.  # noqa: E501
        :type: int
        """

        self._user_id = user_id

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
        if issubclass(UserQuotaDTO, dict):
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
        if not isinstance(other, UserQuotaDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, UserQuotaDTO):
            return True

        return self.to_dict() != other.to_dict()
