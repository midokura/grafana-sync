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


class RevokeAuthTokenCmd(object):
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
        'auth_token_id': 'int'
    }

    attribute_map = {
        'auth_token_id': 'authTokenId'
    }

    def __init__(self, auth_token_id=None, _configuration=None):  # noqa: E501
        """RevokeAuthTokenCmd - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._auth_token_id = None
        self.discriminator = None

        if auth_token_id is not None:
            self.auth_token_id = auth_token_id

    @property
    def auth_token_id(self):
        """Gets the auth_token_id of this RevokeAuthTokenCmd.  # noqa: E501


        :return: The auth_token_id of this RevokeAuthTokenCmd.  # noqa: E501
        :rtype: int
        """
        return self._auth_token_id

    @auth_token_id.setter
    def auth_token_id(self, auth_token_id):
        """Sets the auth_token_id of this RevokeAuthTokenCmd.


        :param auth_token_id: The auth_token_id of this RevokeAuthTokenCmd.  # noqa: E501
        :type: int
        """

        self._auth_token_id = auth_token_id

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
        if issubclass(RevokeAuthTokenCmd, dict):
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
        if not isinstance(other, RevokeAuthTokenCmd):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, RevokeAuthTokenCmd):
            return True

        return self.to_dict() != other.to_dict()
