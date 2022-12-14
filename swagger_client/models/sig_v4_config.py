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


class SigV4Config(object):
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
        'access_key': 'str',
        'profile': 'str',
        'region': 'str',
        'role_arn': 'str',
        'secret_key': 'Secret'
    }

    attribute_map = {
        'access_key': 'AccessKey',
        'profile': 'Profile',
        'region': 'Region',
        'role_arn': 'RoleARN',
        'secret_key': 'SecretKey'
    }

    def __init__(self, access_key=None, profile=None, region=None, role_arn=None, secret_key=None, _configuration=None):  # noqa: E501
        """SigV4Config - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._access_key = None
        self._profile = None
        self._region = None
        self._role_arn = None
        self._secret_key = None
        self.discriminator = None

        if access_key is not None:
            self.access_key = access_key
        if profile is not None:
            self.profile = profile
        if region is not None:
            self.region = region
        if role_arn is not None:
            self.role_arn = role_arn
        if secret_key is not None:
            self.secret_key = secret_key

    @property
    def access_key(self):
        """Gets the access_key of this SigV4Config.  # noqa: E501


        :return: The access_key of this SigV4Config.  # noqa: E501
        :rtype: str
        """
        return self._access_key

    @access_key.setter
    def access_key(self, access_key):
        """Sets the access_key of this SigV4Config.


        :param access_key: The access_key of this SigV4Config.  # noqa: E501
        :type: str
        """

        self._access_key = access_key

    @property
    def profile(self):
        """Gets the profile of this SigV4Config.  # noqa: E501


        :return: The profile of this SigV4Config.  # noqa: E501
        :rtype: str
        """
        return self._profile

    @profile.setter
    def profile(self, profile):
        """Sets the profile of this SigV4Config.


        :param profile: The profile of this SigV4Config.  # noqa: E501
        :type: str
        """

        self._profile = profile

    @property
    def region(self):
        """Gets the region of this SigV4Config.  # noqa: E501


        :return: The region of this SigV4Config.  # noqa: E501
        :rtype: str
        """
        return self._region

    @region.setter
    def region(self, region):
        """Sets the region of this SigV4Config.


        :param region: The region of this SigV4Config.  # noqa: E501
        :type: str
        """

        self._region = region

    @property
    def role_arn(self):
        """Gets the role_arn of this SigV4Config.  # noqa: E501


        :return: The role_arn of this SigV4Config.  # noqa: E501
        :rtype: str
        """
        return self._role_arn

    @role_arn.setter
    def role_arn(self, role_arn):
        """Sets the role_arn of this SigV4Config.


        :param role_arn: The role_arn of this SigV4Config.  # noqa: E501
        :type: str
        """

        self._role_arn = role_arn

    @property
    def secret_key(self):
        """Gets the secret_key of this SigV4Config.  # noqa: E501


        :return: The secret_key of this SigV4Config.  # noqa: E501
        :rtype: Secret
        """
        return self._secret_key

    @secret_key.setter
    def secret_key(self, secret_key):
        """Sets the secret_key of this SigV4Config.


        :param secret_key: The secret_key of this SigV4Config.  # noqa: E501
        :type: Secret
        """

        self._secret_key = secret_key

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
        if issubclass(SigV4Config, dict):
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
        if not isinstance(other, SigV4Config):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, SigV4Config):
            return True

        return self.to_dict() != other.to_dict()
