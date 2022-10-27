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


class UpdateUserCommand(object):
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
        'email': 'str',
        'login': 'str',
        'name': 'str',
        'theme': 'str'
    }

    attribute_map = {
        'email': 'email',
        'login': 'login',
        'name': 'name',
        'theme': 'theme'
    }

    def __init__(self, email=None, login=None, name=None, theme=None, _configuration=None):  # noqa: E501
        """UpdateUserCommand - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._email = None
        self._login = None
        self._name = None
        self._theme = None
        self.discriminator = None

        if email is not None:
            self.email = email
        if login is not None:
            self.login = login
        if name is not None:
            self.name = name
        if theme is not None:
            self.theme = theme

    @property
    def email(self):
        """Gets the email of this UpdateUserCommand.  # noqa: E501


        :return: The email of this UpdateUserCommand.  # noqa: E501
        :rtype: str
        """
        return self._email

    @email.setter
    def email(self, email):
        """Sets the email of this UpdateUserCommand.


        :param email: The email of this UpdateUserCommand.  # noqa: E501
        :type: str
        """

        self._email = email

    @property
    def login(self):
        """Gets the login of this UpdateUserCommand.  # noqa: E501


        :return: The login of this UpdateUserCommand.  # noqa: E501
        :rtype: str
        """
        return self._login

    @login.setter
    def login(self, login):
        """Sets the login of this UpdateUserCommand.


        :param login: The login of this UpdateUserCommand.  # noqa: E501
        :type: str
        """

        self._login = login

    @property
    def name(self):
        """Gets the name of this UpdateUserCommand.  # noqa: E501


        :return: The name of this UpdateUserCommand.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this UpdateUserCommand.


        :param name: The name of this UpdateUserCommand.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def theme(self):
        """Gets the theme of this UpdateUserCommand.  # noqa: E501


        :return: The theme of this UpdateUserCommand.  # noqa: E501
        :rtype: str
        """
        return self._theme

    @theme.setter
    def theme(self, theme):
        """Sets the theme of this UpdateUserCommand.


        :param theme: The theme of this UpdateUserCommand.  # noqa: E501
        :type: str
        """

        self._theme = theme

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
        if issubclass(UpdateUserCommand, dict):
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
        if not isinstance(other, UpdateUserCommand):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, UpdateUserCommand):
            return True

        return self.to_dict() != other.to_dict()
