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


class CreateServiceAccountForm(object):
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
        'is_disabled': 'bool',
        'name': 'str',
        'role': 'str'
    }

    attribute_map = {
        'is_disabled': 'isDisabled',
        'name': 'name',
        'role': 'role'
    }

    def __init__(self, is_disabled=None, name=None, role=None, _configuration=None):  # noqa: E501
        """CreateServiceAccountForm - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._is_disabled = None
        self._name = None
        self._role = None
        self.discriminator = None

        if is_disabled is not None:
            self.is_disabled = is_disabled
        if name is not None:
            self.name = name
        if role is not None:
            self.role = role

    @property
    def is_disabled(self):
        """Gets the is_disabled of this CreateServiceAccountForm.  # noqa: E501


        :return: The is_disabled of this CreateServiceAccountForm.  # noqa: E501
        :rtype: bool
        """
        return self._is_disabled

    @is_disabled.setter
    def is_disabled(self, is_disabled):
        """Sets the is_disabled of this CreateServiceAccountForm.


        :param is_disabled: The is_disabled of this CreateServiceAccountForm.  # noqa: E501
        :type: bool
        """

        self._is_disabled = is_disabled

    @property
    def name(self):
        """Gets the name of this CreateServiceAccountForm.  # noqa: E501


        :return: The name of this CreateServiceAccountForm.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this CreateServiceAccountForm.


        :param name: The name of this CreateServiceAccountForm.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def role(self):
        """Gets the role of this CreateServiceAccountForm.  # noqa: E501


        :return: The role of this CreateServiceAccountForm.  # noqa: E501
        :rtype: str
        """
        return self._role

    @role.setter
    def role(self, role):
        """Sets the role of this CreateServiceAccountForm.


        :param role: The role of this CreateServiceAccountForm.  # noqa: E501
        :type: str
        """
        allowed_values = ["Viewer", "Editor", "Admin"]  # noqa: E501
        if (self._configuration.client_side_validation and
                role not in allowed_values):
            raise ValueError(
                "Invalid value for `role` ({0}), must be one of {1}"  # noqa: E501
                .format(role, allowed_values)
            )

        self._role = role

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
        if issubclass(CreateServiceAccountForm, dict):
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
        if not isinstance(other, CreateServiceAccountForm):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, CreateServiceAccountForm):
            return True

        return self.to_dict() != other.to_dict()
