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


class ImportDashboardInput(object):
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
        'name': 'str',
        'plugin_id': 'str',
        'type': 'str',
        'value': 'str'
    }

    attribute_map = {
        'name': 'name',
        'plugin_id': 'pluginId',
        'type': 'type',
        'value': 'value'
    }

    def __init__(self, name=None, plugin_id=None, type=None, value=None, _configuration=None):  # noqa: E501
        """ImportDashboardInput - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._name = None
        self._plugin_id = None
        self._type = None
        self._value = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if plugin_id is not None:
            self.plugin_id = plugin_id
        if type is not None:
            self.type = type
        if value is not None:
            self.value = value

    @property
    def name(self):
        """Gets the name of this ImportDashboardInput.  # noqa: E501


        :return: The name of this ImportDashboardInput.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this ImportDashboardInput.


        :param name: The name of this ImportDashboardInput.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def plugin_id(self):
        """Gets the plugin_id of this ImportDashboardInput.  # noqa: E501


        :return: The plugin_id of this ImportDashboardInput.  # noqa: E501
        :rtype: str
        """
        return self._plugin_id

    @plugin_id.setter
    def plugin_id(self, plugin_id):
        """Sets the plugin_id of this ImportDashboardInput.


        :param plugin_id: The plugin_id of this ImportDashboardInput.  # noqa: E501
        :type: str
        """

        self._plugin_id = plugin_id

    @property
    def type(self):
        """Gets the type of this ImportDashboardInput.  # noqa: E501


        :return: The type of this ImportDashboardInput.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this ImportDashboardInput.


        :param type: The type of this ImportDashboardInput.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def value(self):
        """Gets the value of this ImportDashboardInput.  # noqa: E501


        :return: The value of this ImportDashboardInput.  # noqa: E501
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """Sets the value of this ImportDashboardInput.


        :param value: The value of this ImportDashboardInput.  # noqa: E501
        :type: str
        """

        self._value = value

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
        if issubclass(ImportDashboardInput, dict):
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
        if not isinstance(other, ImportDashboardInput):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ImportDashboardInput):
            return True

        return self.to_dict() != other.to_dict()
