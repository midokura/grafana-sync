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


class PostableApiAlertingConfig(object):
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
        '_global': 'GlobalConfig',
        'inhibit_rules': 'list[InhibitRule]',
        'mute_time_intervals': 'list[MuteTimeInterval]',
        'receivers': 'list[PostableApiReceiver]',
        'route': 'Route',
        'templates': 'list[str]'
    }

    attribute_map = {
        '_global': 'global',
        'inhibit_rules': 'inhibit_rules',
        'mute_time_intervals': 'mute_time_intervals',
        'receivers': 'receivers',
        'route': 'route',
        'templates': 'templates'
    }

    def __init__(self, _global=None, inhibit_rules=None, mute_time_intervals=None, receivers=None, route=None, templates=None, _configuration=None):  # noqa: E501
        """PostableApiAlertingConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self.__global = None
        self._inhibit_rules = None
        self._mute_time_intervals = None
        self._receivers = None
        self._route = None
        self._templates = None
        self.discriminator = None

        if _global is not None:
            self._global = _global
        if inhibit_rules is not None:
            self.inhibit_rules = inhibit_rules
        if mute_time_intervals is not None:
            self.mute_time_intervals = mute_time_intervals
        if receivers is not None:
            self.receivers = receivers
        if route is not None:
            self.route = route
        if templates is not None:
            self.templates = templates

    @property
    def _global(self):
        """Gets the _global of this PostableApiAlertingConfig.  # noqa: E501


        :return: The _global of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: GlobalConfig
        """
        return self.__global

    @_global.setter
    def _global(self, _global):
        """Sets the _global of this PostableApiAlertingConfig.


        :param _global: The _global of this PostableApiAlertingConfig.  # noqa: E501
        :type: GlobalConfig
        """

        self.__global = _global

    @property
    def inhibit_rules(self):
        """Gets the inhibit_rules of this PostableApiAlertingConfig.  # noqa: E501


        :return: The inhibit_rules of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: list[InhibitRule]
        """
        return self._inhibit_rules

    @inhibit_rules.setter
    def inhibit_rules(self, inhibit_rules):
        """Sets the inhibit_rules of this PostableApiAlertingConfig.


        :param inhibit_rules: The inhibit_rules of this PostableApiAlertingConfig.  # noqa: E501
        :type: list[InhibitRule]
        """

        self._inhibit_rules = inhibit_rules

    @property
    def mute_time_intervals(self):
        """Gets the mute_time_intervals of this PostableApiAlertingConfig.  # noqa: E501


        :return: The mute_time_intervals of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: list[MuteTimeInterval]
        """
        return self._mute_time_intervals

    @mute_time_intervals.setter
    def mute_time_intervals(self, mute_time_intervals):
        """Sets the mute_time_intervals of this PostableApiAlertingConfig.


        :param mute_time_intervals: The mute_time_intervals of this PostableApiAlertingConfig.  # noqa: E501
        :type: list[MuteTimeInterval]
        """

        self._mute_time_intervals = mute_time_intervals

    @property
    def receivers(self):
        """Gets the receivers of this PostableApiAlertingConfig.  # noqa: E501

        Override with our superset receiver type  # noqa: E501

        :return: The receivers of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: list[PostableApiReceiver]
        """
        return self._receivers

    @receivers.setter
    def receivers(self, receivers):
        """Sets the receivers of this PostableApiAlertingConfig.

        Override with our superset receiver type  # noqa: E501

        :param receivers: The receivers of this PostableApiAlertingConfig.  # noqa: E501
        :type: list[PostableApiReceiver]
        """

        self._receivers = receivers

    @property
    def route(self):
        """Gets the route of this PostableApiAlertingConfig.  # noqa: E501


        :return: The route of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: Route
        """
        return self._route

    @route.setter
    def route(self, route):
        """Sets the route of this PostableApiAlertingConfig.


        :param route: The route of this PostableApiAlertingConfig.  # noqa: E501
        :type: Route
        """

        self._route = route

    @property
    def templates(self):
        """Gets the templates of this PostableApiAlertingConfig.  # noqa: E501


        :return: The templates of this PostableApiAlertingConfig.  # noqa: E501
        :rtype: list[str]
        """
        return self._templates

    @templates.setter
    def templates(self, templates):
        """Sets the templates of this PostableApiAlertingConfig.


        :param templates: The templates of this PostableApiAlertingConfig.  # noqa: E501
        :type: list[str]
        """

        self._templates = templates

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
        if issubclass(PostableApiAlertingConfig, dict):
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
        if not isinstance(other, PostableApiAlertingConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, PostableApiAlertingConfig):
            return True

        return self.to_dict() != other.to_dict()