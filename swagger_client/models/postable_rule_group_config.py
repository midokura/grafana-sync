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


class PostableRuleGroupConfig(object):
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
        'interval': 'Duration',
        'name': 'str',
        'rules': 'list[PostableExtendedRuleNode]'
    }

    attribute_map = {
        'interval': 'interval',
        'name': 'name',
        'rules': 'rules'
    }

    def __init__(self, interval=None, name=None, rules=None, _configuration=None):  # noqa: E501
        """PostableRuleGroupConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._interval = None
        self._name = None
        self._rules = None
        self.discriminator = None

        if interval is not None:
            self.interval = interval
        if name is not None:
            self.name = name
        if rules is not None:
            self.rules = rules

    @property
    def interval(self):
        """Gets the interval of this PostableRuleGroupConfig.  # noqa: E501


        :return: The interval of this PostableRuleGroupConfig.  # noqa: E501
        :rtype: Duration
        """
        return self._interval

    @interval.setter
    def interval(self, interval):
        """Sets the interval of this PostableRuleGroupConfig.


        :param interval: The interval of this PostableRuleGroupConfig.  # noqa: E501
        :type: Duration
        """

        self._interval = interval

    @property
    def name(self):
        """Gets the name of this PostableRuleGroupConfig.  # noqa: E501


        :return: The name of this PostableRuleGroupConfig.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this PostableRuleGroupConfig.


        :param name: The name of this PostableRuleGroupConfig.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def rules(self):
        """Gets the rules of this PostableRuleGroupConfig.  # noqa: E501


        :return: The rules of this PostableRuleGroupConfig.  # noqa: E501
        :rtype: list[PostableExtendedRuleNode]
        """
        return self._rules

    @rules.setter
    def rules(self, rules):
        """Sets the rules of this PostableRuleGroupConfig.


        :param rules: The rules of this PostableRuleGroupConfig.  # noqa: E501
        :type: list[PostableExtendedRuleNode]
        """

        self._rules = rules

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
        if issubclass(PostableRuleGroupConfig, dict):
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
        if not isinstance(other, PostableRuleGroupConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, PostableRuleGroupConfig):
            return True

        return self.to_dict() != other.to_dict()
