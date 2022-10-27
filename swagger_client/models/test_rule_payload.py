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


class TestRulePayload(object):
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
        'expr': 'str',
        'grafana_condition': 'EvalAlertConditionCommand'
    }

    attribute_map = {
        'expr': 'expr',
        'grafana_condition': 'grafana_condition'
    }

    def __init__(self, expr=None, grafana_condition=None, _configuration=None):  # noqa: E501
        """TestRulePayload - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._expr = None
        self._grafana_condition = None
        self.discriminator = None

        if expr is not None:
            self.expr = expr
        if grafana_condition is not None:
            self.grafana_condition = grafana_condition

    @property
    def expr(self):
        """Gets the expr of this TestRulePayload.  # noqa: E501


        :return: The expr of this TestRulePayload.  # noqa: E501
        :rtype: str
        """
        return self._expr

    @expr.setter
    def expr(self, expr):
        """Sets the expr of this TestRulePayload.


        :param expr: The expr of this TestRulePayload.  # noqa: E501
        :type: str
        """

        self._expr = expr

    @property
    def grafana_condition(self):
        """Gets the grafana_condition of this TestRulePayload.  # noqa: E501


        :return: The grafana_condition of this TestRulePayload.  # noqa: E501
        :rtype: EvalAlertConditionCommand
        """
        return self._grafana_condition

    @grafana_condition.setter
    def grafana_condition(self, grafana_condition):
        """Sets the grafana_condition of this TestRulePayload.


        :param grafana_condition: The grafana_condition of this TestRulePayload.  # noqa: E501
        :type: EvalAlertConditionCommand
        """

        self._grafana_condition = grafana_condition

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
        if issubclass(TestRulePayload, dict):
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
        if not isinstance(other, TestRulePayload):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TestRulePayload):
            return True

        return self.to_dict() != other.to_dict()
