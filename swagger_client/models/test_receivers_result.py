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


class TestReceiversResult(object):
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
        'alert': 'TestReceiversConfigAlertParams',
        'notified_at': 'datetime',
        'receivers': 'list[TestReceiverResult]'
    }

    attribute_map = {
        'alert': 'alert',
        'notified_at': 'notified_at',
        'receivers': 'receivers'
    }

    def __init__(self, alert=None, notified_at=None, receivers=None, _configuration=None):  # noqa: E501
        """TestReceiversResult - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._alert = None
        self._notified_at = None
        self._receivers = None
        self.discriminator = None

        if alert is not None:
            self.alert = alert
        if notified_at is not None:
            self.notified_at = notified_at
        if receivers is not None:
            self.receivers = receivers

    @property
    def alert(self):
        """Gets the alert of this TestReceiversResult.  # noqa: E501


        :return: The alert of this TestReceiversResult.  # noqa: E501
        :rtype: TestReceiversConfigAlertParams
        """
        return self._alert

    @alert.setter
    def alert(self, alert):
        """Sets the alert of this TestReceiversResult.


        :param alert: The alert of this TestReceiversResult.  # noqa: E501
        :type: TestReceiversConfigAlertParams
        """

        self._alert = alert

    @property
    def notified_at(self):
        """Gets the notified_at of this TestReceiversResult.  # noqa: E501


        :return: The notified_at of this TestReceiversResult.  # noqa: E501
        :rtype: datetime
        """
        return self._notified_at

    @notified_at.setter
    def notified_at(self, notified_at):
        """Sets the notified_at of this TestReceiversResult.


        :param notified_at: The notified_at of this TestReceiversResult.  # noqa: E501
        :type: datetime
        """

        self._notified_at = notified_at

    @property
    def receivers(self):
        """Gets the receivers of this TestReceiversResult.  # noqa: E501


        :return: The receivers of this TestReceiversResult.  # noqa: E501
        :rtype: list[TestReceiverResult]
        """
        return self._receivers

    @receivers.setter
    def receivers(self, receivers):
        """Sets the receivers of this TestReceiversResult.


        :param receivers: The receivers of this TestReceiversResult.  # noqa: E501
        :type: list[TestReceiverResult]
        """

        self._receivers = receivers

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
        if issubclass(TestReceiversResult, dict):
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
        if not isinstance(other, TestReceiversResult):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TestReceiversResult):
            return True

        return self.to_dict() != other.to_dict()
