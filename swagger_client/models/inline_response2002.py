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


class InlineResponse2002(object):
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
        'alert_id': 'int',
        'message': 'str',
        'state': 'str'
    }

    attribute_map = {
        'alert_id': 'alertId',
        'message': 'message',
        'state': 'state'
    }

    def __init__(self, alert_id=None, message=None, state=None, _configuration=None):  # noqa: E501
        """InlineResponse2002 - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._alert_id = None
        self._message = None
        self._state = None
        self.discriminator = None

        self.alert_id = alert_id
        self.message = message
        if state is not None:
            self.state = state

    @property
    def alert_id(self):
        """Gets the alert_id of this InlineResponse2002.  # noqa: E501


        :return: The alert_id of this InlineResponse2002.  # noqa: E501
        :rtype: int
        """
        return self._alert_id

    @alert_id.setter
    def alert_id(self, alert_id):
        """Sets the alert_id of this InlineResponse2002.


        :param alert_id: The alert_id of this InlineResponse2002.  # noqa: E501
        :type: int
        """
        if self._configuration.client_side_validation and alert_id is None:
            raise ValueError("Invalid value for `alert_id`, must not be `None`")  # noqa: E501

        self._alert_id = alert_id

    @property
    def message(self):
        """Gets the message of this InlineResponse2002.  # noqa: E501


        :return: The message of this InlineResponse2002.  # noqa: E501
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """Sets the message of this InlineResponse2002.


        :param message: The message of this InlineResponse2002.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and message is None:
            raise ValueError("Invalid value for `message`, must not be `None`")  # noqa: E501

        self._message = message

    @property
    def state(self):
        """Gets the state of this InlineResponse2002.  # noqa: E501

        Alert result state required true  # noqa: E501

        :return: The state of this InlineResponse2002.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this InlineResponse2002.

        Alert result state required true  # noqa: E501

        :param state: The state of this InlineResponse2002.  # noqa: E501
        :type: str
        """

        self._state = state

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
        if issubclass(InlineResponse2002, dict):
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
        if not isinstance(other, InlineResponse2002):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, InlineResponse2002):
            return True

        return self.to_dict() != other.to_dict()