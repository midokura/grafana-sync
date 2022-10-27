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


class CreateCorrelationResponseBody(object):
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
        'message': 'str',
        'result': 'Correlation'
    }

    attribute_map = {
        'message': 'message',
        'result': 'result'
    }

    def __init__(self, message=None, result=None, _configuration=None):  # noqa: E501
        """CreateCorrelationResponseBody - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._message = None
        self._result = None
        self.discriminator = None

        if message is not None:
            self.message = message
        if result is not None:
            self.result = result

    @property
    def message(self):
        """Gets the message of this CreateCorrelationResponseBody.  # noqa: E501


        :return: The message of this CreateCorrelationResponseBody.  # noqa: E501
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """Sets the message of this CreateCorrelationResponseBody.


        :param message: The message of this CreateCorrelationResponseBody.  # noqa: E501
        :type: str
        """

        self._message = message

    @property
    def result(self):
        """Gets the result of this CreateCorrelationResponseBody.  # noqa: E501


        :return: The result of this CreateCorrelationResponseBody.  # noqa: E501
        :rtype: Correlation
        """
        return self._result

    @result.setter
    def result(self, result):
        """Sets the result of this CreateCorrelationResponseBody.


        :param result: The result of this CreateCorrelationResponseBody.  # noqa: E501
        :type: Correlation
        """

        self._result = result

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
        if issubclass(CreateCorrelationResponseBody, dict):
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
        if not isinstance(other, CreateCorrelationResponseBody):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, CreateCorrelationResponseBody):
            return True

        return self.to_dict() != other.to_dict()
