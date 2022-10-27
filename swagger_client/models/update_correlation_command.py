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


class UpdateCorrelationCommand(object):
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
        'description': 'str',
        'label': 'str'
    }

    attribute_map = {
        'description': 'description',
        'label': 'label'
    }

    def __init__(self, description=None, label=None, _configuration=None):  # noqa: E501
        """UpdateCorrelationCommand - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._description = None
        self._label = None
        self.discriminator = None

        if description is not None:
            self.description = description
        if label is not None:
            self.label = label

    @property
    def description(self):
        """Gets the description of this UpdateCorrelationCommand.  # noqa: E501

        Optional description of the correlation  # noqa: E501

        :return: The description of this UpdateCorrelationCommand.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this UpdateCorrelationCommand.

        Optional description of the correlation  # noqa: E501

        :param description: The description of this UpdateCorrelationCommand.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def label(self):
        """Gets the label of this UpdateCorrelationCommand.  # noqa: E501

        Optional label identifying the correlation  # noqa: E501

        :return: The label of this UpdateCorrelationCommand.  # noqa: E501
        :rtype: str
        """
        return self._label

    @label.setter
    def label(self, label):
        """Sets the label of this UpdateCorrelationCommand.

        Optional label identifying the correlation  # noqa: E501

        :param label: The label of this UpdateCorrelationCommand.  # noqa: E501
        :type: str
        """

        self._label = label

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
        if issubclass(UpdateCorrelationCommand, dict):
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
        if not isinstance(other, UpdateCorrelationCommand):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, UpdateCorrelationCommand):
            return True

        return self.to_dict() != other.to_dict()
