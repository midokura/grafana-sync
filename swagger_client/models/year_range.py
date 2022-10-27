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


class YearRange(object):
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
        'begin': 'int',
        'end': 'int'
    }

    attribute_map = {
        'begin': 'Begin',
        'end': 'End'
    }

    def __init__(self, begin=None, end=None, _configuration=None):  # noqa: E501
        """YearRange - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._begin = None
        self._end = None
        self.discriminator = None

        if begin is not None:
            self.begin = begin
        if end is not None:
            self.end = end

    @property
    def begin(self):
        """Gets the begin of this YearRange.  # noqa: E501


        :return: The begin of this YearRange.  # noqa: E501
        :rtype: int
        """
        return self._begin

    @begin.setter
    def begin(self, begin):
        """Sets the begin of this YearRange.


        :param begin: The begin of this YearRange.  # noqa: E501
        :type: int
        """

        self._begin = begin

    @property
    def end(self):
        """Gets the end of this YearRange.  # noqa: E501


        :return: The end of this YearRange.  # noqa: E501
        :rtype: int
        """
        return self._end

    @end.setter
    def end(self, end):
        """Sets the end of this YearRange.


        :param end: The end of this YearRange.  # noqa: E501
        :type: int
        """

        self._end = end

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
        if issubclass(YearRange, dict):
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
        if not isinstance(other, YearRange):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, YearRange):
            return True

        return self.to_dict() != other.to_dict()
