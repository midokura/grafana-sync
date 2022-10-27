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


class DataResponse(object):
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
        'error': 'str',
        'frames': 'Frames'
    }

    attribute_map = {
        'error': 'Error',
        'frames': 'Frames'
    }

    def __init__(self, error=None, frames=None, _configuration=None):  # noqa: E501
        """DataResponse - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._error = None
        self._frames = None
        self.discriminator = None

        if error is not None:
            self.error = error
        if frames is not None:
            self.frames = frames

    @property
    def error(self):
        """Gets the error of this DataResponse.  # noqa: E501

        Error is a property to be set if the the corresponding DataQuery has an error.  # noqa: E501

        :return: The error of this DataResponse.  # noqa: E501
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error):
        """Sets the error of this DataResponse.

        Error is a property to be set if the the corresponding DataQuery has an error.  # noqa: E501

        :param error: The error of this DataResponse.  # noqa: E501
        :type: str
        """

        self._error = error

    @property
    def frames(self):
        """Gets the frames of this DataResponse.  # noqa: E501


        :return: The frames of this DataResponse.  # noqa: E501
        :rtype: Frames
        """
        return self._frames

    @frames.setter
    def frames(self, frames):
        """Sets the frames of this DataResponse.


        :param frames: The frames of this DataResponse.  # noqa: E501
        :type: Frames
        """

        self._frames = frames

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
        if issubclass(DataResponse, dict):
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
        if not isinstance(other, DataResponse):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DataResponse):
            return True

        return self.to_dict() != other.to_dict()
