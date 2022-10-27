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


class PatchAnnotationsCmd(object):
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
        'id': 'int',
        'tags': 'list[str]',
        'text': 'str',
        'time': 'int',
        'time_end': 'int'
    }

    attribute_map = {
        'id': 'id',
        'tags': 'tags',
        'text': 'text',
        'time': 'time',
        'time_end': 'timeEnd'
    }

    def __init__(self, id=None, tags=None, text=None, time=None, time_end=None, _configuration=None):  # noqa: E501
        """PatchAnnotationsCmd - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._id = None
        self._tags = None
        self._text = None
        self._time = None
        self._time_end = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if tags is not None:
            self.tags = tags
        if text is not None:
            self.text = text
        if time is not None:
            self.time = time
        if time_end is not None:
            self.time_end = time_end

    @property
    def id(self):
        """Gets the id of this PatchAnnotationsCmd.  # noqa: E501


        :return: The id of this PatchAnnotationsCmd.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this PatchAnnotationsCmd.


        :param id: The id of this PatchAnnotationsCmd.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def tags(self):
        """Gets the tags of this PatchAnnotationsCmd.  # noqa: E501


        :return: The tags of this PatchAnnotationsCmd.  # noqa: E501
        :rtype: list[str]
        """
        return self._tags

    @tags.setter
    def tags(self, tags):
        """Sets the tags of this PatchAnnotationsCmd.


        :param tags: The tags of this PatchAnnotationsCmd.  # noqa: E501
        :type: list[str]
        """

        self._tags = tags

    @property
    def text(self):
        """Gets the text of this PatchAnnotationsCmd.  # noqa: E501


        :return: The text of this PatchAnnotationsCmd.  # noqa: E501
        :rtype: str
        """
        return self._text

    @text.setter
    def text(self, text):
        """Sets the text of this PatchAnnotationsCmd.


        :param text: The text of this PatchAnnotationsCmd.  # noqa: E501
        :type: str
        """

        self._text = text

    @property
    def time(self):
        """Gets the time of this PatchAnnotationsCmd.  # noqa: E501


        :return: The time of this PatchAnnotationsCmd.  # noqa: E501
        :rtype: int
        """
        return self._time

    @time.setter
    def time(self, time):
        """Sets the time of this PatchAnnotationsCmd.


        :param time: The time of this PatchAnnotationsCmd.  # noqa: E501
        :type: int
        """

        self._time = time

    @property
    def time_end(self):
        """Gets the time_end of this PatchAnnotationsCmd.  # noqa: E501


        :return: The time_end of this PatchAnnotationsCmd.  # noqa: E501
        :rtype: int
        """
        return self._time_end

    @time_end.setter
    def time_end(self, time_end):
        """Sets the time_end of this PatchAnnotationsCmd.


        :param time_end: The time_end of this PatchAnnotationsCmd.  # noqa: E501
        :type: int
        """

        self._time_end = time_end

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
        if issubclass(PatchAnnotationsCmd, dict):
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
        if not isinstance(other, PatchAnnotationsCmd):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, PatchAnnotationsCmd):
            return True

        return self.to_dict() != other.to_dict()
