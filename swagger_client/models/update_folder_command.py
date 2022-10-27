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


class UpdateFolderCommand(object):
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
        'overwrite': 'bool',
        'title': 'str',
        'uid': 'str',
        'version': 'int'
    }

    attribute_map = {
        'overwrite': 'overwrite',
        'title': 'title',
        'uid': 'uid',
        'version': 'version'
    }

    def __init__(self, overwrite=None, title=None, uid=None, version=None, _configuration=None):  # noqa: E501
        """UpdateFolderCommand - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._overwrite = None
        self._title = None
        self._uid = None
        self._version = None
        self.discriminator = None

        if overwrite is not None:
            self.overwrite = overwrite
        if title is not None:
            self.title = title
        if uid is not None:
            self.uid = uid
        if version is not None:
            self.version = version

    @property
    def overwrite(self):
        """Gets the overwrite of this UpdateFolderCommand.  # noqa: E501


        :return: The overwrite of this UpdateFolderCommand.  # noqa: E501
        :rtype: bool
        """
        return self._overwrite

    @overwrite.setter
    def overwrite(self, overwrite):
        """Sets the overwrite of this UpdateFolderCommand.


        :param overwrite: The overwrite of this UpdateFolderCommand.  # noqa: E501
        :type: bool
        """

        self._overwrite = overwrite

    @property
    def title(self):
        """Gets the title of this UpdateFolderCommand.  # noqa: E501


        :return: The title of this UpdateFolderCommand.  # noqa: E501
        :rtype: str
        """
        return self._title

    @title.setter
    def title(self, title):
        """Sets the title of this UpdateFolderCommand.


        :param title: The title of this UpdateFolderCommand.  # noqa: E501
        :type: str
        """

        self._title = title

    @property
    def uid(self):
        """Gets the uid of this UpdateFolderCommand.  # noqa: E501


        :return: The uid of this UpdateFolderCommand.  # noqa: E501
        :rtype: str
        """
        return self._uid

    @uid.setter
    def uid(self, uid):
        """Sets the uid of this UpdateFolderCommand.


        :param uid: The uid of this UpdateFolderCommand.  # noqa: E501
        :type: str
        """

        self._uid = uid

    @property
    def version(self):
        """Gets the version of this UpdateFolderCommand.  # noqa: E501


        :return: The version of this UpdateFolderCommand.  # noqa: E501
        :rtype: int
        """
        return self._version

    @version.setter
    def version(self, version):
        """Sets the version of this UpdateFolderCommand.


        :param version: The version of this UpdateFolderCommand.  # noqa: E501
        :type: int
        """

        self._version = version

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
        if issubclass(UpdateFolderCommand, dict):
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
        if not isinstance(other, UpdateFolderCommand):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, UpdateFolderCommand):
            return True

        return self.to_dict() != other.to_dict()
