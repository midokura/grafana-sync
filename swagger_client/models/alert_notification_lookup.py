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


class AlertNotificationLookup(object):
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
        'is_default': 'bool',
        'name': 'str',
        'type': 'str',
        'uid': 'str'
    }

    attribute_map = {
        'id': 'id',
        'is_default': 'isDefault',
        'name': 'name',
        'type': 'type',
        'uid': 'uid'
    }

    def __init__(self, id=None, is_default=None, name=None, type=None, uid=None, _configuration=None):  # noqa: E501
        """AlertNotificationLookup - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._id = None
        self._is_default = None
        self._name = None
        self._type = None
        self._uid = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if is_default is not None:
            self.is_default = is_default
        if name is not None:
            self.name = name
        if type is not None:
            self.type = type
        if uid is not None:
            self.uid = uid

    @property
    def id(self):
        """Gets the id of this AlertNotificationLookup.  # noqa: E501


        :return: The id of this AlertNotificationLookup.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this AlertNotificationLookup.


        :param id: The id of this AlertNotificationLookup.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def is_default(self):
        """Gets the is_default of this AlertNotificationLookup.  # noqa: E501


        :return: The is_default of this AlertNotificationLookup.  # noqa: E501
        :rtype: bool
        """
        return self._is_default

    @is_default.setter
    def is_default(self, is_default):
        """Sets the is_default of this AlertNotificationLookup.


        :param is_default: The is_default of this AlertNotificationLookup.  # noqa: E501
        :type: bool
        """

        self._is_default = is_default

    @property
    def name(self):
        """Gets the name of this AlertNotificationLookup.  # noqa: E501


        :return: The name of this AlertNotificationLookup.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this AlertNotificationLookup.


        :param name: The name of this AlertNotificationLookup.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def type(self):
        """Gets the type of this AlertNotificationLookup.  # noqa: E501


        :return: The type of this AlertNotificationLookup.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this AlertNotificationLookup.


        :param type: The type of this AlertNotificationLookup.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def uid(self):
        """Gets the uid of this AlertNotificationLookup.  # noqa: E501


        :return: The uid of this AlertNotificationLookup.  # noqa: E501
        :rtype: str
        """
        return self._uid

    @uid.setter
    def uid(self, uid):
        """Sets the uid of this AlertNotificationLookup.


        :param uid: The uid of this AlertNotificationLookup.  # noqa: E501
        :type: str
        """

        self._uid = uid

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
        if issubclass(AlertNotificationLookup, dict):
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
        if not isinstance(other, AlertNotificationLookup):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AlertNotificationLookup):
            return True

        return self.to_dict() != other.to_dict()
