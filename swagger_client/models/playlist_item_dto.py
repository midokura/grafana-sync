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


class PlaylistItemDTO(object):
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
        'order': 'int',
        'playlistid': 'int',
        'title': 'str',
        'type': 'str',
        'value': 'str'
    }

    attribute_map = {
        'id': 'id',
        'order': 'order',
        'playlistid': 'playlistid',
        'title': 'title',
        'type': 'type',
        'value': 'value'
    }

    def __init__(self, id=None, order=None, playlistid=None, title=None, type=None, value=None, _configuration=None):  # noqa: E501
        """PlaylistItemDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._id = None
        self._order = None
        self._playlistid = None
        self._title = None
        self._type = None
        self._value = None
        self.discriminator = None

        if id is not None:
            self.id = id
        if order is not None:
            self.order = order
        if playlistid is not None:
            self.playlistid = playlistid
        if title is not None:
            self.title = title
        if type is not None:
            self.type = type
        if value is not None:
            self.value = value

    @property
    def id(self):
        """Gets the id of this PlaylistItemDTO.  # noqa: E501


        :return: The id of this PlaylistItemDTO.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this PlaylistItemDTO.


        :param id: The id of this PlaylistItemDTO.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def order(self):
        """Gets the order of this PlaylistItemDTO.  # noqa: E501


        :return: The order of this PlaylistItemDTO.  # noqa: E501
        :rtype: int
        """
        return self._order

    @order.setter
    def order(self, order):
        """Sets the order of this PlaylistItemDTO.


        :param order: The order of this PlaylistItemDTO.  # noqa: E501
        :type: int
        """

        self._order = order

    @property
    def playlistid(self):
        """Gets the playlistid of this PlaylistItemDTO.  # noqa: E501


        :return: The playlistid of this PlaylistItemDTO.  # noqa: E501
        :rtype: int
        """
        return self._playlistid

    @playlistid.setter
    def playlistid(self, playlistid):
        """Sets the playlistid of this PlaylistItemDTO.


        :param playlistid: The playlistid of this PlaylistItemDTO.  # noqa: E501
        :type: int
        """

        self._playlistid = playlistid

    @property
    def title(self):
        """Gets the title of this PlaylistItemDTO.  # noqa: E501


        :return: The title of this PlaylistItemDTO.  # noqa: E501
        :rtype: str
        """
        return self._title

    @title.setter
    def title(self, title):
        """Sets the title of this PlaylistItemDTO.


        :param title: The title of this PlaylistItemDTO.  # noqa: E501
        :type: str
        """

        self._title = title

    @property
    def type(self):
        """Gets the type of this PlaylistItemDTO.  # noqa: E501


        :return: The type of this PlaylistItemDTO.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this PlaylistItemDTO.


        :param type: The type of this PlaylistItemDTO.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def value(self):
        """Gets the value of this PlaylistItemDTO.  # noqa: E501


        :return: The value of this PlaylistItemDTO.  # noqa: E501
        :rtype: str
        """
        return self._value

    @value.setter
    def value(self, value):
        """Sets the value of this PlaylistItemDTO.


        :param value: The value of this PlaylistItemDTO.  # noqa: E501
        :type: str
        """

        self._value = value

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
        if issubclass(PlaylistItemDTO, dict):
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
        if not isinstance(other, PlaylistItemDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, PlaylistItemDTO):
            return True

        return self.to_dict() != other.to_dict()
