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


class RoleDTO(object):
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
        'created': 'datetime',
        'delegatable': 'bool',
        'description': 'str',
        'display_name': 'str',
        'group': 'str',
        'hidden': 'bool',
        'name': 'str',
        'permissions': 'list[Permission]',
        'uid': 'str',
        'updated': 'datetime',
        'version': 'int'
    }

    attribute_map = {
        'created': 'created',
        'delegatable': 'delegatable',
        'description': 'description',
        'display_name': 'displayName',
        'group': 'group',
        'hidden': 'hidden',
        'name': 'name',
        'permissions': 'permissions',
        'uid': 'uid',
        'updated': 'updated',
        'version': 'version'
    }

    def __init__(self, created=None, delegatable=None, description=None, display_name=None, group=None, hidden=None, name=None, permissions=None, uid=None, updated=None, version=None, _configuration=None):  # noqa: E501
        """RoleDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._created = None
        self._delegatable = None
        self._description = None
        self._display_name = None
        self._group = None
        self._hidden = None
        self._name = None
        self._permissions = None
        self._uid = None
        self._updated = None
        self._version = None
        self.discriminator = None

        if created is not None:
            self.created = created
        if delegatable is not None:
            self.delegatable = delegatable
        if description is not None:
            self.description = description
        if display_name is not None:
            self.display_name = display_name
        if group is not None:
            self.group = group
        if hidden is not None:
            self.hidden = hidden
        if name is not None:
            self.name = name
        if permissions is not None:
            self.permissions = permissions
        if uid is not None:
            self.uid = uid
        if updated is not None:
            self.updated = updated
        if version is not None:
            self.version = version

    @property
    def created(self):
        """Gets the created of this RoleDTO.  # noqa: E501


        :return: The created of this RoleDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this RoleDTO.


        :param created: The created of this RoleDTO.  # noqa: E501
        :type: datetime
        """

        self._created = created

    @property
    def delegatable(self):
        """Gets the delegatable of this RoleDTO.  # noqa: E501


        :return: The delegatable of this RoleDTO.  # noqa: E501
        :rtype: bool
        """
        return self._delegatable

    @delegatable.setter
    def delegatable(self, delegatable):
        """Sets the delegatable of this RoleDTO.


        :param delegatable: The delegatable of this RoleDTO.  # noqa: E501
        :type: bool
        """

        self._delegatable = delegatable

    @property
    def description(self):
        """Gets the description of this RoleDTO.  # noqa: E501


        :return: The description of this RoleDTO.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this RoleDTO.


        :param description: The description of this RoleDTO.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def display_name(self):
        """Gets the display_name of this RoleDTO.  # noqa: E501


        :return: The display_name of this RoleDTO.  # noqa: E501
        :rtype: str
        """
        return self._display_name

    @display_name.setter
    def display_name(self, display_name):
        """Sets the display_name of this RoleDTO.


        :param display_name: The display_name of this RoleDTO.  # noqa: E501
        :type: str
        """

        self._display_name = display_name

    @property
    def group(self):
        """Gets the group of this RoleDTO.  # noqa: E501


        :return: The group of this RoleDTO.  # noqa: E501
        :rtype: str
        """
        return self._group

    @group.setter
    def group(self, group):
        """Sets the group of this RoleDTO.


        :param group: The group of this RoleDTO.  # noqa: E501
        :type: str
        """

        self._group = group

    @property
    def hidden(self):
        """Gets the hidden of this RoleDTO.  # noqa: E501


        :return: The hidden of this RoleDTO.  # noqa: E501
        :rtype: bool
        """
        return self._hidden

    @hidden.setter
    def hidden(self, hidden):
        """Sets the hidden of this RoleDTO.


        :param hidden: The hidden of this RoleDTO.  # noqa: E501
        :type: bool
        """

        self._hidden = hidden

    @property
    def name(self):
        """Gets the name of this RoleDTO.  # noqa: E501


        :return: The name of this RoleDTO.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this RoleDTO.


        :param name: The name of this RoleDTO.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def permissions(self):
        """Gets the permissions of this RoleDTO.  # noqa: E501


        :return: The permissions of this RoleDTO.  # noqa: E501
        :rtype: list[Permission]
        """
        return self._permissions

    @permissions.setter
    def permissions(self, permissions):
        """Sets the permissions of this RoleDTO.


        :param permissions: The permissions of this RoleDTO.  # noqa: E501
        :type: list[Permission]
        """

        self._permissions = permissions

    @property
    def uid(self):
        """Gets the uid of this RoleDTO.  # noqa: E501


        :return: The uid of this RoleDTO.  # noqa: E501
        :rtype: str
        """
        return self._uid

    @uid.setter
    def uid(self, uid):
        """Sets the uid of this RoleDTO.


        :param uid: The uid of this RoleDTO.  # noqa: E501
        :type: str
        """

        self._uid = uid

    @property
    def updated(self):
        """Gets the updated of this RoleDTO.  # noqa: E501


        :return: The updated of this RoleDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this RoleDTO.


        :param updated: The updated of this RoleDTO.  # noqa: E501
        :type: datetime
        """

        self._updated = updated

    @property
    def version(self):
        """Gets the version of this RoleDTO.  # noqa: E501


        :return: The version of this RoleDTO.  # noqa: E501
        :rtype: int
        """
        return self._version

    @version.setter
    def version(self, version):
        """Sets the version of this RoleDTO.


        :param version: The version of this RoleDTO.  # noqa: E501
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
        if issubclass(RoleDTO, dict):
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
        if not isinstance(other, RoleDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, RoleDTO):
            return True

        return self.to_dict() != other.to_dict()
