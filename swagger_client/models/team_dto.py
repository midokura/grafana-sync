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


class TeamDTO(object):
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
        'access_control': 'dict(str, bool)',
        'avatar_url': 'str',
        'email': 'str',
        'id': 'int',
        'member_count': 'int',
        'name': 'str',
        'org_id': 'int',
        'permission': 'PermissionType'
    }

    attribute_map = {
        'access_control': 'accessControl',
        'avatar_url': 'avatarUrl',
        'email': 'email',
        'id': 'id',
        'member_count': 'memberCount',
        'name': 'name',
        'org_id': 'orgId',
        'permission': 'permission'
    }

    def __init__(self, access_control=None, avatar_url=None, email=None, id=None, member_count=None, name=None, org_id=None, permission=None, _configuration=None):  # noqa: E501
        """TeamDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._access_control = None
        self._avatar_url = None
        self._email = None
        self._id = None
        self._member_count = None
        self._name = None
        self._org_id = None
        self._permission = None
        self.discriminator = None

        if access_control is not None:
            self.access_control = access_control
        if avatar_url is not None:
            self.avatar_url = avatar_url
        if email is not None:
            self.email = email
        if id is not None:
            self.id = id
        if member_count is not None:
            self.member_count = member_count
        if name is not None:
            self.name = name
        if org_id is not None:
            self.org_id = org_id
        if permission is not None:
            self.permission = permission

    @property
    def access_control(self):
        """Gets the access_control of this TeamDTO.  # noqa: E501


        :return: The access_control of this TeamDTO.  # noqa: E501
        :rtype: dict(str, bool)
        """
        return self._access_control

    @access_control.setter
    def access_control(self, access_control):
        """Sets the access_control of this TeamDTO.


        :param access_control: The access_control of this TeamDTO.  # noqa: E501
        :type: dict(str, bool)
        """

        self._access_control = access_control

    @property
    def avatar_url(self):
        """Gets the avatar_url of this TeamDTO.  # noqa: E501


        :return: The avatar_url of this TeamDTO.  # noqa: E501
        :rtype: str
        """
        return self._avatar_url

    @avatar_url.setter
    def avatar_url(self, avatar_url):
        """Sets the avatar_url of this TeamDTO.


        :param avatar_url: The avatar_url of this TeamDTO.  # noqa: E501
        :type: str
        """

        self._avatar_url = avatar_url

    @property
    def email(self):
        """Gets the email of this TeamDTO.  # noqa: E501


        :return: The email of this TeamDTO.  # noqa: E501
        :rtype: str
        """
        return self._email

    @email.setter
    def email(self, email):
        """Sets the email of this TeamDTO.


        :param email: The email of this TeamDTO.  # noqa: E501
        :type: str
        """

        self._email = email

    @property
    def id(self):
        """Gets the id of this TeamDTO.  # noqa: E501


        :return: The id of this TeamDTO.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this TeamDTO.


        :param id: The id of this TeamDTO.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def member_count(self):
        """Gets the member_count of this TeamDTO.  # noqa: E501


        :return: The member_count of this TeamDTO.  # noqa: E501
        :rtype: int
        """
        return self._member_count

    @member_count.setter
    def member_count(self, member_count):
        """Sets the member_count of this TeamDTO.


        :param member_count: The member_count of this TeamDTO.  # noqa: E501
        :type: int
        """

        self._member_count = member_count

    @property
    def name(self):
        """Gets the name of this TeamDTO.  # noqa: E501


        :return: The name of this TeamDTO.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this TeamDTO.


        :param name: The name of this TeamDTO.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def org_id(self):
        """Gets the org_id of this TeamDTO.  # noqa: E501


        :return: The org_id of this TeamDTO.  # noqa: E501
        :rtype: int
        """
        return self._org_id

    @org_id.setter
    def org_id(self, org_id):
        """Sets the org_id of this TeamDTO.


        :param org_id: The org_id of this TeamDTO.  # noqa: E501
        :type: int
        """

        self._org_id = org_id

    @property
    def permission(self):
        """Gets the permission of this TeamDTO.  # noqa: E501


        :return: The permission of this TeamDTO.  # noqa: E501
        :rtype: PermissionType
        """
        return self._permission

    @permission.setter
    def permission(self, permission):
        """Sets the permission of this TeamDTO.


        :param permission: The permission of this TeamDTO.  # noqa: E501
        :type: PermissionType
        """

        self._permission = permission

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
        if issubclass(TeamDTO, dict):
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
        if not isinstance(other, TeamDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TeamDTO):
            return True

        return self.to_dict() != other.to_dict()
