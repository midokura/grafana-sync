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


class DashboardSnapshotDTO(object):
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
        'expires': 'datetime',
        'external': 'bool',
        'external_url': 'str',
        'id': 'int',
        'key': 'str',
        'name': 'str',
        'org_id': 'int',
        'updated': 'datetime',
        'user_id': 'int'
    }

    attribute_map = {
        'created': 'created',
        'expires': 'expires',
        'external': 'external',
        'external_url': 'externalUrl',
        'id': 'id',
        'key': 'key',
        'name': 'name',
        'org_id': 'orgId',
        'updated': 'updated',
        'user_id': 'userId'
    }

    def __init__(self, created=None, expires=None, external=None, external_url=None, id=None, key=None, name=None, org_id=None, updated=None, user_id=None, _configuration=None):  # noqa: E501
        """DashboardSnapshotDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._created = None
        self._expires = None
        self._external = None
        self._external_url = None
        self._id = None
        self._key = None
        self._name = None
        self._org_id = None
        self._updated = None
        self._user_id = None
        self.discriminator = None

        if created is not None:
            self.created = created
        if expires is not None:
            self.expires = expires
        if external is not None:
            self.external = external
        if external_url is not None:
            self.external_url = external_url
        if id is not None:
            self.id = id
        if key is not None:
            self.key = key
        if name is not None:
            self.name = name
        if org_id is not None:
            self.org_id = org_id
        if updated is not None:
            self.updated = updated
        if user_id is not None:
            self.user_id = user_id

    @property
    def created(self):
        """Gets the created of this DashboardSnapshotDTO.  # noqa: E501


        :return: The created of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this DashboardSnapshotDTO.


        :param created: The created of this DashboardSnapshotDTO.  # noqa: E501
        :type: datetime
        """

        self._created = created

    @property
    def expires(self):
        """Gets the expires of this DashboardSnapshotDTO.  # noqa: E501


        :return: The expires of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._expires

    @expires.setter
    def expires(self, expires):
        """Sets the expires of this DashboardSnapshotDTO.


        :param expires: The expires of this DashboardSnapshotDTO.  # noqa: E501
        :type: datetime
        """

        self._expires = expires

    @property
    def external(self):
        """Gets the external of this DashboardSnapshotDTO.  # noqa: E501


        :return: The external of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: bool
        """
        return self._external

    @external.setter
    def external(self, external):
        """Sets the external of this DashboardSnapshotDTO.


        :param external: The external of this DashboardSnapshotDTO.  # noqa: E501
        :type: bool
        """

        self._external = external

    @property
    def external_url(self):
        """Gets the external_url of this DashboardSnapshotDTO.  # noqa: E501


        :return: The external_url of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: str
        """
        return self._external_url

    @external_url.setter
    def external_url(self, external_url):
        """Sets the external_url of this DashboardSnapshotDTO.


        :param external_url: The external_url of this DashboardSnapshotDTO.  # noqa: E501
        :type: str
        """

        self._external_url = external_url

    @property
    def id(self):
        """Gets the id of this DashboardSnapshotDTO.  # noqa: E501


        :return: The id of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this DashboardSnapshotDTO.


        :param id: The id of this DashboardSnapshotDTO.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def key(self):
        """Gets the key of this DashboardSnapshotDTO.  # noqa: E501


        :return: The key of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: str
        """
        return self._key

    @key.setter
    def key(self, key):
        """Sets the key of this DashboardSnapshotDTO.


        :param key: The key of this DashboardSnapshotDTO.  # noqa: E501
        :type: str
        """

        self._key = key

    @property
    def name(self):
        """Gets the name of this DashboardSnapshotDTO.  # noqa: E501


        :return: The name of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this DashboardSnapshotDTO.


        :param name: The name of this DashboardSnapshotDTO.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def org_id(self):
        """Gets the org_id of this DashboardSnapshotDTO.  # noqa: E501


        :return: The org_id of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: int
        """
        return self._org_id

    @org_id.setter
    def org_id(self, org_id):
        """Sets the org_id of this DashboardSnapshotDTO.


        :param org_id: The org_id of this DashboardSnapshotDTO.  # noqa: E501
        :type: int
        """

        self._org_id = org_id

    @property
    def updated(self):
        """Gets the updated of this DashboardSnapshotDTO.  # noqa: E501


        :return: The updated of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this DashboardSnapshotDTO.


        :param updated: The updated of this DashboardSnapshotDTO.  # noqa: E501
        :type: datetime
        """

        self._updated = updated

    @property
    def user_id(self):
        """Gets the user_id of this DashboardSnapshotDTO.  # noqa: E501


        :return: The user_id of this DashboardSnapshotDTO.  # noqa: E501
        :rtype: int
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """Sets the user_id of this DashboardSnapshotDTO.


        :param user_id: The user_id of this DashboardSnapshotDTO.  # noqa: E501
        :type: int
        """

        self._user_id = user_id

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
        if issubclass(DashboardSnapshotDTO, dict):
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
        if not isinstance(other, DashboardSnapshotDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DashboardSnapshotDTO):
            return True

        return self.to_dict() != other.to_dict()
