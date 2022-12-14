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


class DashboardMeta(object):
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
        'annotations_permissions': 'AnnotationPermission',
        'can_admin': 'bool',
        'can_delete': 'bool',
        'can_edit': 'bool',
        'can_save': 'bool',
        'can_star': 'bool',
        'created': 'datetime',
        'created_by': 'str',
        'expires': 'datetime',
        'folder_id': 'int',
        'folder_title': 'str',
        'folder_uid': 'str',
        'folder_url': 'str',
        'has_acl': 'bool',
        'is_folder': 'bool',
        'is_home': 'bool',
        'is_snapshot': 'bool',
        'is_starred': 'bool',
        'provisioned': 'bool',
        'provisioned_external_id': 'str',
        'public_dashboard_access_token': 'str',
        'public_dashboard_enabled': 'bool',
        'slug': 'str',
        'type': 'str',
        'updated': 'datetime',
        'updated_by': 'str',
        'url': 'str',
        'version': 'int'
    }

    attribute_map = {
        'annotations_permissions': 'annotationsPermissions',
        'can_admin': 'canAdmin',
        'can_delete': 'canDelete',
        'can_edit': 'canEdit',
        'can_save': 'canSave',
        'can_star': 'canStar',
        'created': 'created',
        'created_by': 'createdBy',
        'expires': 'expires',
        'folder_id': 'folderId',
        'folder_title': 'folderTitle',
        'folder_uid': 'folderUid',
        'folder_url': 'folderUrl',
        'has_acl': 'hasAcl',
        'is_folder': 'isFolder',
        'is_home': 'isHome',
        'is_snapshot': 'isSnapshot',
        'is_starred': 'isStarred',
        'provisioned': 'provisioned',
        'provisioned_external_id': 'provisionedExternalId',
        'public_dashboard_access_token': 'publicDashboardAccessToken',
        'public_dashboard_enabled': 'publicDashboardEnabled',
        'slug': 'slug',
        'type': 'type',
        'updated': 'updated',
        'updated_by': 'updatedBy',
        'url': 'url',
        'version': 'version'
    }

    def __init__(self, annotations_permissions=None, can_admin=None, can_delete=None, can_edit=None, can_save=None, can_star=None, created=None, created_by=None, expires=None, folder_id=None, folder_title=None, folder_uid=None, folder_url=None, has_acl=None, is_folder=None, is_home=None, is_snapshot=None, is_starred=None, provisioned=None, provisioned_external_id=None, public_dashboard_access_token=None, public_dashboard_enabled=None, slug=None, type=None, updated=None, updated_by=None, url=None, version=None, _configuration=None):  # noqa: E501
        """DashboardMeta - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._annotations_permissions = None
        self._can_admin = None
        self._can_delete = None
        self._can_edit = None
        self._can_save = None
        self._can_star = None
        self._created = None
        self._created_by = None
        self._expires = None
        self._folder_id = None
        self._folder_title = None
        self._folder_uid = None
        self._folder_url = None
        self._has_acl = None
        self._is_folder = None
        self._is_home = None
        self._is_snapshot = None
        self._is_starred = None
        self._provisioned = None
        self._provisioned_external_id = None
        self._public_dashboard_access_token = None
        self._public_dashboard_enabled = None
        self._slug = None
        self._type = None
        self._updated = None
        self._updated_by = None
        self._url = None
        self._version = None
        self.discriminator = None

        if annotations_permissions is not None:
            self.annotations_permissions = annotations_permissions
        if can_admin is not None:
            self.can_admin = can_admin
        if can_delete is not None:
            self.can_delete = can_delete
        if can_edit is not None:
            self.can_edit = can_edit
        if can_save is not None:
            self.can_save = can_save
        if can_star is not None:
            self.can_star = can_star
        if created is not None:
            self.created = created
        if created_by is not None:
            self.created_by = created_by
        if expires is not None:
            self.expires = expires
        if folder_id is not None:
            self.folder_id = folder_id
        if folder_title is not None:
            self.folder_title = folder_title
        if folder_uid is not None:
            self.folder_uid = folder_uid
        if folder_url is not None:
            self.folder_url = folder_url
        if has_acl is not None:
            self.has_acl = has_acl
        if is_folder is not None:
            self.is_folder = is_folder
        if is_home is not None:
            self.is_home = is_home
        if is_snapshot is not None:
            self.is_snapshot = is_snapshot
        if is_starred is not None:
            self.is_starred = is_starred
        if provisioned is not None:
            self.provisioned = provisioned
        if provisioned_external_id is not None:
            self.provisioned_external_id = provisioned_external_id
        if public_dashboard_access_token is not None:
            self.public_dashboard_access_token = public_dashboard_access_token
        if public_dashboard_enabled is not None:
            self.public_dashboard_enabled = public_dashboard_enabled
        if slug is not None:
            self.slug = slug
        if type is not None:
            self.type = type
        if updated is not None:
            self.updated = updated
        if updated_by is not None:
            self.updated_by = updated_by
        if url is not None:
            self.url = url
        if version is not None:
            self.version = version

    @property
    def annotations_permissions(self):
        """Gets the annotations_permissions of this DashboardMeta.  # noqa: E501


        :return: The annotations_permissions of this DashboardMeta.  # noqa: E501
        :rtype: AnnotationPermission
        """
        return self._annotations_permissions

    @annotations_permissions.setter
    def annotations_permissions(self, annotations_permissions):
        """Sets the annotations_permissions of this DashboardMeta.


        :param annotations_permissions: The annotations_permissions of this DashboardMeta.  # noqa: E501
        :type: AnnotationPermission
        """

        self._annotations_permissions = annotations_permissions

    @property
    def can_admin(self):
        """Gets the can_admin of this DashboardMeta.  # noqa: E501


        :return: The can_admin of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._can_admin

    @can_admin.setter
    def can_admin(self, can_admin):
        """Sets the can_admin of this DashboardMeta.


        :param can_admin: The can_admin of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._can_admin = can_admin

    @property
    def can_delete(self):
        """Gets the can_delete of this DashboardMeta.  # noqa: E501


        :return: The can_delete of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete

    @can_delete.setter
    def can_delete(self, can_delete):
        """Sets the can_delete of this DashboardMeta.


        :param can_delete: The can_delete of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._can_delete = can_delete

    @property
    def can_edit(self):
        """Gets the can_edit of this DashboardMeta.  # noqa: E501


        :return: The can_edit of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._can_edit

    @can_edit.setter
    def can_edit(self, can_edit):
        """Sets the can_edit of this DashboardMeta.


        :param can_edit: The can_edit of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._can_edit = can_edit

    @property
    def can_save(self):
        """Gets the can_save of this DashboardMeta.  # noqa: E501


        :return: The can_save of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._can_save

    @can_save.setter
    def can_save(self, can_save):
        """Sets the can_save of this DashboardMeta.


        :param can_save: The can_save of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._can_save = can_save

    @property
    def can_star(self):
        """Gets the can_star of this DashboardMeta.  # noqa: E501


        :return: The can_star of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._can_star

    @can_star.setter
    def can_star(self, can_star):
        """Sets the can_star of this DashboardMeta.


        :param can_star: The can_star of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._can_star = can_star

    @property
    def created(self):
        """Gets the created of this DashboardMeta.  # noqa: E501


        :return: The created of this DashboardMeta.  # noqa: E501
        :rtype: datetime
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this DashboardMeta.


        :param created: The created of this DashboardMeta.  # noqa: E501
        :type: datetime
        """

        self._created = created

    @property
    def created_by(self):
        """Gets the created_by of this DashboardMeta.  # noqa: E501


        :return: The created_by of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._created_by

    @created_by.setter
    def created_by(self, created_by):
        """Sets the created_by of this DashboardMeta.


        :param created_by: The created_by of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._created_by = created_by

    @property
    def expires(self):
        """Gets the expires of this DashboardMeta.  # noqa: E501


        :return: The expires of this DashboardMeta.  # noqa: E501
        :rtype: datetime
        """
        return self._expires

    @expires.setter
    def expires(self, expires):
        """Sets the expires of this DashboardMeta.


        :param expires: The expires of this DashboardMeta.  # noqa: E501
        :type: datetime
        """

        self._expires = expires

    @property
    def folder_id(self):
        """Gets the folder_id of this DashboardMeta.  # noqa: E501


        :return: The folder_id of this DashboardMeta.  # noqa: E501
        :rtype: int
        """
        return self._folder_id

    @folder_id.setter
    def folder_id(self, folder_id):
        """Sets the folder_id of this DashboardMeta.


        :param folder_id: The folder_id of this DashboardMeta.  # noqa: E501
        :type: int
        """

        self._folder_id = folder_id

    @property
    def folder_title(self):
        """Gets the folder_title of this DashboardMeta.  # noqa: E501


        :return: The folder_title of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._folder_title

    @folder_title.setter
    def folder_title(self, folder_title):
        """Sets the folder_title of this DashboardMeta.


        :param folder_title: The folder_title of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._folder_title = folder_title

    @property
    def folder_uid(self):
        """Gets the folder_uid of this DashboardMeta.  # noqa: E501


        :return: The folder_uid of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._folder_uid

    @folder_uid.setter
    def folder_uid(self, folder_uid):
        """Sets the folder_uid of this DashboardMeta.


        :param folder_uid: The folder_uid of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._folder_uid = folder_uid

    @property
    def folder_url(self):
        """Gets the folder_url of this DashboardMeta.  # noqa: E501


        :return: The folder_url of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._folder_url

    @folder_url.setter
    def folder_url(self, folder_url):
        """Sets the folder_url of this DashboardMeta.


        :param folder_url: The folder_url of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._folder_url = folder_url

    @property
    def has_acl(self):
        """Gets the has_acl of this DashboardMeta.  # noqa: E501


        :return: The has_acl of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._has_acl

    @has_acl.setter
    def has_acl(self, has_acl):
        """Sets the has_acl of this DashboardMeta.


        :param has_acl: The has_acl of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._has_acl = has_acl

    @property
    def is_folder(self):
        """Gets the is_folder of this DashboardMeta.  # noqa: E501


        :return: The is_folder of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._is_folder

    @is_folder.setter
    def is_folder(self, is_folder):
        """Sets the is_folder of this DashboardMeta.


        :param is_folder: The is_folder of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._is_folder = is_folder

    @property
    def is_home(self):
        """Gets the is_home of this DashboardMeta.  # noqa: E501


        :return: The is_home of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._is_home

    @is_home.setter
    def is_home(self, is_home):
        """Sets the is_home of this DashboardMeta.


        :param is_home: The is_home of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._is_home = is_home

    @property
    def is_snapshot(self):
        """Gets the is_snapshot of this DashboardMeta.  # noqa: E501


        :return: The is_snapshot of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._is_snapshot

    @is_snapshot.setter
    def is_snapshot(self, is_snapshot):
        """Sets the is_snapshot of this DashboardMeta.


        :param is_snapshot: The is_snapshot of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._is_snapshot = is_snapshot

    @property
    def is_starred(self):
        """Gets the is_starred of this DashboardMeta.  # noqa: E501


        :return: The is_starred of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._is_starred

    @is_starred.setter
    def is_starred(self, is_starred):
        """Sets the is_starred of this DashboardMeta.


        :param is_starred: The is_starred of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._is_starred = is_starred

    @property
    def provisioned(self):
        """Gets the provisioned of this DashboardMeta.  # noqa: E501


        :return: The provisioned of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._provisioned

    @provisioned.setter
    def provisioned(self, provisioned):
        """Sets the provisioned of this DashboardMeta.


        :param provisioned: The provisioned of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._provisioned = provisioned

    @property
    def provisioned_external_id(self):
        """Gets the provisioned_external_id of this DashboardMeta.  # noqa: E501


        :return: The provisioned_external_id of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._provisioned_external_id

    @provisioned_external_id.setter
    def provisioned_external_id(self, provisioned_external_id):
        """Sets the provisioned_external_id of this DashboardMeta.


        :param provisioned_external_id: The provisioned_external_id of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._provisioned_external_id = provisioned_external_id

    @property
    def public_dashboard_access_token(self):
        """Gets the public_dashboard_access_token of this DashboardMeta.  # noqa: E501


        :return: The public_dashboard_access_token of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._public_dashboard_access_token

    @public_dashboard_access_token.setter
    def public_dashboard_access_token(self, public_dashboard_access_token):
        """Sets the public_dashboard_access_token of this DashboardMeta.


        :param public_dashboard_access_token: The public_dashboard_access_token of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._public_dashboard_access_token = public_dashboard_access_token

    @property
    def public_dashboard_enabled(self):
        """Gets the public_dashboard_enabled of this DashboardMeta.  # noqa: E501


        :return: The public_dashboard_enabled of this DashboardMeta.  # noqa: E501
        :rtype: bool
        """
        return self._public_dashboard_enabled

    @public_dashboard_enabled.setter
    def public_dashboard_enabled(self, public_dashboard_enabled):
        """Sets the public_dashboard_enabled of this DashboardMeta.


        :param public_dashboard_enabled: The public_dashboard_enabled of this DashboardMeta.  # noqa: E501
        :type: bool
        """

        self._public_dashboard_enabled = public_dashboard_enabled

    @property
    def slug(self):
        """Gets the slug of this DashboardMeta.  # noqa: E501


        :return: The slug of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._slug

    @slug.setter
    def slug(self, slug):
        """Sets the slug of this DashboardMeta.


        :param slug: The slug of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._slug = slug

    @property
    def type(self):
        """Gets the type of this DashboardMeta.  # noqa: E501


        :return: The type of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this DashboardMeta.


        :param type: The type of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def updated(self):
        """Gets the updated of this DashboardMeta.  # noqa: E501


        :return: The updated of this DashboardMeta.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this DashboardMeta.


        :param updated: The updated of this DashboardMeta.  # noqa: E501
        :type: datetime
        """

        self._updated = updated

    @property
    def updated_by(self):
        """Gets the updated_by of this DashboardMeta.  # noqa: E501


        :return: The updated_by of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._updated_by

    @updated_by.setter
    def updated_by(self, updated_by):
        """Sets the updated_by of this DashboardMeta.


        :param updated_by: The updated_by of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._updated_by = updated_by

    @property
    def url(self):
        """Gets the url of this DashboardMeta.  # noqa: E501


        :return: The url of this DashboardMeta.  # noqa: E501
        :rtype: str
        """
        return self._url

    @url.setter
    def url(self, url):
        """Sets the url of this DashboardMeta.


        :param url: The url of this DashboardMeta.  # noqa: E501
        :type: str
        """

        self._url = url

    @property
    def version(self):
        """Gets the version of this DashboardMeta.  # noqa: E501


        :return: The version of this DashboardMeta.  # noqa: E501
        :rtype: int
        """
        return self._version

    @version.setter
    def version(self, version):
        """Sets the version of this DashboardMeta.


        :param version: The version of this DashboardMeta.  # noqa: E501
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
        if issubclass(DashboardMeta, dict):
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
        if not isinstance(other, DashboardMeta):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DashboardMeta):
            return True

        return self.to_dict() != other.to_dict()
