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


class DataSource(object):
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
        'access': 'DsAccess',
        'access_control': 'Metadata',
        'basic_auth': 'bool',
        'basic_auth_user': 'str',
        'database': 'str',
        'id': 'int',
        'is_default': 'bool',
        'json_data': 'Json',
        'name': 'str',
        'org_id': 'int',
        'read_only': 'bool',
        'secure_json_fields': 'dict(str, bool)',
        'type': 'str',
        'type_logo_url': 'str',
        'uid': 'str',
        'url': 'str',
        'user': 'str',
        'version': 'int',
        'with_credentials': 'bool'
    }

    attribute_map = {
        'access': 'access',
        'access_control': 'accessControl',
        'basic_auth': 'basicAuth',
        'basic_auth_user': 'basicAuthUser',
        'database': 'database',
        'id': 'id',
        'is_default': 'isDefault',
        'json_data': 'jsonData',
        'name': 'name',
        'org_id': 'orgId',
        'read_only': 'readOnly',
        'secure_json_fields': 'secureJsonFields',
        'type': 'type',
        'type_logo_url': 'typeLogoUrl',
        'uid': 'uid',
        'url': 'url',
        'user': 'user',
        'version': 'version',
        'with_credentials': 'withCredentials'
    }

    def __init__(self, access=None, access_control=None, basic_auth=None, basic_auth_user=None, database=None, id=None, is_default=None, json_data=None, name=None, org_id=None, read_only=None, secure_json_fields=None, type=None, type_logo_url=None, uid=None, url=None, user=None, version=None, with_credentials=None, _configuration=None):  # noqa: E501
        """DataSource - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._access = None
        self._access_control = None
        self._basic_auth = None
        self._basic_auth_user = None
        self._database = None
        self._id = None
        self._is_default = None
        self._json_data = None
        self._name = None
        self._org_id = None
        self._read_only = None
        self._secure_json_fields = None
        self._type = None
        self._type_logo_url = None
        self._uid = None
        self._url = None
        self._user = None
        self._version = None
        self._with_credentials = None
        self.discriminator = None

        if access is not None:
            self.access = access
        if access_control is not None:
            self.access_control = access_control
        if basic_auth is not None:
            self.basic_auth = basic_auth
        if basic_auth_user is not None:
            self.basic_auth_user = basic_auth_user
        if database is not None:
            self.database = database
        if id is not None:
            self.id = id
        if is_default is not None:
            self.is_default = is_default
        if json_data is not None:
            self.json_data = json_data
        if name is not None:
            self.name = name
        if org_id is not None:
            self.org_id = org_id
        if read_only is not None:
            self.read_only = read_only
        if secure_json_fields is not None:
            self.secure_json_fields = secure_json_fields
        if type is not None:
            self.type = type
        if type_logo_url is not None:
            self.type_logo_url = type_logo_url
        if uid is not None:
            self.uid = uid
        if url is not None:
            self.url = url
        if user is not None:
            self.user = user
        if version is not None:
            self.version = version
        if with_credentials is not None:
            self.with_credentials = with_credentials

    @property
    def access(self):
        """Gets the access of this DataSource.  # noqa: E501


        :return: The access of this DataSource.  # noqa: E501
        :rtype: DsAccess
        """
        return self._access

    @access.setter
    def access(self, access):
        """Sets the access of this DataSource.


        :param access: The access of this DataSource.  # noqa: E501
        :type: DsAccess
        """

        self._access = access

    @property
    def access_control(self):
        """Gets the access_control of this DataSource.  # noqa: E501


        :return: The access_control of this DataSource.  # noqa: E501
        :rtype: Metadata
        """
        return self._access_control

    @access_control.setter
    def access_control(self, access_control):
        """Sets the access_control of this DataSource.


        :param access_control: The access_control of this DataSource.  # noqa: E501
        :type: Metadata
        """

        self._access_control = access_control

    @property
    def basic_auth(self):
        """Gets the basic_auth of this DataSource.  # noqa: E501


        :return: The basic_auth of this DataSource.  # noqa: E501
        :rtype: bool
        """
        return self._basic_auth

    @basic_auth.setter
    def basic_auth(self, basic_auth):
        """Sets the basic_auth of this DataSource.


        :param basic_auth: The basic_auth of this DataSource.  # noqa: E501
        :type: bool
        """

        self._basic_auth = basic_auth

    @property
    def basic_auth_user(self):
        """Gets the basic_auth_user of this DataSource.  # noqa: E501


        :return: The basic_auth_user of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._basic_auth_user

    @basic_auth_user.setter
    def basic_auth_user(self, basic_auth_user):
        """Sets the basic_auth_user of this DataSource.


        :param basic_auth_user: The basic_auth_user of this DataSource.  # noqa: E501
        :type: str
        """

        self._basic_auth_user = basic_auth_user

    @property
    def database(self):
        """Gets the database of this DataSource.  # noqa: E501


        :return: The database of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._database

    @database.setter
    def database(self, database):
        """Sets the database of this DataSource.


        :param database: The database of this DataSource.  # noqa: E501
        :type: str
        """

        self._database = database

    @property
    def id(self):
        """Gets the id of this DataSource.  # noqa: E501


        :return: The id of this DataSource.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this DataSource.


        :param id: The id of this DataSource.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def is_default(self):
        """Gets the is_default of this DataSource.  # noqa: E501


        :return: The is_default of this DataSource.  # noqa: E501
        :rtype: bool
        """
        return self._is_default

    @is_default.setter
    def is_default(self, is_default):
        """Sets the is_default of this DataSource.


        :param is_default: The is_default of this DataSource.  # noqa: E501
        :type: bool
        """

        self._is_default = is_default

    @property
    def json_data(self):
        """Gets the json_data of this DataSource.  # noqa: E501


        :return: The json_data of this DataSource.  # noqa: E501
        :rtype: Json
        """
        return self._json_data

    @json_data.setter
    def json_data(self, json_data):
        """Sets the json_data of this DataSource.


        :param json_data: The json_data of this DataSource.  # noqa: E501
        :type: Json
        """

        self._json_data = json_data

    @property
    def name(self):
        """Gets the name of this DataSource.  # noqa: E501


        :return: The name of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this DataSource.


        :param name: The name of this DataSource.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def org_id(self):
        """Gets the org_id of this DataSource.  # noqa: E501


        :return: The org_id of this DataSource.  # noqa: E501
        :rtype: int
        """
        return self._org_id

    @org_id.setter
    def org_id(self, org_id):
        """Sets the org_id of this DataSource.


        :param org_id: The org_id of this DataSource.  # noqa: E501
        :type: int
        """

        self._org_id = org_id

    @property
    def read_only(self):
        """Gets the read_only of this DataSource.  # noqa: E501


        :return: The read_only of this DataSource.  # noqa: E501
        :rtype: bool
        """
        return self._read_only

    @read_only.setter
    def read_only(self, read_only):
        """Sets the read_only of this DataSource.


        :param read_only: The read_only of this DataSource.  # noqa: E501
        :type: bool
        """

        self._read_only = read_only

    @property
    def secure_json_fields(self):
        """Gets the secure_json_fields of this DataSource.  # noqa: E501


        :return: The secure_json_fields of this DataSource.  # noqa: E501
        :rtype: dict(str, bool)
        """
        return self._secure_json_fields

    @secure_json_fields.setter
    def secure_json_fields(self, secure_json_fields):
        """Sets the secure_json_fields of this DataSource.


        :param secure_json_fields: The secure_json_fields of this DataSource.  # noqa: E501
        :type: dict(str, bool)
        """

        self._secure_json_fields = secure_json_fields

    @property
    def type(self):
        """Gets the type of this DataSource.  # noqa: E501


        :return: The type of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this DataSource.


        :param type: The type of this DataSource.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def type_logo_url(self):
        """Gets the type_logo_url of this DataSource.  # noqa: E501


        :return: The type_logo_url of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._type_logo_url

    @type_logo_url.setter
    def type_logo_url(self, type_logo_url):
        """Sets the type_logo_url of this DataSource.


        :param type_logo_url: The type_logo_url of this DataSource.  # noqa: E501
        :type: str
        """

        self._type_logo_url = type_logo_url

    @property
    def uid(self):
        """Gets the uid of this DataSource.  # noqa: E501


        :return: The uid of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._uid

    @uid.setter
    def uid(self, uid):
        """Sets the uid of this DataSource.


        :param uid: The uid of this DataSource.  # noqa: E501
        :type: str
        """

        self._uid = uid

    @property
    def url(self):
        """Gets the url of this DataSource.  # noqa: E501


        :return: The url of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._url

    @url.setter
    def url(self, url):
        """Sets the url of this DataSource.


        :param url: The url of this DataSource.  # noqa: E501
        :type: str
        """

        self._url = url

    @property
    def user(self):
        """Gets the user of this DataSource.  # noqa: E501


        :return: The user of this DataSource.  # noqa: E501
        :rtype: str
        """
        return self._user

    @user.setter
    def user(self, user):
        """Sets the user of this DataSource.


        :param user: The user of this DataSource.  # noqa: E501
        :type: str
        """

        self._user = user

    @property
    def version(self):
        """Gets the version of this DataSource.  # noqa: E501


        :return: The version of this DataSource.  # noqa: E501
        :rtype: int
        """
        return self._version

    @version.setter
    def version(self, version):
        """Sets the version of this DataSource.


        :param version: The version of this DataSource.  # noqa: E501
        :type: int
        """

        self._version = version

    @property
    def with_credentials(self):
        """Gets the with_credentials of this DataSource.  # noqa: E501


        :return: The with_credentials of this DataSource.  # noqa: E501
        :rtype: bool
        """
        return self._with_credentials

    @with_credentials.setter
    def with_credentials(self, with_credentials):
        """Sets the with_credentials of this DataSource.


        :param with_credentials: The with_credentials of this DataSource.  # noqa: E501
        :type: bool
        """

        self._with_credentials = with_credentials

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
        if issubclass(DataSource, dict):
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
        if not isinstance(other, DataSource):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DataSource):
            return True

        return self.to_dict() != other.to_dict()
