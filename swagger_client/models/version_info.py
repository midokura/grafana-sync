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


class VersionInfo(object):
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
        'branch': 'str',
        'build_date': 'str',
        'build_user': 'str',
        'go_version': 'str',
        'revision': 'str',
        'version': 'str'
    }

    attribute_map = {
        'branch': 'branch',
        'build_date': 'buildDate',
        'build_user': 'buildUser',
        'go_version': 'goVersion',
        'revision': 'revision',
        'version': 'version'
    }

    def __init__(self, branch=None, build_date=None, build_user=None, go_version=None, revision=None, version=None, _configuration=None):  # noqa: E501
        """VersionInfo - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._branch = None
        self._build_date = None
        self._build_user = None
        self._go_version = None
        self._revision = None
        self._version = None
        self.discriminator = None

        self.branch = branch
        self.build_date = build_date
        self.build_user = build_user
        self.go_version = go_version
        self.revision = revision
        self.version = version

    @property
    def branch(self):
        """Gets the branch of this VersionInfo.  # noqa: E501

        branch  # noqa: E501

        :return: The branch of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._branch

    @branch.setter
    def branch(self, branch):
        """Sets the branch of this VersionInfo.

        branch  # noqa: E501

        :param branch: The branch of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and branch is None:
            raise ValueError("Invalid value for `branch`, must not be `None`")  # noqa: E501

        self._branch = branch

    @property
    def build_date(self):
        """Gets the build_date of this VersionInfo.  # noqa: E501

        build date  # noqa: E501

        :return: The build_date of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._build_date

    @build_date.setter
    def build_date(self, build_date):
        """Sets the build_date of this VersionInfo.

        build date  # noqa: E501

        :param build_date: The build_date of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and build_date is None:
            raise ValueError("Invalid value for `build_date`, must not be `None`")  # noqa: E501

        self._build_date = build_date

    @property
    def build_user(self):
        """Gets the build_user of this VersionInfo.  # noqa: E501

        build user  # noqa: E501

        :return: The build_user of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._build_user

    @build_user.setter
    def build_user(self, build_user):
        """Sets the build_user of this VersionInfo.

        build user  # noqa: E501

        :param build_user: The build_user of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and build_user is None:
            raise ValueError("Invalid value for `build_user`, must not be `None`")  # noqa: E501

        self._build_user = build_user

    @property
    def go_version(self):
        """Gets the go_version of this VersionInfo.  # noqa: E501

        go version  # noqa: E501

        :return: The go_version of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._go_version

    @go_version.setter
    def go_version(self, go_version):
        """Sets the go_version of this VersionInfo.

        go version  # noqa: E501

        :param go_version: The go_version of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and go_version is None:
            raise ValueError("Invalid value for `go_version`, must not be `None`")  # noqa: E501

        self._go_version = go_version

    @property
    def revision(self):
        """Gets the revision of this VersionInfo.  # noqa: E501

        revision  # noqa: E501

        :return: The revision of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._revision

    @revision.setter
    def revision(self, revision):
        """Sets the revision of this VersionInfo.

        revision  # noqa: E501

        :param revision: The revision of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and revision is None:
            raise ValueError("Invalid value for `revision`, must not be `None`")  # noqa: E501

        self._revision = revision

    @property
    def version(self):
        """Gets the version of this VersionInfo.  # noqa: E501

        version  # noqa: E501

        :return: The version of this VersionInfo.  # noqa: E501
        :rtype: str
        """
        return self._version

    @version.setter
    def version(self, version):
        """Sets the version of this VersionInfo.

        version  # noqa: E501

        :param version: The version of this VersionInfo.  # noqa: E501
        :type: str
        """
        if self._configuration.client_side_validation and version is None:
            raise ValueError("Invalid value for `version`, must not be `None`")  # noqa: E501

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
        if issubclass(VersionInfo, dict):
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
        if not isinstance(other, VersionInfo):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, VersionInfo):
            return True

        return self.to_dict() != other.to_dict()
