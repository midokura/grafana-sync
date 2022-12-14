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


class PrometheusRemoteWriteTargetJSON(object):
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
        'data_source_uid': 'str',
        'id': 'str',
        'remote_write_path': 'str'
    }

    attribute_map = {
        'data_source_uid': 'data_source_uid',
        'id': 'id',
        'remote_write_path': 'remote_write_path'
    }

    def __init__(self, data_source_uid=None, id=None, remote_write_path=None, _configuration=None):  # noqa: E501
        """PrometheusRemoteWriteTargetJSON - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._data_source_uid = None
        self._id = None
        self._remote_write_path = None
        self.discriminator = None

        if data_source_uid is not None:
            self.data_source_uid = data_source_uid
        if id is not None:
            self.id = id
        if remote_write_path is not None:
            self.remote_write_path = remote_write_path

    @property
    def data_source_uid(self):
        """Gets the data_source_uid of this PrometheusRemoteWriteTargetJSON.  # noqa: E501


        :return: The data_source_uid of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :rtype: str
        """
        return self._data_source_uid

    @data_source_uid.setter
    def data_source_uid(self, data_source_uid):
        """Sets the data_source_uid of this PrometheusRemoteWriteTargetJSON.


        :param data_source_uid: The data_source_uid of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :type: str
        """

        self._data_source_uid = data_source_uid

    @property
    def id(self):
        """Gets the id of this PrometheusRemoteWriteTargetJSON.  # noqa: E501


        :return: The id of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this PrometheusRemoteWriteTargetJSON.


        :param id: The id of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :type: str
        """

        self._id = id

    @property
    def remote_write_path(self):
        """Gets the remote_write_path of this PrometheusRemoteWriteTargetJSON.  # noqa: E501


        :return: The remote_write_path of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :rtype: str
        """
        return self._remote_write_path

    @remote_write_path.setter
    def remote_write_path(self, remote_write_path):
        """Sets the remote_write_path of this PrometheusRemoteWriteTargetJSON.


        :param remote_write_path: The remote_write_path of this PrometheusRemoteWriteTargetJSON.  # noqa: E501
        :type: str
        """

        self._remote_write_path = remote_write_path

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
        if issubclass(PrometheusRemoteWriteTargetJSON, dict):
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
        if not isinstance(other, PrometheusRemoteWriteTargetJSON):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, PrometheusRemoteWriteTargetJSON):
            return True

        return self.to_dict() != other.to_dict()
