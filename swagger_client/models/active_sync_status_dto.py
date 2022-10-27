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


class ActiveSyncStatusDTO(object):
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
        'enabled': 'bool',
        'next_sync': 'datetime',
        'prev_sync': 'SyncResult',
        'schedule': 'str'
    }

    attribute_map = {
        'enabled': 'enabled',
        'next_sync': 'nextSync',
        'prev_sync': 'prevSync',
        'schedule': 'schedule'
    }

    def __init__(self, enabled=None, next_sync=None, prev_sync=None, schedule=None, _configuration=None):  # noqa: E501
        """ActiveSyncStatusDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._enabled = None
        self._next_sync = None
        self._prev_sync = None
        self._schedule = None
        self.discriminator = None

        if enabled is not None:
            self.enabled = enabled
        if next_sync is not None:
            self.next_sync = next_sync
        if prev_sync is not None:
            self.prev_sync = prev_sync
        if schedule is not None:
            self.schedule = schedule

    @property
    def enabled(self):
        """Gets the enabled of this ActiveSyncStatusDTO.  # noqa: E501


        :return: The enabled of this ActiveSyncStatusDTO.  # noqa: E501
        :rtype: bool
        """
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Sets the enabled of this ActiveSyncStatusDTO.


        :param enabled: The enabled of this ActiveSyncStatusDTO.  # noqa: E501
        :type: bool
        """

        self._enabled = enabled

    @property
    def next_sync(self):
        """Gets the next_sync of this ActiveSyncStatusDTO.  # noqa: E501


        :return: The next_sync of this ActiveSyncStatusDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._next_sync

    @next_sync.setter
    def next_sync(self, next_sync):
        """Sets the next_sync of this ActiveSyncStatusDTO.


        :param next_sync: The next_sync of this ActiveSyncStatusDTO.  # noqa: E501
        :type: datetime
        """

        self._next_sync = next_sync

    @property
    def prev_sync(self):
        """Gets the prev_sync of this ActiveSyncStatusDTO.  # noqa: E501


        :return: The prev_sync of this ActiveSyncStatusDTO.  # noqa: E501
        :rtype: SyncResult
        """
        return self._prev_sync

    @prev_sync.setter
    def prev_sync(self, prev_sync):
        """Sets the prev_sync of this ActiveSyncStatusDTO.


        :param prev_sync: The prev_sync of this ActiveSyncStatusDTO.  # noqa: E501
        :type: SyncResult
        """

        self._prev_sync = prev_sync

    @property
    def schedule(self):
        """Gets the schedule of this ActiveSyncStatusDTO.  # noqa: E501


        :return: The schedule of this ActiveSyncStatusDTO.  # noqa: E501
        :rtype: str
        """
        return self._schedule

    @schedule.setter
    def schedule(self, schedule):
        """Sets the schedule of this ActiveSyncStatusDTO.


        :param schedule: The schedule of this ActiveSyncStatusDTO.  # noqa: E501
        :type: str
        """

        self._schedule = schedule

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
        if issubclass(ActiveSyncStatusDTO, dict):
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
        if not isinstance(other, ActiveSyncStatusDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ActiveSyncStatusDTO):
            return True

        return self.to_dict() != other.to_dict()
