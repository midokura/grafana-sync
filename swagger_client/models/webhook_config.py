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


class WebhookConfig(object):
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
        'http_config': 'HTTPClientConfig',
        'max_alerts': 'int',
        'send_resolved': 'bool',
        'url': 'URL'
    }

    attribute_map = {
        'http_config': 'http_config',
        'max_alerts': 'max_alerts',
        'send_resolved': 'send_resolved',
        'url': 'url'
    }

    def __init__(self, http_config=None, max_alerts=None, send_resolved=None, url=None, _configuration=None):  # noqa: E501
        """WebhookConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._http_config = None
        self._max_alerts = None
        self._send_resolved = None
        self._url = None
        self.discriminator = None

        if http_config is not None:
            self.http_config = http_config
        if max_alerts is not None:
            self.max_alerts = max_alerts
        if send_resolved is not None:
            self.send_resolved = send_resolved
        if url is not None:
            self.url = url

    @property
    def http_config(self):
        """Gets the http_config of this WebhookConfig.  # noqa: E501


        :return: The http_config of this WebhookConfig.  # noqa: E501
        :rtype: HTTPClientConfig
        """
        return self._http_config

    @http_config.setter
    def http_config(self, http_config):
        """Sets the http_config of this WebhookConfig.


        :param http_config: The http_config of this WebhookConfig.  # noqa: E501
        :type: HTTPClientConfig
        """

        self._http_config = http_config

    @property
    def max_alerts(self):
        """Gets the max_alerts of this WebhookConfig.  # noqa: E501

        MaxAlerts is the maximum number of alerts to be sent per webhook message. Alerts exceeding this threshold will be truncated. Setting this to 0 allows an unlimited number of alerts.  # noqa: E501

        :return: The max_alerts of this WebhookConfig.  # noqa: E501
        :rtype: int
        """
        return self._max_alerts

    @max_alerts.setter
    def max_alerts(self, max_alerts):
        """Sets the max_alerts of this WebhookConfig.

        MaxAlerts is the maximum number of alerts to be sent per webhook message. Alerts exceeding this threshold will be truncated. Setting this to 0 allows an unlimited number of alerts.  # noqa: E501

        :param max_alerts: The max_alerts of this WebhookConfig.  # noqa: E501
        :type: int
        """

        self._max_alerts = max_alerts

    @property
    def send_resolved(self):
        """Gets the send_resolved of this WebhookConfig.  # noqa: E501


        :return: The send_resolved of this WebhookConfig.  # noqa: E501
        :rtype: bool
        """
        return self._send_resolved

    @send_resolved.setter
    def send_resolved(self, send_resolved):
        """Sets the send_resolved of this WebhookConfig.


        :param send_resolved: The send_resolved of this WebhookConfig.  # noqa: E501
        :type: bool
        """

        self._send_resolved = send_resolved

    @property
    def url(self):
        """Gets the url of this WebhookConfig.  # noqa: E501


        :return: The url of this WebhookConfig.  # noqa: E501
        :rtype: URL
        """
        return self._url

    @url.setter
    def url(self, url):
        """Sets the url of this WebhookConfig.


        :param url: The url of this WebhookConfig.  # noqa: E501
        :type: URL
        """

        self._url = url

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
        if issubclass(WebhookConfig, dict):
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
        if not isinstance(other, WebhookConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, WebhookConfig):
            return True

        return self.to_dict() != other.to_dict()