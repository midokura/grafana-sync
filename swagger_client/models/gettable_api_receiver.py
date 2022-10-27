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


class GettableApiReceiver(object):
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
        'email_configs': 'list[EmailConfig]',
        'grafana_managed_receiver_configs': 'list[GettableGrafanaReceiver]',
        'name': 'str',
        'opsgenie_configs': 'list[OpsGenieConfig]',
        'pagerduty_configs': 'list[PagerdutyConfig]',
        'pushover_configs': 'list[PushoverConfig]',
        'slack_configs': 'list[SlackConfig]',
        'sns_configs': 'list[SNSConfig]',
        'victorops_configs': 'list[VictorOpsConfig]',
        'webhook_configs': 'list[WebhookConfig]',
        'wechat_configs': 'list[WechatConfig]'
    }

    attribute_map = {
        'email_configs': 'email_configs',
        'grafana_managed_receiver_configs': 'grafana_managed_receiver_configs',
        'name': 'name',
        'opsgenie_configs': 'opsgenie_configs',
        'pagerduty_configs': 'pagerduty_configs',
        'pushover_configs': 'pushover_configs',
        'slack_configs': 'slack_configs',
        'sns_configs': 'sns_configs',
        'victorops_configs': 'victorops_configs',
        'webhook_configs': 'webhook_configs',
        'wechat_configs': 'wechat_configs'
    }

    def __init__(self, email_configs=None, grafana_managed_receiver_configs=None, name=None, opsgenie_configs=None, pagerduty_configs=None, pushover_configs=None, slack_configs=None, sns_configs=None, victorops_configs=None, webhook_configs=None, wechat_configs=None, _configuration=None):  # noqa: E501
        """GettableApiReceiver - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._email_configs = None
        self._grafana_managed_receiver_configs = None
        self._name = None
        self._opsgenie_configs = None
        self._pagerduty_configs = None
        self._pushover_configs = None
        self._slack_configs = None
        self._sns_configs = None
        self._victorops_configs = None
        self._webhook_configs = None
        self._wechat_configs = None
        self.discriminator = None

        if email_configs is not None:
            self.email_configs = email_configs
        if grafana_managed_receiver_configs is not None:
            self.grafana_managed_receiver_configs = grafana_managed_receiver_configs
        if name is not None:
            self.name = name
        if opsgenie_configs is not None:
            self.opsgenie_configs = opsgenie_configs
        if pagerduty_configs is not None:
            self.pagerduty_configs = pagerduty_configs
        if pushover_configs is not None:
            self.pushover_configs = pushover_configs
        if slack_configs is not None:
            self.slack_configs = slack_configs
        if sns_configs is not None:
            self.sns_configs = sns_configs
        if victorops_configs is not None:
            self.victorops_configs = victorops_configs
        if webhook_configs is not None:
            self.webhook_configs = webhook_configs
        if wechat_configs is not None:
            self.wechat_configs = wechat_configs

    @property
    def email_configs(self):
        """Gets the email_configs of this GettableApiReceiver.  # noqa: E501


        :return: The email_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[EmailConfig]
        """
        return self._email_configs

    @email_configs.setter
    def email_configs(self, email_configs):
        """Sets the email_configs of this GettableApiReceiver.


        :param email_configs: The email_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[EmailConfig]
        """

        self._email_configs = email_configs

    @property
    def grafana_managed_receiver_configs(self):
        """Gets the grafana_managed_receiver_configs of this GettableApiReceiver.  # noqa: E501


        :return: The grafana_managed_receiver_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[GettableGrafanaReceiver]
        """
        return self._grafana_managed_receiver_configs

    @grafana_managed_receiver_configs.setter
    def grafana_managed_receiver_configs(self, grafana_managed_receiver_configs):
        """Sets the grafana_managed_receiver_configs of this GettableApiReceiver.


        :param grafana_managed_receiver_configs: The grafana_managed_receiver_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[GettableGrafanaReceiver]
        """

        self._grafana_managed_receiver_configs = grafana_managed_receiver_configs

    @property
    def name(self):
        """Gets the name of this GettableApiReceiver.  # noqa: E501

        A unique identifier for this receiver.  # noqa: E501

        :return: The name of this GettableApiReceiver.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this GettableApiReceiver.

        A unique identifier for this receiver.  # noqa: E501

        :param name: The name of this GettableApiReceiver.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def opsgenie_configs(self):
        """Gets the opsgenie_configs of this GettableApiReceiver.  # noqa: E501


        :return: The opsgenie_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[OpsGenieConfig]
        """
        return self._opsgenie_configs

    @opsgenie_configs.setter
    def opsgenie_configs(self, opsgenie_configs):
        """Sets the opsgenie_configs of this GettableApiReceiver.


        :param opsgenie_configs: The opsgenie_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[OpsGenieConfig]
        """

        self._opsgenie_configs = opsgenie_configs

    @property
    def pagerduty_configs(self):
        """Gets the pagerduty_configs of this GettableApiReceiver.  # noqa: E501


        :return: The pagerduty_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[PagerdutyConfig]
        """
        return self._pagerduty_configs

    @pagerduty_configs.setter
    def pagerduty_configs(self, pagerduty_configs):
        """Sets the pagerduty_configs of this GettableApiReceiver.


        :param pagerduty_configs: The pagerduty_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[PagerdutyConfig]
        """

        self._pagerduty_configs = pagerduty_configs

    @property
    def pushover_configs(self):
        """Gets the pushover_configs of this GettableApiReceiver.  # noqa: E501


        :return: The pushover_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[PushoverConfig]
        """
        return self._pushover_configs

    @pushover_configs.setter
    def pushover_configs(self, pushover_configs):
        """Sets the pushover_configs of this GettableApiReceiver.


        :param pushover_configs: The pushover_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[PushoverConfig]
        """

        self._pushover_configs = pushover_configs

    @property
    def slack_configs(self):
        """Gets the slack_configs of this GettableApiReceiver.  # noqa: E501


        :return: The slack_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[SlackConfig]
        """
        return self._slack_configs

    @slack_configs.setter
    def slack_configs(self, slack_configs):
        """Sets the slack_configs of this GettableApiReceiver.


        :param slack_configs: The slack_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[SlackConfig]
        """

        self._slack_configs = slack_configs

    @property
    def sns_configs(self):
        """Gets the sns_configs of this GettableApiReceiver.  # noqa: E501


        :return: The sns_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[SNSConfig]
        """
        return self._sns_configs

    @sns_configs.setter
    def sns_configs(self, sns_configs):
        """Sets the sns_configs of this GettableApiReceiver.


        :param sns_configs: The sns_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[SNSConfig]
        """

        self._sns_configs = sns_configs

    @property
    def victorops_configs(self):
        """Gets the victorops_configs of this GettableApiReceiver.  # noqa: E501


        :return: The victorops_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[VictorOpsConfig]
        """
        return self._victorops_configs

    @victorops_configs.setter
    def victorops_configs(self, victorops_configs):
        """Sets the victorops_configs of this GettableApiReceiver.


        :param victorops_configs: The victorops_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[VictorOpsConfig]
        """

        self._victorops_configs = victorops_configs

    @property
    def webhook_configs(self):
        """Gets the webhook_configs of this GettableApiReceiver.  # noqa: E501


        :return: The webhook_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[WebhookConfig]
        """
        return self._webhook_configs

    @webhook_configs.setter
    def webhook_configs(self, webhook_configs):
        """Sets the webhook_configs of this GettableApiReceiver.


        :param webhook_configs: The webhook_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[WebhookConfig]
        """

        self._webhook_configs = webhook_configs

    @property
    def wechat_configs(self):
        """Gets the wechat_configs of this GettableApiReceiver.  # noqa: E501


        :return: The wechat_configs of this GettableApiReceiver.  # noqa: E501
        :rtype: list[WechatConfig]
        """
        return self._wechat_configs

    @wechat_configs.setter
    def wechat_configs(self, wechat_configs):
        """Sets the wechat_configs of this GettableApiReceiver.


        :param wechat_configs: The wechat_configs of this GettableApiReceiver.  # noqa: E501
        :type: list[WechatConfig]
        """

        self._wechat_configs = wechat_configs

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
        if issubclass(GettableApiReceiver, dict):
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
        if not isinstance(other, GettableApiReceiver):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, GettableApiReceiver):
            return True

        return self.to_dict() != other.to_dict()
