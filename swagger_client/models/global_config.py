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


class GlobalConfig(object):
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
        'opsgenie_api_key': 'Secret',
        'opsgenie_api_key_file': 'str',
        'opsgenie_api_url': 'URL',
        'pagerduty_url': 'URL',
        'resolve_timeout': 'Duration',
        'slack_api_url': 'SecretURL',
        'slack_api_url_file': 'str',
        'smtp_auth_identity': 'str',
        'smtp_auth_password': 'Secret',
        'smtp_auth_secret': 'Secret',
        'smtp_auth_username': 'str',
        'smtp_from': 'str',
        'smtp_hello': 'str',
        'smtp_require_tls': 'bool',
        'smtp_smarthost': 'HostPort',
        'victorops_api_key': 'Secret',
        'victorops_api_url': 'URL',
        'wechat_api_corp_id': 'str',
        'wechat_api_secret': 'Secret',
        'wechat_api_url': 'URL'
    }

    attribute_map = {
        'http_config': 'http_config',
        'opsgenie_api_key': 'opsgenie_api_key',
        'opsgenie_api_key_file': 'opsgenie_api_key_file',
        'opsgenie_api_url': 'opsgenie_api_url',
        'pagerduty_url': 'pagerduty_url',
        'resolve_timeout': 'resolve_timeout',
        'slack_api_url': 'slack_api_url',
        'slack_api_url_file': 'slack_api_url_file',
        'smtp_auth_identity': 'smtp_auth_identity',
        'smtp_auth_password': 'smtp_auth_password',
        'smtp_auth_secret': 'smtp_auth_secret',
        'smtp_auth_username': 'smtp_auth_username',
        'smtp_from': 'smtp_from',
        'smtp_hello': 'smtp_hello',
        'smtp_require_tls': 'smtp_require_tls',
        'smtp_smarthost': 'smtp_smarthost',
        'victorops_api_key': 'victorops_api_key',
        'victorops_api_url': 'victorops_api_url',
        'wechat_api_corp_id': 'wechat_api_corp_id',
        'wechat_api_secret': 'wechat_api_secret',
        'wechat_api_url': 'wechat_api_url'
    }

    def __init__(self, http_config=None, opsgenie_api_key=None, opsgenie_api_key_file=None, opsgenie_api_url=None, pagerduty_url=None, resolve_timeout=None, slack_api_url=None, slack_api_url_file=None, smtp_auth_identity=None, smtp_auth_password=None, smtp_auth_secret=None, smtp_auth_username=None, smtp_from=None, smtp_hello=None, smtp_require_tls=None, smtp_smarthost=None, victorops_api_key=None, victorops_api_url=None, wechat_api_corp_id=None, wechat_api_secret=None, wechat_api_url=None, _configuration=None):  # noqa: E501
        """GlobalConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._http_config = None
        self._opsgenie_api_key = None
        self._opsgenie_api_key_file = None
        self._opsgenie_api_url = None
        self._pagerduty_url = None
        self._resolve_timeout = None
        self._slack_api_url = None
        self._slack_api_url_file = None
        self._smtp_auth_identity = None
        self._smtp_auth_password = None
        self._smtp_auth_secret = None
        self._smtp_auth_username = None
        self._smtp_from = None
        self._smtp_hello = None
        self._smtp_require_tls = None
        self._smtp_smarthost = None
        self._victorops_api_key = None
        self._victorops_api_url = None
        self._wechat_api_corp_id = None
        self._wechat_api_secret = None
        self._wechat_api_url = None
        self.discriminator = None

        if http_config is not None:
            self.http_config = http_config
        if opsgenie_api_key is not None:
            self.opsgenie_api_key = opsgenie_api_key
        if opsgenie_api_key_file is not None:
            self.opsgenie_api_key_file = opsgenie_api_key_file
        if opsgenie_api_url is not None:
            self.opsgenie_api_url = opsgenie_api_url
        if pagerduty_url is not None:
            self.pagerduty_url = pagerduty_url
        if resolve_timeout is not None:
            self.resolve_timeout = resolve_timeout
        if slack_api_url is not None:
            self.slack_api_url = slack_api_url
        if slack_api_url_file is not None:
            self.slack_api_url_file = slack_api_url_file
        if smtp_auth_identity is not None:
            self.smtp_auth_identity = smtp_auth_identity
        if smtp_auth_password is not None:
            self.smtp_auth_password = smtp_auth_password
        if smtp_auth_secret is not None:
            self.smtp_auth_secret = smtp_auth_secret
        if smtp_auth_username is not None:
            self.smtp_auth_username = smtp_auth_username
        if smtp_from is not None:
            self.smtp_from = smtp_from
        if smtp_hello is not None:
            self.smtp_hello = smtp_hello
        if smtp_require_tls is not None:
            self.smtp_require_tls = smtp_require_tls
        if smtp_smarthost is not None:
            self.smtp_smarthost = smtp_smarthost
        if victorops_api_key is not None:
            self.victorops_api_key = victorops_api_key
        if victorops_api_url is not None:
            self.victorops_api_url = victorops_api_url
        if wechat_api_corp_id is not None:
            self.wechat_api_corp_id = wechat_api_corp_id
        if wechat_api_secret is not None:
            self.wechat_api_secret = wechat_api_secret
        if wechat_api_url is not None:
            self.wechat_api_url = wechat_api_url

    @property
    def http_config(self):
        """Gets the http_config of this GlobalConfig.  # noqa: E501


        :return: The http_config of this GlobalConfig.  # noqa: E501
        :rtype: HTTPClientConfig
        """
        return self._http_config

    @http_config.setter
    def http_config(self, http_config):
        """Sets the http_config of this GlobalConfig.


        :param http_config: The http_config of this GlobalConfig.  # noqa: E501
        :type: HTTPClientConfig
        """

        self._http_config = http_config

    @property
    def opsgenie_api_key(self):
        """Gets the opsgenie_api_key of this GlobalConfig.  # noqa: E501


        :return: The opsgenie_api_key of this GlobalConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._opsgenie_api_key

    @opsgenie_api_key.setter
    def opsgenie_api_key(self, opsgenie_api_key):
        """Sets the opsgenie_api_key of this GlobalConfig.


        :param opsgenie_api_key: The opsgenie_api_key of this GlobalConfig.  # noqa: E501
        :type: Secret
        """

        self._opsgenie_api_key = opsgenie_api_key

    @property
    def opsgenie_api_key_file(self):
        """Gets the opsgenie_api_key_file of this GlobalConfig.  # noqa: E501


        :return: The opsgenie_api_key_file of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._opsgenie_api_key_file

    @opsgenie_api_key_file.setter
    def opsgenie_api_key_file(self, opsgenie_api_key_file):
        """Sets the opsgenie_api_key_file of this GlobalConfig.


        :param opsgenie_api_key_file: The opsgenie_api_key_file of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._opsgenie_api_key_file = opsgenie_api_key_file

    @property
    def opsgenie_api_url(self):
        """Gets the opsgenie_api_url of this GlobalConfig.  # noqa: E501


        :return: The opsgenie_api_url of this GlobalConfig.  # noqa: E501
        :rtype: URL
        """
        return self._opsgenie_api_url

    @opsgenie_api_url.setter
    def opsgenie_api_url(self, opsgenie_api_url):
        """Sets the opsgenie_api_url of this GlobalConfig.


        :param opsgenie_api_url: The opsgenie_api_url of this GlobalConfig.  # noqa: E501
        :type: URL
        """

        self._opsgenie_api_url = opsgenie_api_url

    @property
    def pagerduty_url(self):
        """Gets the pagerduty_url of this GlobalConfig.  # noqa: E501


        :return: The pagerduty_url of this GlobalConfig.  # noqa: E501
        :rtype: URL
        """
        return self._pagerduty_url

    @pagerduty_url.setter
    def pagerduty_url(self, pagerduty_url):
        """Sets the pagerduty_url of this GlobalConfig.


        :param pagerduty_url: The pagerduty_url of this GlobalConfig.  # noqa: E501
        :type: URL
        """

        self._pagerduty_url = pagerduty_url

    @property
    def resolve_timeout(self):
        """Gets the resolve_timeout of this GlobalConfig.  # noqa: E501


        :return: The resolve_timeout of this GlobalConfig.  # noqa: E501
        :rtype: Duration
        """
        return self._resolve_timeout

    @resolve_timeout.setter
    def resolve_timeout(self, resolve_timeout):
        """Sets the resolve_timeout of this GlobalConfig.


        :param resolve_timeout: The resolve_timeout of this GlobalConfig.  # noqa: E501
        :type: Duration
        """

        self._resolve_timeout = resolve_timeout

    @property
    def slack_api_url(self):
        """Gets the slack_api_url of this GlobalConfig.  # noqa: E501


        :return: The slack_api_url of this GlobalConfig.  # noqa: E501
        :rtype: SecretURL
        """
        return self._slack_api_url

    @slack_api_url.setter
    def slack_api_url(self, slack_api_url):
        """Sets the slack_api_url of this GlobalConfig.


        :param slack_api_url: The slack_api_url of this GlobalConfig.  # noqa: E501
        :type: SecretURL
        """

        self._slack_api_url = slack_api_url

    @property
    def slack_api_url_file(self):
        """Gets the slack_api_url_file of this GlobalConfig.  # noqa: E501


        :return: The slack_api_url_file of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._slack_api_url_file

    @slack_api_url_file.setter
    def slack_api_url_file(self, slack_api_url_file):
        """Sets the slack_api_url_file of this GlobalConfig.


        :param slack_api_url_file: The slack_api_url_file of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._slack_api_url_file = slack_api_url_file

    @property
    def smtp_auth_identity(self):
        """Gets the smtp_auth_identity of this GlobalConfig.  # noqa: E501


        :return: The smtp_auth_identity of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._smtp_auth_identity

    @smtp_auth_identity.setter
    def smtp_auth_identity(self, smtp_auth_identity):
        """Sets the smtp_auth_identity of this GlobalConfig.


        :param smtp_auth_identity: The smtp_auth_identity of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._smtp_auth_identity = smtp_auth_identity

    @property
    def smtp_auth_password(self):
        """Gets the smtp_auth_password of this GlobalConfig.  # noqa: E501


        :return: The smtp_auth_password of this GlobalConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._smtp_auth_password

    @smtp_auth_password.setter
    def smtp_auth_password(self, smtp_auth_password):
        """Sets the smtp_auth_password of this GlobalConfig.


        :param smtp_auth_password: The smtp_auth_password of this GlobalConfig.  # noqa: E501
        :type: Secret
        """

        self._smtp_auth_password = smtp_auth_password

    @property
    def smtp_auth_secret(self):
        """Gets the smtp_auth_secret of this GlobalConfig.  # noqa: E501


        :return: The smtp_auth_secret of this GlobalConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._smtp_auth_secret

    @smtp_auth_secret.setter
    def smtp_auth_secret(self, smtp_auth_secret):
        """Sets the smtp_auth_secret of this GlobalConfig.


        :param smtp_auth_secret: The smtp_auth_secret of this GlobalConfig.  # noqa: E501
        :type: Secret
        """

        self._smtp_auth_secret = smtp_auth_secret

    @property
    def smtp_auth_username(self):
        """Gets the smtp_auth_username of this GlobalConfig.  # noqa: E501


        :return: The smtp_auth_username of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._smtp_auth_username

    @smtp_auth_username.setter
    def smtp_auth_username(self, smtp_auth_username):
        """Sets the smtp_auth_username of this GlobalConfig.


        :param smtp_auth_username: The smtp_auth_username of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._smtp_auth_username = smtp_auth_username

    @property
    def smtp_from(self):
        """Gets the smtp_from of this GlobalConfig.  # noqa: E501


        :return: The smtp_from of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._smtp_from

    @smtp_from.setter
    def smtp_from(self, smtp_from):
        """Sets the smtp_from of this GlobalConfig.


        :param smtp_from: The smtp_from of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._smtp_from = smtp_from

    @property
    def smtp_hello(self):
        """Gets the smtp_hello of this GlobalConfig.  # noqa: E501


        :return: The smtp_hello of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._smtp_hello

    @smtp_hello.setter
    def smtp_hello(self, smtp_hello):
        """Sets the smtp_hello of this GlobalConfig.


        :param smtp_hello: The smtp_hello of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._smtp_hello = smtp_hello

    @property
    def smtp_require_tls(self):
        """Gets the smtp_require_tls of this GlobalConfig.  # noqa: E501


        :return: The smtp_require_tls of this GlobalConfig.  # noqa: E501
        :rtype: bool
        """
        return self._smtp_require_tls

    @smtp_require_tls.setter
    def smtp_require_tls(self, smtp_require_tls):
        """Sets the smtp_require_tls of this GlobalConfig.


        :param smtp_require_tls: The smtp_require_tls of this GlobalConfig.  # noqa: E501
        :type: bool
        """

        self._smtp_require_tls = smtp_require_tls

    @property
    def smtp_smarthost(self):
        """Gets the smtp_smarthost of this GlobalConfig.  # noqa: E501


        :return: The smtp_smarthost of this GlobalConfig.  # noqa: E501
        :rtype: HostPort
        """
        return self._smtp_smarthost

    @smtp_smarthost.setter
    def smtp_smarthost(self, smtp_smarthost):
        """Sets the smtp_smarthost of this GlobalConfig.


        :param smtp_smarthost: The smtp_smarthost of this GlobalConfig.  # noqa: E501
        :type: HostPort
        """

        self._smtp_smarthost = smtp_smarthost

    @property
    def victorops_api_key(self):
        """Gets the victorops_api_key of this GlobalConfig.  # noqa: E501


        :return: The victorops_api_key of this GlobalConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._victorops_api_key

    @victorops_api_key.setter
    def victorops_api_key(self, victorops_api_key):
        """Sets the victorops_api_key of this GlobalConfig.


        :param victorops_api_key: The victorops_api_key of this GlobalConfig.  # noqa: E501
        :type: Secret
        """

        self._victorops_api_key = victorops_api_key

    @property
    def victorops_api_url(self):
        """Gets the victorops_api_url of this GlobalConfig.  # noqa: E501


        :return: The victorops_api_url of this GlobalConfig.  # noqa: E501
        :rtype: URL
        """
        return self._victorops_api_url

    @victorops_api_url.setter
    def victorops_api_url(self, victorops_api_url):
        """Sets the victorops_api_url of this GlobalConfig.


        :param victorops_api_url: The victorops_api_url of this GlobalConfig.  # noqa: E501
        :type: URL
        """

        self._victorops_api_url = victorops_api_url

    @property
    def wechat_api_corp_id(self):
        """Gets the wechat_api_corp_id of this GlobalConfig.  # noqa: E501


        :return: The wechat_api_corp_id of this GlobalConfig.  # noqa: E501
        :rtype: str
        """
        return self._wechat_api_corp_id

    @wechat_api_corp_id.setter
    def wechat_api_corp_id(self, wechat_api_corp_id):
        """Sets the wechat_api_corp_id of this GlobalConfig.


        :param wechat_api_corp_id: The wechat_api_corp_id of this GlobalConfig.  # noqa: E501
        :type: str
        """

        self._wechat_api_corp_id = wechat_api_corp_id

    @property
    def wechat_api_secret(self):
        """Gets the wechat_api_secret of this GlobalConfig.  # noqa: E501


        :return: The wechat_api_secret of this GlobalConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._wechat_api_secret

    @wechat_api_secret.setter
    def wechat_api_secret(self, wechat_api_secret):
        """Sets the wechat_api_secret of this GlobalConfig.


        :param wechat_api_secret: The wechat_api_secret of this GlobalConfig.  # noqa: E501
        :type: Secret
        """

        self._wechat_api_secret = wechat_api_secret

    @property
    def wechat_api_url(self):
        """Gets the wechat_api_url of this GlobalConfig.  # noqa: E501


        :return: The wechat_api_url of this GlobalConfig.  # noqa: E501
        :rtype: URL
        """
        return self._wechat_api_url

    @wechat_api_url.setter
    def wechat_api_url(self, wechat_api_url):
        """Sets the wechat_api_url of this GlobalConfig.


        :param wechat_api_url: The wechat_api_url of this GlobalConfig.  # noqa: E501
        :type: URL
        """

        self._wechat_api_url = wechat_api_url

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
        if issubclass(GlobalConfig, dict):
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
        if not isinstance(other, GlobalConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, GlobalConfig):
            return True

        return self.to_dict() != other.to_dict()
