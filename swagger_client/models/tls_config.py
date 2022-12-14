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


class TLSConfig(object):
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
        'ca_file': 'str',
        'cert_file': 'str',
        'insecure_skip_verify': 'bool',
        'key_file': 'str',
        'server_name': 'str'
    }

    attribute_map = {
        'ca_file': 'ca_file',
        'cert_file': 'cert_file',
        'insecure_skip_verify': 'insecure_skip_verify',
        'key_file': 'key_file',
        'server_name': 'server_name'
    }

    def __init__(self, ca_file=None, cert_file=None, insecure_skip_verify=None, key_file=None, server_name=None, _configuration=None):  # noqa: E501
        """TLSConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._ca_file = None
        self._cert_file = None
        self._insecure_skip_verify = None
        self._key_file = None
        self._server_name = None
        self.discriminator = None

        if ca_file is not None:
            self.ca_file = ca_file
        if cert_file is not None:
            self.cert_file = cert_file
        if insecure_skip_verify is not None:
            self.insecure_skip_verify = insecure_skip_verify
        if key_file is not None:
            self.key_file = key_file
        if server_name is not None:
            self.server_name = server_name

    @property
    def ca_file(self):
        """Gets the ca_file of this TLSConfig.  # noqa: E501

        The CA cert to use for the targets.  # noqa: E501

        :return: The ca_file of this TLSConfig.  # noqa: E501
        :rtype: str
        """
        return self._ca_file

    @ca_file.setter
    def ca_file(self, ca_file):
        """Sets the ca_file of this TLSConfig.

        The CA cert to use for the targets.  # noqa: E501

        :param ca_file: The ca_file of this TLSConfig.  # noqa: E501
        :type: str
        """

        self._ca_file = ca_file

    @property
    def cert_file(self):
        """Gets the cert_file of this TLSConfig.  # noqa: E501

        The client cert file for the targets.  # noqa: E501

        :return: The cert_file of this TLSConfig.  # noqa: E501
        :rtype: str
        """
        return self._cert_file

    @cert_file.setter
    def cert_file(self, cert_file):
        """Sets the cert_file of this TLSConfig.

        The client cert file for the targets.  # noqa: E501

        :param cert_file: The cert_file of this TLSConfig.  # noqa: E501
        :type: str
        """

        self._cert_file = cert_file

    @property
    def insecure_skip_verify(self):
        """Gets the insecure_skip_verify of this TLSConfig.  # noqa: E501

        Disable target certificate validation.  # noqa: E501

        :return: The insecure_skip_verify of this TLSConfig.  # noqa: E501
        :rtype: bool
        """
        return self._insecure_skip_verify

    @insecure_skip_verify.setter
    def insecure_skip_verify(self, insecure_skip_verify):
        """Sets the insecure_skip_verify of this TLSConfig.

        Disable target certificate validation.  # noqa: E501

        :param insecure_skip_verify: The insecure_skip_verify of this TLSConfig.  # noqa: E501
        :type: bool
        """

        self._insecure_skip_verify = insecure_skip_verify

    @property
    def key_file(self):
        """Gets the key_file of this TLSConfig.  # noqa: E501

        The client key file for the targets.  # noqa: E501

        :return: The key_file of this TLSConfig.  # noqa: E501
        :rtype: str
        """
        return self._key_file

    @key_file.setter
    def key_file(self, key_file):
        """Sets the key_file of this TLSConfig.

        The client key file for the targets.  # noqa: E501

        :param key_file: The key_file of this TLSConfig.  # noqa: E501
        :type: str
        """

        self._key_file = key_file

    @property
    def server_name(self):
        """Gets the server_name of this TLSConfig.  # noqa: E501

        Used to verify the hostname for the targets.  # noqa: E501

        :return: The server_name of this TLSConfig.  # noqa: E501
        :rtype: str
        """
        return self._server_name

    @server_name.setter
    def server_name(self, server_name):
        """Sets the server_name of this TLSConfig.

        Used to verify the hostname for the targets.  # noqa: E501

        :param server_name: The server_name of this TLSConfig.  # noqa: E501
        :type: str
        """

        self._server_name = server_name

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
        if issubclass(TLSConfig, dict):
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
        if not isinstance(other, TLSConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TLSConfig):
            return True

        return self.to_dict() != other.to_dict()
