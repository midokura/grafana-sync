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


class OpsGenieConfig(object):
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
        'actions': 'str',
        'api_key': 'Secret',
        'api_key_file': 'str',
        'api_url': 'URL',
        'description': 'str',
        'details': 'dict(str, str)',
        'entity': 'str',
        'http_config': 'HTTPClientConfig',
        'message': 'str',
        'note': 'str',
        'priority': 'str',
        'responders': 'list[OpsGenieConfigResponder]',
        'send_resolved': 'bool',
        'source': 'str',
        'tags': 'str',
        'update_alerts': 'bool'
    }

    attribute_map = {
        'actions': 'actions',
        'api_key': 'api_key',
        'api_key_file': 'api_key_file',
        'api_url': 'api_url',
        'description': 'description',
        'details': 'details',
        'entity': 'entity',
        'http_config': 'http_config',
        'message': 'message',
        'note': 'note',
        'priority': 'priority',
        'responders': 'responders',
        'send_resolved': 'send_resolved',
        'source': 'source',
        'tags': 'tags',
        'update_alerts': 'update_alerts'
    }

    def __init__(self, actions=None, api_key=None, api_key_file=None, api_url=None, description=None, details=None, entity=None, http_config=None, message=None, note=None, priority=None, responders=None, send_resolved=None, source=None, tags=None, update_alerts=None, _configuration=None):  # noqa: E501
        """OpsGenieConfig - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._actions = None
        self._api_key = None
        self._api_key_file = None
        self._api_url = None
        self._description = None
        self._details = None
        self._entity = None
        self._http_config = None
        self._message = None
        self._note = None
        self._priority = None
        self._responders = None
        self._send_resolved = None
        self._source = None
        self._tags = None
        self._update_alerts = None
        self.discriminator = None

        if actions is not None:
            self.actions = actions
        if api_key is not None:
            self.api_key = api_key
        if api_key_file is not None:
            self.api_key_file = api_key_file
        if api_url is not None:
            self.api_url = api_url
        if description is not None:
            self.description = description
        if details is not None:
            self.details = details
        if entity is not None:
            self.entity = entity
        if http_config is not None:
            self.http_config = http_config
        if message is not None:
            self.message = message
        if note is not None:
            self.note = note
        if priority is not None:
            self.priority = priority
        if responders is not None:
            self.responders = responders
        if send_resolved is not None:
            self.send_resolved = send_resolved
        if source is not None:
            self.source = source
        if tags is not None:
            self.tags = tags
        if update_alerts is not None:
            self.update_alerts = update_alerts

    @property
    def actions(self):
        """Gets the actions of this OpsGenieConfig.  # noqa: E501


        :return: The actions of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._actions

    @actions.setter
    def actions(self, actions):
        """Sets the actions of this OpsGenieConfig.


        :param actions: The actions of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._actions = actions

    @property
    def api_key(self):
        """Gets the api_key of this OpsGenieConfig.  # noqa: E501


        :return: The api_key of this OpsGenieConfig.  # noqa: E501
        :rtype: Secret
        """
        return self._api_key

    @api_key.setter
    def api_key(self, api_key):
        """Sets the api_key of this OpsGenieConfig.


        :param api_key: The api_key of this OpsGenieConfig.  # noqa: E501
        :type: Secret
        """

        self._api_key = api_key

    @property
    def api_key_file(self):
        """Gets the api_key_file of this OpsGenieConfig.  # noqa: E501


        :return: The api_key_file of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._api_key_file

    @api_key_file.setter
    def api_key_file(self, api_key_file):
        """Sets the api_key_file of this OpsGenieConfig.


        :param api_key_file: The api_key_file of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._api_key_file = api_key_file

    @property
    def api_url(self):
        """Gets the api_url of this OpsGenieConfig.  # noqa: E501


        :return: The api_url of this OpsGenieConfig.  # noqa: E501
        :rtype: URL
        """
        return self._api_url

    @api_url.setter
    def api_url(self, api_url):
        """Sets the api_url of this OpsGenieConfig.


        :param api_url: The api_url of this OpsGenieConfig.  # noqa: E501
        :type: URL
        """

        self._api_url = api_url

    @property
    def description(self):
        """Gets the description of this OpsGenieConfig.  # noqa: E501


        :return: The description of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this OpsGenieConfig.


        :param description: The description of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def details(self):
        """Gets the details of this OpsGenieConfig.  # noqa: E501


        :return: The details of this OpsGenieConfig.  # noqa: E501
        :rtype: dict(str, str)
        """
        return self._details

    @details.setter
    def details(self, details):
        """Sets the details of this OpsGenieConfig.


        :param details: The details of this OpsGenieConfig.  # noqa: E501
        :type: dict(str, str)
        """

        self._details = details

    @property
    def entity(self):
        """Gets the entity of this OpsGenieConfig.  # noqa: E501


        :return: The entity of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._entity

    @entity.setter
    def entity(self, entity):
        """Sets the entity of this OpsGenieConfig.


        :param entity: The entity of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._entity = entity

    @property
    def http_config(self):
        """Gets the http_config of this OpsGenieConfig.  # noqa: E501


        :return: The http_config of this OpsGenieConfig.  # noqa: E501
        :rtype: HTTPClientConfig
        """
        return self._http_config

    @http_config.setter
    def http_config(self, http_config):
        """Sets the http_config of this OpsGenieConfig.


        :param http_config: The http_config of this OpsGenieConfig.  # noqa: E501
        :type: HTTPClientConfig
        """

        self._http_config = http_config

    @property
    def message(self):
        """Gets the message of this OpsGenieConfig.  # noqa: E501


        :return: The message of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """Sets the message of this OpsGenieConfig.


        :param message: The message of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._message = message

    @property
    def note(self):
        """Gets the note of this OpsGenieConfig.  # noqa: E501


        :return: The note of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._note

    @note.setter
    def note(self, note):
        """Sets the note of this OpsGenieConfig.


        :param note: The note of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._note = note

    @property
    def priority(self):
        """Gets the priority of this OpsGenieConfig.  # noqa: E501


        :return: The priority of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._priority

    @priority.setter
    def priority(self, priority):
        """Sets the priority of this OpsGenieConfig.


        :param priority: The priority of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._priority = priority

    @property
    def responders(self):
        """Gets the responders of this OpsGenieConfig.  # noqa: E501


        :return: The responders of this OpsGenieConfig.  # noqa: E501
        :rtype: list[OpsGenieConfigResponder]
        """
        return self._responders

    @responders.setter
    def responders(self, responders):
        """Sets the responders of this OpsGenieConfig.


        :param responders: The responders of this OpsGenieConfig.  # noqa: E501
        :type: list[OpsGenieConfigResponder]
        """

        self._responders = responders

    @property
    def send_resolved(self):
        """Gets the send_resolved of this OpsGenieConfig.  # noqa: E501


        :return: The send_resolved of this OpsGenieConfig.  # noqa: E501
        :rtype: bool
        """
        return self._send_resolved

    @send_resolved.setter
    def send_resolved(self, send_resolved):
        """Sets the send_resolved of this OpsGenieConfig.


        :param send_resolved: The send_resolved of this OpsGenieConfig.  # noqa: E501
        :type: bool
        """

        self._send_resolved = send_resolved

    @property
    def source(self):
        """Gets the source of this OpsGenieConfig.  # noqa: E501


        :return: The source of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._source

    @source.setter
    def source(self, source):
        """Sets the source of this OpsGenieConfig.


        :param source: The source of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._source = source

    @property
    def tags(self):
        """Gets the tags of this OpsGenieConfig.  # noqa: E501


        :return: The tags of this OpsGenieConfig.  # noqa: E501
        :rtype: str
        """
        return self._tags

    @tags.setter
    def tags(self, tags):
        """Sets the tags of this OpsGenieConfig.


        :param tags: The tags of this OpsGenieConfig.  # noqa: E501
        :type: str
        """

        self._tags = tags

    @property
    def update_alerts(self):
        """Gets the update_alerts of this OpsGenieConfig.  # noqa: E501


        :return: The update_alerts of this OpsGenieConfig.  # noqa: E501
        :rtype: bool
        """
        return self._update_alerts

    @update_alerts.setter
    def update_alerts(self, update_alerts):
        """Sets the update_alerts of this OpsGenieConfig.


        :param update_alerts: The update_alerts of this OpsGenieConfig.  # noqa: E501
        :type: bool
        """

        self._update_alerts = update_alerts

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
        if issubclass(OpsGenieConfig, dict):
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
        if not isinstance(other, OpsGenieConfig):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, OpsGenieConfig):
            return True

        return self.to_dict() != other.to_dict()
