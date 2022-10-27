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


class ConfigDTO(object):
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
        'created': 'datetime',
        'dashboard_id': 'int',
        'dashboard_name': 'str',
        'dashboard_uid': 'str',
        'dashboards': 'list[DashboardDTO]',
        'enable_csv': 'bool',
        'enable_dashboard_url': 'bool',
        'formats': 'list[Type]',
        'id': 'int',
        'message': 'str',
        'name': 'str',
        'options': 'ReportOptionsDTO',
        'org_id': 'int',
        'recipients': 'str',
        'reply_to': 'str',
        'schedule': 'ScheduleDTO',
        'state': 'State',
        'template_vars': 'object',
        'updated': 'datetime',
        'user_id': 'int'
    }

    attribute_map = {
        'created': 'created',
        'dashboard_id': 'dashboardId',
        'dashboard_name': 'dashboardName',
        'dashboard_uid': 'dashboardUid',
        'dashboards': 'dashboards',
        'enable_csv': 'enableCsv',
        'enable_dashboard_url': 'enableDashboardUrl',
        'formats': 'formats',
        'id': 'id',
        'message': 'message',
        'name': 'name',
        'options': 'options',
        'org_id': 'orgId',
        'recipients': 'recipients',
        'reply_to': 'replyTo',
        'schedule': 'schedule',
        'state': 'state',
        'template_vars': 'templateVars',
        'updated': 'updated',
        'user_id': 'userId'
    }

    def __init__(self, created=None, dashboard_id=None, dashboard_name=None, dashboard_uid=None, dashboards=None, enable_csv=None, enable_dashboard_url=None, formats=None, id=None, message=None, name=None, options=None, org_id=None, recipients=None, reply_to=None, schedule=None, state=None, template_vars=None, updated=None, user_id=None, _configuration=None):  # noqa: E501
        """ConfigDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._created = None
        self._dashboard_id = None
        self._dashboard_name = None
        self._dashboard_uid = None
        self._dashboards = None
        self._enable_csv = None
        self._enable_dashboard_url = None
        self._formats = None
        self._id = None
        self._message = None
        self._name = None
        self._options = None
        self._org_id = None
        self._recipients = None
        self._reply_to = None
        self._schedule = None
        self._state = None
        self._template_vars = None
        self._updated = None
        self._user_id = None
        self.discriminator = None

        if created is not None:
            self.created = created
        if dashboard_id is not None:
            self.dashboard_id = dashboard_id
        if dashboard_name is not None:
            self.dashboard_name = dashboard_name
        if dashboard_uid is not None:
            self.dashboard_uid = dashboard_uid
        if dashboards is not None:
            self.dashboards = dashboards
        if enable_csv is not None:
            self.enable_csv = enable_csv
        if enable_dashboard_url is not None:
            self.enable_dashboard_url = enable_dashboard_url
        if formats is not None:
            self.formats = formats
        if id is not None:
            self.id = id
        if message is not None:
            self.message = message
        if name is not None:
            self.name = name
        if options is not None:
            self.options = options
        if org_id is not None:
            self.org_id = org_id
        if recipients is not None:
            self.recipients = recipients
        if reply_to is not None:
            self.reply_to = reply_to
        if schedule is not None:
            self.schedule = schedule
        if state is not None:
            self.state = state
        if template_vars is not None:
            self.template_vars = template_vars
        if updated is not None:
            self.updated = updated
        if user_id is not None:
            self.user_id = user_id

    @property
    def created(self):
        """Gets the created of this ConfigDTO.  # noqa: E501


        :return: The created of this ConfigDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this ConfigDTO.


        :param created: The created of this ConfigDTO.  # noqa: E501
        :type: datetime
        """

        self._created = created

    @property
    def dashboard_id(self):
        """Gets the dashboard_id of this ConfigDTO.  # noqa: E501


        :return: The dashboard_id of this ConfigDTO.  # noqa: E501
        :rtype: int
        """
        return self._dashboard_id

    @dashboard_id.setter
    def dashboard_id(self, dashboard_id):
        """Sets the dashboard_id of this ConfigDTO.


        :param dashboard_id: The dashboard_id of this ConfigDTO.  # noqa: E501
        :type: int
        """

        self._dashboard_id = dashboard_id

    @property
    def dashboard_name(self):
        """Gets the dashboard_name of this ConfigDTO.  # noqa: E501


        :return: The dashboard_name of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._dashboard_name

    @dashboard_name.setter
    def dashboard_name(self, dashboard_name):
        """Sets the dashboard_name of this ConfigDTO.


        :param dashboard_name: The dashboard_name of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._dashboard_name = dashboard_name

    @property
    def dashboard_uid(self):
        """Gets the dashboard_uid of this ConfigDTO.  # noqa: E501


        :return: The dashboard_uid of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._dashboard_uid

    @dashboard_uid.setter
    def dashboard_uid(self, dashboard_uid):
        """Sets the dashboard_uid of this ConfigDTO.


        :param dashboard_uid: The dashboard_uid of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._dashboard_uid = dashboard_uid

    @property
    def dashboards(self):
        """Gets the dashboards of this ConfigDTO.  # noqa: E501


        :return: The dashboards of this ConfigDTO.  # noqa: E501
        :rtype: list[DashboardDTO]
        """
        return self._dashboards

    @dashboards.setter
    def dashboards(self, dashboards):
        """Sets the dashboards of this ConfigDTO.


        :param dashboards: The dashboards of this ConfigDTO.  # noqa: E501
        :type: list[DashboardDTO]
        """

        self._dashboards = dashboards

    @property
    def enable_csv(self):
        """Gets the enable_csv of this ConfigDTO.  # noqa: E501


        :return: The enable_csv of this ConfigDTO.  # noqa: E501
        :rtype: bool
        """
        return self._enable_csv

    @enable_csv.setter
    def enable_csv(self, enable_csv):
        """Sets the enable_csv of this ConfigDTO.


        :param enable_csv: The enable_csv of this ConfigDTO.  # noqa: E501
        :type: bool
        """

        self._enable_csv = enable_csv

    @property
    def enable_dashboard_url(self):
        """Gets the enable_dashboard_url of this ConfigDTO.  # noqa: E501


        :return: The enable_dashboard_url of this ConfigDTO.  # noqa: E501
        :rtype: bool
        """
        return self._enable_dashboard_url

    @enable_dashboard_url.setter
    def enable_dashboard_url(self, enable_dashboard_url):
        """Sets the enable_dashboard_url of this ConfigDTO.


        :param enable_dashboard_url: The enable_dashboard_url of this ConfigDTO.  # noqa: E501
        :type: bool
        """

        self._enable_dashboard_url = enable_dashboard_url

    @property
    def formats(self):
        """Gets the formats of this ConfigDTO.  # noqa: E501


        :return: The formats of this ConfigDTO.  # noqa: E501
        :rtype: list[Type]
        """
        return self._formats

    @formats.setter
    def formats(self, formats):
        """Sets the formats of this ConfigDTO.


        :param formats: The formats of this ConfigDTO.  # noqa: E501
        :type: list[Type]
        """

        self._formats = formats

    @property
    def id(self):
        """Gets the id of this ConfigDTO.  # noqa: E501


        :return: The id of this ConfigDTO.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ConfigDTO.


        :param id: The id of this ConfigDTO.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def message(self):
        """Gets the message of this ConfigDTO.  # noqa: E501


        :return: The message of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """Sets the message of this ConfigDTO.


        :param message: The message of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._message = message

    @property
    def name(self):
        """Gets the name of this ConfigDTO.  # noqa: E501


        :return: The name of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this ConfigDTO.


        :param name: The name of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def options(self):
        """Gets the options of this ConfigDTO.  # noqa: E501


        :return: The options of this ConfigDTO.  # noqa: E501
        :rtype: ReportOptionsDTO
        """
        return self._options

    @options.setter
    def options(self, options):
        """Sets the options of this ConfigDTO.


        :param options: The options of this ConfigDTO.  # noqa: E501
        :type: ReportOptionsDTO
        """

        self._options = options

    @property
    def org_id(self):
        """Gets the org_id of this ConfigDTO.  # noqa: E501


        :return: The org_id of this ConfigDTO.  # noqa: E501
        :rtype: int
        """
        return self._org_id

    @org_id.setter
    def org_id(self, org_id):
        """Sets the org_id of this ConfigDTO.


        :param org_id: The org_id of this ConfigDTO.  # noqa: E501
        :type: int
        """

        self._org_id = org_id

    @property
    def recipients(self):
        """Gets the recipients of this ConfigDTO.  # noqa: E501


        :return: The recipients of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._recipients

    @recipients.setter
    def recipients(self, recipients):
        """Sets the recipients of this ConfigDTO.


        :param recipients: The recipients of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._recipients = recipients

    @property
    def reply_to(self):
        """Gets the reply_to of this ConfigDTO.  # noqa: E501


        :return: The reply_to of this ConfigDTO.  # noqa: E501
        :rtype: str
        """
        return self._reply_to

    @reply_to.setter
    def reply_to(self, reply_to):
        """Sets the reply_to of this ConfigDTO.


        :param reply_to: The reply_to of this ConfigDTO.  # noqa: E501
        :type: str
        """

        self._reply_to = reply_to

    @property
    def schedule(self):
        """Gets the schedule of this ConfigDTO.  # noqa: E501


        :return: The schedule of this ConfigDTO.  # noqa: E501
        :rtype: ScheduleDTO
        """
        return self._schedule

    @schedule.setter
    def schedule(self, schedule):
        """Sets the schedule of this ConfigDTO.


        :param schedule: The schedule of this ConfigDTO.  # noqa: E501
        :type: ScheduleDTO
        """

        self._schedule = schedule

    @property
    def state(self):
        """Gets the state of this ConfigDTO.  # noqa: E501


        :return: The state of this ConfigDTO.  # noqa: E501
        :rtype: State
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this ConfigDTO.


        :param state: The state of this ConfigDTO.  # noqa: E501
        :type: State
        """

        self._state = state

    @property
    def template_vars(self):
        """Gets the template_vars of this ConfigDTO.  # noqa: E501


        :return: The template_vars of this ConfigDTO.  # noqa: E501
        :rtype: object
        """
        return self._template_vars

    @template_vars.setter
    def template_vars(self, template_vars):
        """Sets the template_vars of this ConfigDTO.


        :param template_vars: The template_vars of this ConfigDTO.  # noqa: E501
        :type: object
        """

        self._template_vars = template_vars

    @property
    def updated(self):
        """Gets the updated of this ConfigDTO.  # noqa: E501


        :return: The updated of this ConfigDTO.  # noqa: E501
        :rtype: datetime
        """
        return self._updated

    @updated.setter
    def updated(self, updated):
        """Sets the updated of this ConfigDTO.


        :param updated: The updated of this ConfigDTO.  # noqa: E501
        :type: datetime
        """

        self._updated = updated

    @property
    def user_id(self):
        """Gets the user_id of this ConfigDTO.  # noqa: E501


        :return: The user_id of this ConfigDTO.  # noqa: E501
        :rtype: int
        """
        return self._user_id

    @user_id.setter
    def user_id(self, user_id):
        """Sets the user_id of this ConfigDTO.


        :param user_id: The user_id of this ConfigDTO.  # noqa: E501
        :type: int
        """

        self._user_id = user_id

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
        if issubclass(ConfigDTO, dict):
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
        if not isinstance(other, ConfigDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, ConfigDTO):
            return True

        return self.to_dict() != other.to_dict()
