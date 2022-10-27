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


class DashboardDTO(object):
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
        'dashboard': 'DashboardReportDTO',
        'report_variables': 'object',
        'time_range': 'TimeRangeDTO'
    }

    attribute_map = {
        'dashboard': 'dashboard',
        'report_variables': 'reportVariables',
        'time_range': 'timeRange'
    }

    def __init__(self, dashboard=None, report_variables=None, time_range=None, _configuration=None):  # noqa: E501
        """DashboardDTO - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._dashboard = None
        self._report_variables = None
        self._time_range = None
        self.discriminator = None

        if dashboard is not None:
            self.dashboard = dashboard
        if report_variables is not None:
            self.report_variables = report_variables
        if time_range is not None:
            self.time_range = time_range

    @property
    def dashboard(self):
        """Gets the dashboard of this DashboardDTO.  # noqa: E501


        :return: The dashboard of this DashboardDTO.  # noqa: E501
        :rtype: DashboardReportDTO
        """
        return self._dashboard

    @dashboard.setter
    def dashboard(self, dashboard):
        """Sets the dashboard of this DashboardDTO.


        :param dashboard: The dashboard of this DashboardDTO.  # noqa: E501
        :type: DashboardReportDTO
        """

        self._dashboard = dashboard

    @property
    def report_variables(self):
        """Gets the report_variables of this DashboardDTO.  # noqa: E501


        :return: The report_variables of this DashboardDTO.  # noqa: E501
        :rtype: object
        """
        return self._report_variables

    @report_variables.setter
    def report_variables(self, report_variables):
        """Sets the report_variables of this DashboardDTO.


        :param report_variables: The report_variables of this DashboardDTO.  # noqa: E501
        :type: object
        """

        self._report_variables = report_variables

    @property
    def time_range(self):
        """Gets the time_range of this DashboardDTO.  # noqa: E501


        :return: The time_range of this DashboardDTO.  # noqa: E501
        :rtype: TimeRangeDTO
        """
        return self._time_range

    @time_range.setter
    def time_range(self, time_range):
        """Sets the time_range of this DashboardDTO.


        :param time_range: The time_range of this DashboardDTO.  # noqa: E501
        :type: TimeRangeDTO
        """

        self._time_range = time_range

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
        if issubclass(DashboardDTO, dict):
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
        if not isinstance(other, DashboardDTO):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, DashboardDTO):
            return True

        return self.to_dict() != other.to_dict()
