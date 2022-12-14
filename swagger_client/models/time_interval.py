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


class TimeInterval(object):
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
        'days_of_month': 'list[DayOfMonthRange]',
        'months': 'list[MonthRange]',
        'times': 'list[TimeRange]',
        'weekdays': 'list[WeekdayRange]',
        'years': 'list[YearRange]'
    }

    attribute_map = {
        'days_of_month': 'days_of_month',
        'months': 'months',
        'times': 'times',
        'weekdays': 'weekdays',
        'years': 'years'
    }

    def __init__(self, days_of_month=None, months=None, times=None, weekdays=None, years=None, _configuration=None):  # noqa: E501
        """TimeInterval - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._days_of_month = None
        self._months = None
        self._times = None
        self._weekdays = None
        self._years = None
        self.discriminator = None

        if days_of_month is not None:
            self.days_of_month = days_of_month
        if months is not None:
            self.months = months
        if times is not None:
            self.times = times
        if weekdays is not None:
            self.weekdays = weekdays
        if years is not None:
            self.years = years

    @property
    def days_of_month(self):
        """Gets the days_of_month of this TimeInterval.  # noqa: E501


        :return: The days_of_month of this TimeInterval.  # noqa: E501
        :rtype: list[DayOfMonthRange]
        """
        return self._days_of_month

    @days_of_month.setter
    def days_of_month(self, days_of_month):
        """Sets the days_of_month of this TimeInterval.


        :param days_of_month: The days_of_month of this TimeInterval.  # noqa: E501
        :type: list[DayOfMonthRange]
        """

        self._days_of_month = days_of_month

    @property
    def months(self):
        """Gets the months of this TimeInterval.  # noqa: E501


        :return: The months of this TimeInterval.  # noqa: E501
        :rtype: list[MonthRange]
        """
        return self._months

    @months.setter
    def months(self, months):
        """Sets the months of this TimeInterval.


        :param months: The months of this TimeInterval.  # noqa: E501
        :type: list[MonthRange]
        """

        self._months = months

    @property
    def times(self):
        """Gets the times of this TimeInterval.  # noqa: E501


        :return: The times of this TimeInterval.  # noqa: E501
        :rtype: list[TimeRange]
        """
        return self._times

    @times.setter
    def times(self, times):
        """Sets the times of this TimeInterval.


        :param times: The times of this TimeInterval.  # noqa: E501
        :type: list[TimeRange]
        """

        self._times = times

    @property
    def weekdays(self):
        """Gets the weekdays of this TimeInterval.  # noqa: E501


        :return: The weekdays of this TimeInterval.  # noqa: E501
        :rtype: list[WeekdayRange]
        """
        return self._weekdays

    @weekdays.setter
    def weekdays(self, weekdays):
        """Sets the weekdays of this TimeInterval.


        :param weekdays: The weekdays of this TimeInterval.  # noqa: E501
        :type: list[WeekdayRange]
        """

        self._weekdays = weekdays

    @property
    def years(self):
        """Gets the years of this TimeInterval.  # noqa: E501


        :return: The years of this TimeInterval.  # noqa: E501
        :rtype: list[YearRange]
        """
        return self._years

    @years.setter
    def years(self, years):
        """Sets the years of this TimeInterval.


        :param years: The years of this TimeInterval.  # noqa: E501
        :type: list[YearRange]
        """

        self._years = years

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
        if issubclass(TimeInterval, dict):
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
        if not isinstance(other, TimeInterval):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, TimeInterval):
            return True

        return self.to_dict() != other.to_dict()
