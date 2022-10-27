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


class AlertTestResult(object):
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
        'condition_evals': 'str',
        'error': 'str',
        'firing': 'bool',
        'logs': 'list[AlertTestResultLog]',
        'matches': 'list[EvalMatch]',
        'state': 'AlertStateType',
        'time_ms': 'str'
    }

    attribute_map = {
        'condition_evals': 'conditionEvals',
        'error': 'error',
        'firing': 'firing',
        'logs': 'logs',
        'matches': 'matches',
        'state': 'state',
        'time_ms': 'timeMs'
    }

    def __init__(self, condition_evals=None, error=None, firing=None, logs=None, matches=None, state=None, time_ms=None, _configuration=None):  # noqa: E501
        """AlertTestResult - a model defined in Swagger"""  # noqa: E501
        if _configuration is None:
            _configuration = Configuration()
        self._configuration = _configuration

        self._condition_evals = None
        self._error = None
        self._firing = None
        self._logs = None
        self._matches = None
        self._state = None
        self._time_ms = None
        self.discriminator = None

        if condition_evals is not None:
            self.condition_evals = condition_evals
        if error is not None:
            self.error = error
        if firing is not None:
            self.firing = firing
        if logs is not None:
            self.logs = logs
        if matches is not None:
            self.matches = matches
        if state is not None:
            self.state = state
        if time_ms is not None:
            self.time_ms = time_ms

    @property
    def condition_evals(self):
        """Gets the condition_evals of this AlertTestResult.  # noqa: E501


        :return: The condition_evals of this AlertTestResult.  # noqa: E501
        :rtype: str
        """
        return self._condition_evals

    @condition_evals.setter
    def condition_evals(self, condition_evals):
        """Sets the condition_evals of this AlertTestResult.


        :param condition_evals: The condition_evals of this AlertTestResult.  # noqa: E501
        :type: str
        """

        self._condition_evals = condition_evals

    @property
    def error(self):
        """Gets the error of this AlertTestResult.  # noqa: E501


        :return: The error of this AlertTestResult.  # noqa: E501
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error):
        """Sets the error of this AlertTestResult.


        :param error: The error of this AlertTestResult.  # noqa: E501
        :type: str
        """

        self._error = error

    @property
    def firing(self):
        """Gets the firing of this AlertTestResult.  # noqa: E501


        :return: The firing of this AlertTestResult.  # noqa: E501
        :rtype: bool
        """
        return self._firing

    @firing.setter
    def firing(self, firing):
        """Sets the firing of this AlertTestResult.


        :param firing: The firing of this AlertTestResult.  # noqa: E501
        :type: bool
        """

        self._firing = firing

    @property
    def logs(self):
        """Gets the logs of this AlertTestResult.  # noqa: E501


        :return: The logs of this AlertTestResult.  # noqa: E501
        :rtype: list[AlertTestResultLog]
        """
        return self._logs

    @logs.setter
    def logs(self, logs):
        """Sets the logs of this AlertTestResult.


        :param logs: The logs of this AlertTestResult.  # noqa: E501
        :type: list[AlertTestResultLog]
        """

        self._logs = logs

    @property
    def matches(self):
        """Gets the matches of this AlertTestResult.  # noqa: E501


        :return: The matches of this AlertTestResult.  # noqa: E501
        :rtype: list[EvalMatch]
        """
        return self._matches

    @matches.setter
    def matches(self, matches):
        """Sets the matches of this AlertTestResult.


        :param matches: The matches of this AlertTestResult.  # noqa: E501
        :type: list[EvalMatch]
        """

        self._matches = matches

    @property
    def state(self):
        """Gets the state of this AlertTestResult.  # noqa: E501


        :return: The state of this AlertTestResult.  # noqa: E501
        :rtype: AlertStateType
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this AlertTestResult.


        :param state: The state of this AlertTestResult.  # noqa: E501
        :type: AlertStateType
        """

        self._state = state

    @property
    def time_ms(self):
        """Gets the time_ms of this AlertTestResult.  # noqa: E501


        :return: The time_ms of this AlertTestResult.  # noqa: E501
        :rtype: str
        """
        return self._time_ms

    @time_ms.setter
    def time_ms(self, time_ms):
        """Sets the time_ms of this AlertTestResult.


        :param time_ms: The time_ms of this AlertTestResult.  # noqa: E501
        :type: str
        """

        self._time_ms = time_ms

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
        if issubclass(AlertTestResult, dict):
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
        if not isinstance(other, AlertTestResult):
            return False

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        if not isinstance(other, AlertTestResult):
            return True

        return self.to_dict() != other.to_dict()
