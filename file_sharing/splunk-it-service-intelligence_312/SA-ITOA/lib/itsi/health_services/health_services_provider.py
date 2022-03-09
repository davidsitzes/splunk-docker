# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys

from splunk.appserver.mrsparkle.lib import i18n
from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.searches.compute_health_score import ScoreCalculation, ThresholdSettings
from ITOA.setup_logging import setup_logging

logger = setup_logging ("itsi_health_service_provider.log", "itsi.controllers.health_services")

class Provider(object):
    """
    Health Score Provider Base Class
    """
    SEVERITY_NAME = 'severity_name'
    SEVERITY_LEVEL = 'severity_level'
    URGENCY = 'urgency'
    HEALTH_SCORE = 'health_score'
    HEALTH_SEVERITY_COLOR = 'health_severity_color'
    HEALTH_SEVERITY = 'health_severity_name'
    HEALTH_MIN = 'health_min'
    HEALTH_MAX = 'health_max'
    HEALTH_IS_MIN_INCLUDED = 'health_min_included'
    HEALTH_IS_MAX_INCLUDED = 'health_max_included'

    def __init__(self, session_key, logger_=None):
        """
        A provider for different health calculated related function
        @param {string} session_key:  session_key
        @return:
        """
        self.session_key = session_key
        self.output = self._get_output_object()
        self.threshold_settings = {}
        self.logger = logger_ if logger_ else logger
        self._get_threshold_settings()

    def _get_output_object(self):
        """
        Response json
        @return: json object
        """
        output = jsonresponse.JsonResponse()
        output.success = False
        output.data = {}
        return output

    def _add_error_msg(self, msg):
        """
        Add error msg
        @@param msg - message
        """
        self.output.addError(msg)

    def _get_threshold_settings(self):
        """
        Get threshold setting from conf file
        @return: None
        """
        try:
            data = ThresholdSettings.get_thresholds_weight(self.session_key)
            if len(data) > 0:
                self.threshold_settings = data
            else:
                self._add_error_msg("Failed to read threshold_labels.conf file")
        except Exception as e:
            self.logger.exception(e)
            self._add_error_msg(e.message)

    def _basic_severity_list_check(self, data):
        """
        Perform check on given inputs for health calculation inputs
        @param data: item of the list
        @return: a tuple (is_success flag, message if it is failed)
        """
        is_success = True
        msg = None
        if data.get(self.SEVERITY_LEVEL) is None and data.get(self.SEVERITY_NAME) is None:
            is_success = False
            msg = _("{0} or {1} one of field needs to be provided.").format(self.SEVERITY_NAME, self.SEVERITY_LEVEL)
        if data.get(self.URGENCY) is None:
            is_success = False
            msg = _("{0} field is required in each field.").format(self.URGENCY)

        return is_success, msg

    def get_severity_info(self, level=None, name=None):
        """
        Get severity level or name by providing either of one thing
        @param {int} level: severity level
        @param {string} name: severity name
        @return:
        """
        for key, data in self.threshold_settings.iteritems():
            if level is not None and data.level == level:
                return key
            if name is not None and key == name:
                return data.level

    def calculate_score(self, list_severity_importance):
        """
        Calculate health score for given list which has each item
            severity_name or severity_level -- one of these fields or both
            urgency -- importance/urgency
        @param {list} list_severity_importance: List of item pass to calculate health
        @return: Calculated health score
        """
        for data in list_severity_importance:
            is_success, msg = self._basic_severity_list_check(data)
            if is_success:
                # covert to float
                if data.get(self.SEVERITY_LEVEL):
                    data[self.SEVERITY_LEVEL] = float(data.get(self.SEVERITY_LEVEL))

                if data.get(self.SEVERITY_NAME) is None:
                    data[self.SEVERITY_NAME] = self.get_severity_info(level=data.get(self.SEVERITY_LEVEL))
                if data.get(self.SEVERITY_LEVEL) is None:
                    data[self.SEVERITY_LEVEL] = self.get_severity_info(name=data.get(self.SEVERITY_NAME))

                data[self.URGENCY] = float(data.get(self.URGENCY))
            else:
                self._add_error_msg(msg)
                return self.output

        # get score now
        score = ScoreCalculation.calculate_score(list_severity_importance,
                                                 self.threshold_settings,
                                                 self.SEVERITY_LEVEL,
                                                 self.SEVERITY_NAME,
                                                 self.URGENCY)

        self.logger.debug("Final score=%s", score)
        self.output.data[self.HEALTH_SCORE] = score
        severity, color, level = ScoreCalculation.get_health_severity(score, self.threshold_settings)
        self.output.data[self.HEALTH_SEVERITY] = severity
        self.output.data[self.HEALTH_SEVERITY_COLOR] = color
        self.output.success = True
        return self.output

    def get_min_max_score_for_status(self, status):
        """
        Get health score min and max limit for given status
        @param {string} status: health severity name
        @return: a tuple of min and max health score
        """
        min, is_min_included, max, is_max_included = ScoreCalculation.get_health_min_max(status, self.threshold_settings)
        if min is None or max is None:
            self._add_error_msg(
                _("Failed to get minimum and maximum value of given status={0}. It may be an invalid status.").format(status))
        else:
            self.output.success = True
            self.output.data[self.HEALTH_MIN] = min
            self.output.data[self.HEALTH_IS_MIN_INCLUDED] = is_min_included
            self.output.data[self.HEALTH_MAX] = max
            self.output.data[self.HEALTH_IS_MAX_INCLUDED] = is_max_included

        return self.output

    def get_score_to_status(self, score):
        """
        For given score, it return status and color
        @param {int} score: score
        @return:
        """
        self.output.data[self.HEALTH_SCORE] = score
        severity, color, level = ScoreCalculation.get_health_severity(score, self.threshold_settings)
        self.output.data[self.HEALTH_SEVERITY] = severity
        self.output.data[self.HEALTH_SEVERITY_COLOR] = color
        self.output.success = True
        return self.output
