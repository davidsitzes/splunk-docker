# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import logging
import collections
# from datetime import datetime
from splunk.appserver.mrsparkle.lib import i18n
from splunk.util import normalizeBoolean

from ITOA.setup_logging import setup_logging

class ParseArgs(object):
    '''
        Class to parse search parameters
    '''

    @staticmethod
    def get_params(args):
        '''
        Parse search arguments and return dict and error_msg of search params
        :param: list of system arguments pass to scripts
        :return: tuple of search params, error message
        :rtype: type (dict,string)
        '''
        i = 0
        params = {}
        error_msg = None

        while i < len(args):
            arg = args[i]
            if arg.find('is_consecutive') != -1 or arg.find('count') or arg.find('suppression_period') or arg.find(
                    'health_compute_interval') or arg.find('debug'):
                values = arg.split("=")
                if len(values) != 2:
                    error_msg = _("Invalid argument '%s'.") % arg
                    break
                key = values[0].strip()
                value = values[1].strip()
                if value is None or value == "":
                    error_msg = _("Invalid argument value '%s', it should be a valid value.") % arg
                    break
                if key == 'is_consecutive' or key == 'debug':
                    params[key] = normalizeBoolean(value)
                else:
                    # make sure other integer value is non-zero value
                    if float(value) == 0:
                        error_msg = _("Invalid argument value '%s', it should not be non-zero value.") % arg
                        break
                    params[key] = float(value)
            else:
                error_msg = _("Invalid argument '%s'.") % arg
                break
            i += 1
        return params, error_msg


class CustomSuppressAlert(object):
    '''
        Check for suppression criteria
        Note: Before using this class make sure the following thing
            - events should pass to "process_result" function in chronological order (increasing time order)
            - make sure _time field exist and values for this field should in sec
    '''

    def __init__(self, params):
        '''
        Initialize class
        :param params: dict for suppression criteria
        :return:
        '''
        level = logging.DEBUG if params.get('debug') is not None else logging.WARN
        self.logger = setup_logging("itsi_searches.log", "itsi.command.suppressalert", level=level,
                                    is_console_header=True)
        self.logger.info("Staring suppression command ...")
        self.is_consecutive = params.get('is_consecutive')
        self.count = params.get('count')
        self.suppression_period = params.get('suppression_period')
        self.health_compute_interval = params.get('health_compute_interval', 1)  # default is 1 minute interval
        self.de_queue = collections.deque()
        self.initial_event = True
        self.last_event_time = None
        self.is_generate_alert = False
        # We are capturing the latest or earliest alert in the window (depending on chronological order direction)
        self.persisted_data = {}

    def _get_time_diff(self, time1, time2):
        '''
        Get time different between time2 - time 1
        :param time1: string|int
        :param time2: string|int
        :return:
        '''
        self.logger.debug("Getting time difference between %s and %s", time1, time2)
        return float(time2) - float(time1)

    def process_result(self, event):
        '''
        Processing events in streaming manner
        Note: Before using this function make sure the following thing
            - events should pass to "process_result" function in chronological order
            - make sure _time field exist and values for this fields should in sec
        :param event:
        :return:
        '''
        self.logger.debug("Processing event='%s'", event)
        self.de_queue.append(event)
        # Compare second pass onwards
        if not self.initial_event:
            if self.is_consecutive:
                # Add some buffer 10%
                if self._get_time_diff(self.last_event_time,
                                       event.get('_time')) > self.health_compute_interval * 60 * 1.1:
                    # event was not consecutive
                    self.logger.debug("Found non consecutive, last_event_time=%s new event time=%s",
                                      self.last_event_time,
                                      event.get('_time'))
                    # Remove all
                    self.de_queue.clear()
                    # Have only current one the queue
                    self.de_queue.append(event)
            else:
                while len(self.de_queue) != 0:
                    element = self.de_queue.popleft()
                    if self._get_time_diff(element.get('_time'),
                                           event.get('_time')) > self.suppression_period * 60:
                        # Keep removing all element which is outside suppress period
                        continue
                    else:
                        # re-add
                        self.de_queue.appendleft(element)
                        break

        if len(self.de_queue) >= self.count:
            actual_count = len(self.de_queue)
            self.logger.info(
                "Suppression criteria is met, processed events count=%s, threshold count=%s, is_consecutive=%s, suppression_period=%s",
                actual_count, self.count, self.is_consecutive, self.suppression_period)
            self.logger.debug("All events with in given time window, events='%s'", self.de_queue)
            # met suppress criteria
            self.is_generate_alert = True
            # We are capturing the latest or earliest alert in the window (depending on chronological order direction)
            # to get basic alert information like composite id
            self.persisted_data = event
            if self.is_consecutive:
                self.persisted_data[
                    'event_description'] = '{0} has {1} status (health score {2}) more than {3} times for last {4} minutes'.format(
                    event.get('composite_kpi_name'), event.get('severity_label'), event.get('health_score'),
                    int(self.count), int(self.count))
            else:
                self.persisted_data[
                    'event_description'] = '{0} has {1} status (health score {2}) more than {3} times for last {4} minutes'.format(
                    event.get('composite_kpi_name'), event.get('severity_label'), event.get('health_score'),
                    int(actual_count), int(self.suppression_period))
        else:
            self.logger.debug("Suppression criteria did not meet, queue count:%s, threshold count:%s",
                              len(self.de_queue), self.count)
        # Add time for next reference
        self.last_event_time = event.get('_time')
        if self.initial_event:
            self.initial_event = False

    def get_alerts(self):
        '''
        Call this function once process_result process all events
        :return: list of event, if suppression criteria met
        '''
        if self.is_generate_alert:
            return [self.persisted_data]
        else:
            return []
