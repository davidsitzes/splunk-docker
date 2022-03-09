import logging
import json

import splunk.rest as rest

from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_conf_stanza


class EventFieldAnalyzer(object):
    """
        A class which defines rules for identifying fields with in an event as text field and categorical field
    """
    # Field Summary field names
    ACE_CONF_FILE_NAME = 'notable_event_correlation'

    ACE_EVENT_ANALYZER_STANZA_NAME = 'ace_field_analyzer'

    ACE_CONF_STANDARD_TEXT_KEY_NAME = 'text_field_names'
    ACE_CONF_IGNORE_FIELD_KEY_NAME = 'ignore_fields_that_contain'

    ACE_CONF_THRESHOLD_DISTINCT_VALUE_PERC_KEY_NAME = 'threshold_distinct_value_perc'
    ACE_CONF_MIN_DISTINCT_VALUE_PERC_KEY_NAME = 'min_distinct_value_perc'
    ACE_CONF_MAX_COUNT_PERC_KEY_NAME = 'max_count_perc'
    ACE_CONF_THRESHOLD_EVENT_COVERAGE_PERC_KEY_NAME = 'threshold_event_coverage_perc'

    FILED_SUMMARY_FIELD = 'field'
    FILED_SUMMARY_COUNT = 'count'
    FILED_SUMMARY_DISTINCT_COUNT = 'distinct_count'
    FILED_SUMMARY_VALUES = 'values'
    FILED_SUMMARY_EVENT_COVERAGE_PERC= 'event_coverage_perc'

    DEFAULT_THRESHOLD_DISTINCT_VALUE_PERC = 35
    DEFAULT_MIN_DISTINCT_VALUE_PERC = 10
    DEFAULT_MAX_COUNT_PERC = 80
    DEFAULT_THRESHOLD_EVENT_COVERAGE_PERC  = 10

    DEFAULT_STANDARD_TEXT_FIELD_NAMES = ['comment', 'description', 'summary', 'review', 'message']
    # Ignore fields that contain in their name any of the key words in this list
    # Key word "time" will ignore fields that represent time like alert_triggertime,alerttriggertime,lasttimeup, etc ...
    DEFAULT_IGNORE_FIELDS_THAT_CONTAIN = ['time']

    def __init__(self, read_results, settings, is_debug=False):
        """
        Initialize the class
        :param read_results: results provided by splunk search
        :param settings: settings provide by search
        :param is_debug: flag to set debug level for logs
        :return:
        """

        if is_debug:
            level = logging.DEBUG
        else:
            level = logging.WARN
        self.logger = setup_logging('itsi_searches.log', 'itsi.command.eventfieldtype', is_console_header=False,
                                    level=level)

        self.results = []
        self.settings = settings
        self.records = read_results
        self.output_fields = set()

        self.STANDARD_TEXT_FIELD_NAMES = self.standard_text_field_conf_values()
        self.FIELD_ANALYZER_THRESHOLDS = self.field_analyzer_conf_threshod_values()
        self.IGNORE_FIELDS = self.ignore_conf_fields()
        
    def standard_text_field_conf_values(self):
        stanze_value = self.get_conf_values(self.settings['sessionKey'], self.ACE_EVENT_ANALYZER_STANZA_NAME)
        if self.ACE_CONF_STANDARD_TEXT_KEY_NAME in stanze_value:
            std_text_fields = stanze_value[self.ACE_CONF_STANDARD_TEXT_KEY_NAME]
            words = std_text_fields.split(",")
            return words
        return self.DEFAULT_STANDARD_TEXT_FIELD_NAMES

    def field_analyzer_conf_threshod_values(self):
        threshold_values = {}
        stanze_value = self.get_conf_values(self.settings['sessionKey'],
                                            self.ACE_EVENT_ANALYZER_STANZA_NAME)
        if self.ACE_CONF_THRESHOLD_DISTINCT_VALUE_PERC_KEY_NAME in stanze_value:
            self.DEFAULT_THRESHOLD_DISTINCT_VALUE_PERC = \
                int(stanze_value[self.ACE_CONF_THRESHOLD_DISTINCT_VALUE_PERC_KEY_NAME])

        if self.ACE_CONF_MIN_DISTINCT_VALUE_PERC_KEY_NAME in stanze_value:
            self.DEFAULT_MIN_DISTINCT_VALUE_PERC = int(stanze_value[self.ACE_CONF_MIN_DISTINCT_VALUE_PERC_KEY_NAME])

        if self.ACE_CONF_MAX_COUNT_PERC_KEY_NAME in stanze_value:
            self.DEFAULT_MAX_COUNT_PERC = int(stanze_value[self.ACE_CONF_MAX_COUNT_PERC_KEY_NAME])

        if self.ACE_CONF_THRESHOLD_EVENT_COVERAGE_PERC_KEY_NAME in stanze_value:
            self.DEFAULT_THRESHOLD_EVENT_COVERAGE_PERC = \
                int(stanze_value[self.ACE_CONF_THRESHOLD_EVENT_COVERAGE_PERC_KEY_NAME])

        return threshold_values

    def ignore_conf_fields(self):
        stanze_value = self.get_conf_values(self.settings['sessionKey'], self.ACE_EVENT_ANALYZER_STANZA_NAME)
        if self.ACE_CONF_IGNORE_FIELD_KEY_NAME in stanze_value:
            ignore_fields = stanze_value[self.ACE_CONF_IGNORE_FIELD_KEY_NAME]
            words = ignore_fields.split(",")
            return words
        return self.DEFAULT_IGNORE_FIELDS_THAT_CONTAIN

    def get_conf_values(self, session_key, stanza_name):
        ret = get_conf_stanza(session_key, self.ACE_CONF_FILE_NAME, stanza_name, app='itsi')
        content = ret['content']
        json_content = json.loads(content)
        try:
            entry = json_content['entry']
            stanze_entry = entry[0]
            entry_content = stanze_entry['content']
            return entry_content
        except KeyError as e:
            self.logger.error('Error extracting config value for stanza_name %s, '
                              'hence setting default value%s', stanza_name)
            return None


    def get_output_fields(self):
        """
        Get the field names of the return result.
        Each element in the result array is dictionary of fixed set of
        fields representing field names of the return result.
        :return: Set of field names if result exists else empty set
        """
        if self.results:
            for k in self.results[-1].keys():
                self.output_fields.add(k)
        return self.output_fields

    def _add_to_results(self, result):
        """
        Add field analysis result to result set

        @type result: dict
        @param result: Result with fixed set of fields

        :return: None but add to the result set
        """
        self.results.append(result)

    def _build_result(self, field_name, field_type, distinct_count, event_coverage_perc, ignore):
        """
        Build the field analysis result
        @type field_name: basestring
        @param field_name: Name of the field

        @type field_type: basestring
        @param field_type: Type of the field (Text or Category)

        @type distinct_count: int
        @param distinct_count: Number of distinct field values

        @type event_coverage_perc: int
        @param event_coverage_perc: Percentage of events with valid value for field "field_name"

        @type ignore: boolean
        @param ignore: Annotate the field as ignore if set true

        @return: {dic}: Dictionary holding field analysis info
        """
        result = {
            'field': field_name,
            'type': field_type,
            'no_of_values': distinct_count,
            'event_coverage_perc': event_coverage_perc,
            'ignore': ignore
            }
        return result

    def field_with_one_distinct_value(self, record):
        """
        Check if the field has only one distinct value

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: {boolean} If the field have only one distinct_value in a set of events
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
        values = []
        try:
            values = json.loads(record.get(self.FILED_SUMMARY_VALUES))
        except Exception as e:
            self.logger.error('Could not properly load field summary values, with Exception: %s', e)

        if distinct_count == 2:
            is_empty = False
            for value in values:
                if value.get('value') == "\"\"" or value.get('value') == "\'\'" or value.get('value') == "":
                    is_empty = True
            if is_empty:
                result = self._build_result(field_name, None, None, None, True)
                self._add_to_results(result)
                return True
        return False

    def field_with_all_distinct_values(self, record):
        """
        Check if the field has unique value for each event

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: {boolean}
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        count = int(record.get(self.FILED_SUMMARY_COUNT))
        distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
        if count == distinct_count:
            result = self._build_result(field_name, None, None, None, True)
            self._add_to_results(result)
            return True
        return False

    def check_and_add_standard_text_field(self, record):
        """
        Check if the field name is one of the standard names that represent textual content

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: {boolean}
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        for text_field_name in self.STANDARD_TEXT_FIELD_NAMES:
            if text_field_name in str.lower(field_name):
                distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
                event_coverage_perc = record.get(self.FILED_SUMMARY_EVENT_COVERAGE_PERC)
                result = self._build_result(field_name, 'text', distinct_count, event_coverage_perc, False)
                self._add_to_results(result)
                return True
        return False

    def check_and_add_categorical_field(self, record):
        """
        Check if the field is categorical field

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: {boolean}
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        count = int(record.get(self.FILED_SUMMARY_COUNT))
        event_coverage_perc = record.get(self.FILED_SUMMARY_EVENT_COVERAGE_PERC)
        distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
        distinct_value_perc = round((distinct_count/float(count)) * 100, 2)

        if distinct_value_perc < self.DEFAULT_THRESHOLD_DISTINCT_VALUE_PERC:
            result = self._build_result(field_name, 'attribute', distinct_count, event_coverage_perc, False)
            self._add_to_results(result)
            return True
        else:
            values = []
            try:
                values = json.loads(record.get(self.FILED_SUMMARY_VALUES))
            except Exception as e:
                self.logger.error('Could not properly load field summary values, with Exception: %s', e)

            min_distinct_values = int((self.DEFAULT_MIN_DISTINCT_VALUE_PERC/100.0) * distinct_count)
            max_count = int((self.DEFAULT_MAX_COUNT_PERC/100.0) * count)
            cum_count = 0
            for i in range(0, min_distinct_values):
                value = values[i]
                cum_count = cum_count + int(value.get('count'))
                if cum_count > max_count:
                    result = self._build_result(field_name, 'attribute', distinct_count, event_coverage_perc, False)
                    self._add_to_results(result)
                    return True
            return False

    def check_and_add_custom_text_field(self, record):
        """
        Check if the field is textual field but that did not have standard text field names

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: {boolean}
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
        event_coverage_perc = record.get(self.FILED_SUMMARY_EVENT_COVERAGE_PERC)
        if event_coverage_perc > self.DEFAULT_THRESHOLD_EVENT_COVERAGE_PERC:
            result = self._build_result(field_name, 'text', distinct_count, event_coverage_perc, False)
            self._add_to_results(result)
            return True
        return False

    def set_record_as_category(self, record):
        """
        Set the field as categorical field

        @type record: dict
        @param record: Dictionary holding a field summary data of a particular field

        :return: None but adds to the result set holding field segregation information
        """
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        distinct_count = int(record.get(self.FILED_SUMMARY_DISTINCT_COUNT))
        event_coverage_perc = record.get(self.FILED_SUMMARY_EVENT_COVERAGE_PERC)
        result = self._build_result(field_name, 'attribute', distinct_count, event_coverage_perc, False)
        self._add_to_results(result)

    def ignore_fields(self, record):
        field_name = record.get(self.FILED_SUMMARY_FIELD)
        for ignore_field in self.IGNORE_FIELDS:
            if ignore_field in str.lower(field_name):
                result = self._build_result(field_name, None, None, None, True)
                self._add_to_results(result)
                return True
        return False

    def _raiseExceptionWithMessage(self, msg):
        """
        Logs an error message and raises an exception with that message

        @type msg: basestring
        @param msg: the message to be used for the exception raising
        """
        self.logger.error(msg)
        raise Exception(msg)

    def process_fields(self):
        """
        Loops through each field summary record to identify if the field in the record if text or categorical
        :return: None but adds result to analysis to result set
        """
        first_record = True
        for record in self.records:
            try:
                if first_record:
                    # 'event_count_total' has been added to fieldsummary search for the correlation engine
                    # Assumption: certain fields (like title, description) are always present meaning event_count_total will always return accurate event count
                    self.event_count = record['event_count_total']
                first_record = False
                if self.event_count:
                    record['event_coverage_perc'] = int(round((float(record['count']) / float(self.event_count)) * 100.0))
                if self.ignore_fields(record):
                    continue
                elif self.field_with_one_distinct_value(record):
                    continue
                elif self.field_with_all_distinct_values(record):
                    continue
                elif self.check_and_add_standard_text_field(record):
                    continue
                elif self.check_and_add_categorical_field(record):
                    continue
                elif self.check_and_add_custom_text_field(record):
                    continue
                else:
                    self.set_record_as_category(record)
                    continue
            except Exception as e:
                self.logger.error("Error is processing field summary record, hence dropping it with exception:%s", e)
                continue

    def execute(self):
        """
            Function that calls the logic where each event field is run through set of rules to
            identify it as text field or categorical field
            Output results should have following fields
                field, type, no_of_values, event_coverage_perc
        """
        self.process_fields()
        return self.results
