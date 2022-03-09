# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
This module implements the logic for the set_severity_fields custom search command
This command looks up service id and kpi id fields in search pipeline, looks up the
appropriate KPI record in the KV store, computes severity levels for the event in question
and injects alert_* fields in the search results (see the docstring for set_threshold_info).
"""
import datetime
import copy

# Core Splunk Imports
import splunk.rest
import splunk.util
from splunk.appserver.mrsparkle.lib import i18n

from itsi.objects.itsi_kpi_base_search import ItsiKPIBaseSearch
from itsi.objects.itsi_service import ItsiService
from itsi.itsi_time_block_utils import ItsiTimeBlockUtils

from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import is_valid_dict, is_string_numeric, is_valid_str

from maintenance_services.objects.operative_maintenance_record import OperativeMaintenanceRecord

logger = setup_logging("itsi_searches.log", "itsi.command.set_severity")


class SetSeverityFieldsCommandError(Exception):
    pass


class CollectKpiInfo(object):
    """
        Class to collect kpi meta data
    """

    def __init__(self, session_key):
        """
            Initialize session_key
        """
        self.service_object = ItsiService(session_key, 'nobody')
        self.kpi_base_search_object = ItsiKPIBaseSearch(session_key, 'nobody')
        self.operative_maintenance_record_object = OperativeMaintenanceRecord(session_key, 'nobody')

        # Store fetched kpi data
        self.kpis_data = {}
        self.service_data = {}
        self.shared_base_kpis = {}
        self.maintenance_service_cache = self._get_maintenance_services()

    def _get_maintenance_services(self):
        service_dict = self.operative_maintenance_record_object.get_bulk(
            'nobody',
            filter_data={'maintenance_object_type': 'service'},
            fields=['maintenance_object_key']
        )
        return [service.get('maintenance_object_key') for service in service_dict]


    def get_kpi(self, service_id, kpi_id):
        """
            Get kpi meta data. If kpiid data contains in dict then just return it otherwise retrieve it from kv store
            that way we do not retrieve data for each event
            @type service_id: basestring
            @param service_id: service id

            @type kpi_id: basestring
            @param kpi_id: kpi id

            @return None or a single KPI
        """
        if kpi_id in self.kpis_data:
            return self.kpis_data[kpi_id], self.service_data
        else:
            service = self.service_object.get('nobody', service_id)
            if service is None:
                logger.error('Service (serviceid=%s) does not exist in kv store' % service_id)
                return None, service
            for kpi in service.get('kpis', []):
                if kpi['_key'] == kpi_id:
                    # store is before return it back
                    self.kpis_data[kpi.get('_key')] = kpi
                    in_maintenance = service.get('_key') in self.maintenance_service_cache
                    self.service_data = {
                        '_key': service.get('_key'),
                        'in_maintenance': in_maintenance,
                        'sec_grp': service.get('sec_grp')
                    }
                    return kpi, self.service_data
        return None, None

    def get_kpis_from_shared_base(self, kpi_shared_base_search):
        """
        Get the kpi meta data using the kpi base search
        @param kpi_shared_base_search: The shared base search identifier
        @type kpi_shared_base_search: string
        @return None on error or a dict of the kpis keyed by service_id influenced by this shared base search
        """
        shared_base = self.kpi_base_search_object.get('nobody', kpi_shared_base_search)
        if shared_base is None:
            logger.error('Shared base search %s does not exist in kv store' % kpi_shared_base_search)
            return None

        # Only fetch services only if all the conditions are true:
        #   1. service must be "enabled"
        #   2. service must contain KPIs of type "shared_base"
        #   3. with KPIs which have their base search id set to given base search. NOTE: since kpi base searches
        #   can only belong to the Global group which is shared by all private groups, lookup by base search id is fine
        services = self.service_object.get_bulk(
            'nobody',
            filter_data={'$and': [
                {'enabled': 1},
                {'kpis.search_type': 'shared_base'},
                {'kpis.base_search_id': kpi_shared_base_search}
            ]}
        )
        if services is None or len(services) == 0:
            logger.error('Shared base search %s has no matching kpis' % shared_base)
            return None

        kpis_found = {}
        for svc in services:
            kpis = svc.get("kpis")
            service_key = svc.get("_key")
            service_in_maintenance = service_key in self.maintenance_service_cache
            if kpis is None:
                logger.error('Somehow, matching service=%s has no kpis' % kpi_shared_base_search)
            for kpi in kpis:
                if kpi.get('search_type', '') == 'shared_base' and kpi.get('base_search_id') == kpi_shared_base_search:
                    if svc.get('_key') not in kpis_found:
                        kpis_found[service_key] = {"kpis": []}
                        kpis_found[service_key]['entity_rules'] = svc.get('entity_rules')
                    self.kpis_data[kpi.get('_key')] = kpi
                    kpis_found[svc.get('_key')]['kpis'].append(kpi)
                    kpis_found[svc.get('_key')]['in_maintenance'] = service_in_maintenance
                    kpis_found[svc.get('_key')]['sec_grp'] = svc.get('sec_grp')
        return kpis_found

    def check_kpi_for_count_override(self, kpi_dict):
        """
        In cases of an entity level count/dc operator and a service level avg/max/min/sum operator we need to override
        the no data null with a service level 0. Any other combination will be handled normally.

        @param kpi_dict:
        @type kpi_dict: dict

        @return: True if we should perform the count value override, False otherwise
        @rtype: bool
        """
        # See https://confluence.splunk.com/display/PROD/ITSI+Search+Test+Matrix for a list of all
        # Possible search results - all places where we should have 0 instead of NA
        if kpi_dict.get('aggregate_statop') == 'dc':
            return True

        if not kpi_dict.get('is_entity_breakdown', False):
            if kpi_dict.get('aggregate_statop') == 'count':  # Both dc and count should return true for the agg. statop
                return True
            return False

        # Handle the generic case of our matrix - we do the count override
        valid_entity_ops = ('count', 'dc')
        valid_service_ops = ('avg', 'dc', 'sum', 'max', 'min')
        if kpi_dict.get('entity_statop') in valid_entity_ops and kpi_dict.get('aggregate_statop') in valid_service_ops:
            return True

        return False


class SetSeverityFields(object):
    def __init__(self, is_handle_no_data=False, is_generate_max_value_alert=False, default_time=None):
        """
        Initialize
        @type is_handle_no_data: boolean
        @param is_handle_no_data:  boolean to handle no data scenario

        @type is_generate_max_value_alert: boolean
        @param is_generate_max_value_alert: handle to generate max alert_value event
        @return:
        """
        # Flag to generate extra alert and handle no data scenario
        self.is_handle_no_data = is_handle_no_data
        self.is_generate_max_value_alert = is_generate_max_value_alert
        # Max result set - to handle multiple kpis its a dict with kpiid as the key
        self.max_alert_result = {}
        # default time
        self.default_time = default_time

    def _get_alert_level(self, value, kpi, threshold_settings, is_kpi_in_maintenance=False):
        '''
        Given a metric value and threshold_settings object
        (which contains a thresholdLevels array) generate alert fields

        @param value: alert value to lookup thresholding for
        @type value: basestring

        @param kpi: KPI that is being thresholded
        @type: object

        @param threshold_settings: thresholding settings to apply
        @type: dict

        @param is_kpi_in_maintenance: indicates if the KPI is in maintenance
        @type is_kpi_in_maintenance: boolean

        @return: alert fields identified from applying thresholds on alert value
        '''
        threshold_levels = []
        if is_valid_dict(threshold_settings):
            threshold_levels = threshold_settings['thresholdLevels']

        if is_kpi_in_maintenance:
            return {
                'alert_severity': 'maintenance',
                'alert_color': '#5C6773',
                'alert_level': int('-2')  # -2 is for maintenance
            }

        if value is None or not is_string_numeric(value):  # assume this means a data gap
            logger.debug("No data scenario, value is=%s", value)
            return {
                'alert_severity': kpi.get('gap_severity', 'unknown'),
                'alert_color': kpi.get('gap_severity_color', '#CCCCCC'),
                'alert_level': int(kpi.get('gap_severity_value', '-1'))
            }
        else:
            value = float(value)
            threshold_levels.sort(key=lambda x: -float(x['thresholdValue']))  # descending order by value
            # pick highest threshold that is consistent with `value`
            for level in threshold_levels:
                threshold_value = float(level.get('thresholdValue', None))
                if value >= threshold_value:
                    logger.debug("threshold value found, for value=%s, threshold value=%s", value, threshold_value)
                    return {
                        'alert_severity': level.get('severityLabel', 'unknown'),
                        'alert_color': level.get('severityColor', '#CCCCCC'),
                        'alert_level': int(level.get('severityValue', '-1'))
                    }
            # if we got here, value is below every threshold, so return the base severity
            logger.debug("value=%s in range of base severity", value)
            if not isinstance(threshold_settings, dict):
                return {
                    'alert_severity': 'unknown',
                    'alert_color': '#CCCCCC',
                    'alert_level': int('-1')
                }
            else:
                return {
                    'alert_severity': threshold_settings.get('baseSeverityLabel', 'unknown'),
                    'alert_color': threshold_settings.get('baseSeverityColor', '#CCCCCC'),
                    'alert_level': int(threshold_settings.get('baseSeverityValue', '-1'))
                }

    def _compare_fixed_thresholds(self, result, kpi, service_info):
        """
        Return severity fields based on fixed/constant thresholds
        @param result: the search results row dictionary to use for comparison
        @type result: dict
        @param kpi: the kpi model dictionary
        @type kpi: dict
        @param service_info: relevant service information
        @type service_info: dict
        @return: the severity fields to be set into the result row
        @rtype: dict
        """
        entity_thresholds = kpi.get('entity_thresholds')
        aggregate_thresholds = kpi.get('aggregate_thresholds')
        is_service_in_maintenance = service_info.get('in_maintenance', False)
        return self._make_alert_fields(result, kpi, aggregate_thresholds, entity_thresholds, is_service_in_maintenance)

    def _make_alert_fields(
        self,
        result,
        kpi,
        aggregate_thresholds,
        entity_thresholds,
        is_service_in_maintenance=False
    ):
        is_service_aggregate = splunk.util.normalizeBoolean(result.get('is_service_aggregate', True))
        value = result.get('alert_value')
        if is_service_aggregate:
            is_all_entities_in_maintenance = splunk.util.normalizeBoolean(
                result.get("is_all_entities_in_maintenance", False)
            )
            is_kpi_in_maintenance = is_service_in_maintenance or is_all_entities_in_maintenance
            alerts = self._get_alert_level(value, kpi, aggregate_thresholds, is_kpi_in_maintenance)
            alerts['is_entity_in_maintenance'] = 1 if is_kpi_in_maintenance else 0  # entity is service aggregate
        else:
            is_entity_in_maintenance = splunk.util.normalizeBoolean(result.get("is_entity_in_maintenance", False))
            is_kpi_in_maintenance = is_service_in_maintenance or is_entity_in_maintenance
            alerts = self._get_alert_level(value, kpi, entity_thresholds, is_kpi_in_maintenance)

        alerts['is_service_in_maintenance'] = 1 if is_service_in_maintenance else 0  # Save away for tracking

        # Compared with max stored value and save it to generate separate event
        if self.is_generate_max_value_alert:
            if self.max_alert_result.get(kpi.get('_key')) is None:
                # Get first value
                self.max_alert_result[kpi.get('_key')] = self._copy_and_update_alert_values(result, alerts)

            max_alert_level = self.max_alert_result[kpi.get('_key')].get('alert_level')
            current_alert_level = alerts.get('alert_level')

            if not is_string_numeric(max_alert_level) and is_string_numeric(current_alert_level):
                # max contain no empty or non numeric value so assign numeric value
                self.max_alert_result[kpi.get('_key')] = self._copy_and_update_alert_values(result, alerts)

            if is_string_numeric(max_alert_level) and is_string_numeric(current_alert_level):
                # compare max value
                if float(current_alert_level) >= float(max_alert_level):
                    self.max_alert_result[kpi.get('_key')] = self._copy_and_update_alert_values(result, alerts)

        return alerts

    def _copy_and_update_alert_values(self, result, alert_values):
        """
        Supporting function to do deep copy of result and add alerts_values in it.

        @type result: dict
        @param result: result or event

        @type alert_values: dict
        @param alert_values: finalized alert values for given result

        @rtype dict
        @return: new instance of dict by combining both
        """
        combine_result = copy.deepcopy(result)
        combine_result.update(alert_values)
        return combine_result

    def _get_policy(self, time, threshold_spec, tzoffset):
        """
        @param time: UTC epoch timestamp
        @type time: string, int, or float

        @param threshold_spec: dict containing policies dict and time_blocks list
        @type threshold_spec: dict

        @param tzoffset: ISO timezone offset, e.g. '-07:00' or empty string for UTC
        @type tzoffset: string
        """
        if not is_valid_dict(threshold_spec):
            error_msg = _('Invalid KPI threshold_spec: {0}. Expected dict.').format(threshold_spec)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        policies = threshold_spec.get('policies')
        if not is_valid_dict(policies):
            error_msg = _('Invalid KPI policies: {0}. Expected dict.').format(policies)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        if len(policies) == 0:
            error_msg = _('Invalid KPI policies: {0}. Expected dict to not be empty.').format(policies)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        # first, get current time information
        if is_valid_str(tzoffset):
            tz = splunk.util.TZInfo(offset=splunk.util.parseISOOffset(tzoffset))
        else:
            tz = splunk.util.utc
        date = datetime.datetime.fromtimestamp(float(time), tz)
        day, hour, minute = str(date.weekday()), str(date.hour), str(date.minute)
        # use time information to create a time block
        # note: time block has a 1 minute duration to pass validation
        time_blocks = [[' '.join([minute, hour, '*', '*', day]), 1]]

        # find policy associated with time block
        found_policy_key = 'default_policy'
        for policy_key, policy in policies.iteritems():
            policy_time_blocks = policy.get('time_blocks', [])
            # if we find conflicting time blocks in policy_time_blocks, it means we've found our policy
            if ItsiTimeBlockUtils.check_time_block_conflict_between(time_blocks, policy_time_blocks):
                found_policy_key = policy_key
                break

        return policies.get(found_policy_key, {})

    def _compare_variable_thresholds(self, result, kpi, service_info):
        """
        Return severity fields based on time-variate thresholds given the timestamp and threshold policy set
        @param result: the search result row dictionary to use for comparison
        @type result: dict
        @param kpi: the kpi model dictionary
        @type kpi: dict
        @param service_info: relevant service information
        @type service_info: dict
        @return: the severity fields to be set into the result row
        @rtype: dict
        """
        threshold_spec = kpi.get('time_variate_thresholds_specification')
        # Note that _time on summary index is UTC epoch
        policy = self._get_policy(result.get('_time', self.default_time), threshold_spec, kpi.get('tz_offset', ''))
        entity_thresholds = policy.get('entity_thresholds', {})
        aggregate_thresholds = policy.get('aggregate_thresholds')
        is_service_in_maintenance = service_info.get('in_maintenance', False)
        return self._make_alert_fields(result, kpi, aggregate_thresholds, entity_thresholds, is_service_in_maintenance)

    def get_severity_info(self, result, kpi=None, service_info=None):
        """
        Compute and return the alert-related fields for a single results row from a search.
        The following fields are inserted:
        - alert_severity (severity label e.g. "normal")
        - alert_color (e.g. "#99D18B")
        - alert_level (numeric severity level e.g. 2)
        - alert_value (the value of the metric field)
        - alert_entity ('aggregate' for aggregate thresholds else entity_key)

        The code inspects the `time_variate_thresholds` flag in the KPI record. If it is
        absent or not set, threshold settings are retrieved from the entity-level
        and/or aggregate-level threshold setting records in the KPI, otherwise they
        are looked up based on the result _time field using time blocks collection to identify the
        relevant policy record, and policy record to get the threshold settings.

        @param result: the search result row dictionary to use for comparison
        @type result: dict

        @param kpi: kpi record as fetched from the KV store
        @type kpi: dict

        @param service_info: relevant service information collected from KV store
        @type service_info: dict

        @return: the severity fields to be set into the result row
        @rtype: dict
        """
        # When kpi or service is not saved and this command is called, often used for preview charts
        if (kpi is None) or (service_info is None):
            return {
                'alert_severity': 'unknown',
                'alert_color': '#CCCCCC',
                'alert_level': int(-1)
            }
        else:
            if kpi.get('time_variate_thresholds', False):
                return self._compare_variable_thresholds(result, kpi, service_info)
            else:
                return self._compare_fixed_thresholds(result, kpi, service_info)

    def get_max_value_event(self, kpi):
        """
        @rtype: dict|None
        @return: Max result or None
        """
        return self.max_alert_result.get(kpi)
