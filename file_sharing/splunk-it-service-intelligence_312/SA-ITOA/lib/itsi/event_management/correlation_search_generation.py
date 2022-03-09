# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
from datetime import datetime
import math
import time
import json

logger = setup_logging("itsi_event_management.log", "itsi.object.correlation_search.search_generation")

class SearchGeneration(object):
    '''
        A class which generate search for multi alert kpi so it can be saved as correlation searches
        TODO: Move multi KPI alert generate here and correlation search creation here
    '''

    COMPOSITE_KPI_SEARCH_TYPE = "composite_kpi_score_type"
    COMPOSITE_KPI_PERCENTAGE_TYPE = "composite_kpi_percentage_type"
    TYPES = [COMPOSITE_KPI_SEARCH_TYPE, COMPOSITE_KPI_PERCENTAGE_TYPE]
    # Search field
    HEALTH_SCORE_FIELD = "health_score"
    COMPOSITE_KPI_FIELD = "composite_kpi_id"
    # Properties fields
    COMPOSITE_THRESHOLD_HS_FIELD = "threshold_health_score"
    COUNT_FIELD = "count"
    SUPPRESSION_PERIOD_FIELD = "suppression_period"
    IS_CONSECUTIVE_FIELD = "is_consecutive"
    IS_SUPPRESSION_FIELD = "is_suppression"
    MIN_ALERT_PERIOD_FIELD = "min_alert_period"
    RUN_EVERY_FIELD = "run_every"
    COMPOSITE_KPIS = "score_based_kpis"
    SERVICE_ID = "serviceid"
    KPI_ID = "kpiid"
    # Mutlti KPI Properties
    PERCENTAGE_BASED_KPIS = "percentage_based_kpis"
    MULTI_KPI_TIME_LABEL = "time_label"
    LABEL_THRESHOLDS = 'label_thresholds'
    THRESHOLDS = 'thresholds'

    def __init__(self, id, properties, search_type=COMPOSITE_KPI_SEARCH_TYPE):
        """
            Initialized class with appropriate data to generate search. Invoke get_search function once initialization
            is done to generate search
        @type id: basestring
        @param id: id
        @param {dict} properties: dict which hold properties
        @param {string} search_type: type of search creation, refer self.CORRELATION_SEARCH_TYPE to get all possible type
        @return:
        """
        self.logger = logger

        if search_type not in self.TYPES:
            self.logger.debug("Invalid correlation search type:%s", search_type)
            raise ValueError(_("Invalid correlation search type:{0}").format(search_type))

        self.search_type = search_type
        self.id = id
        self.properties = properties if properties else {}
        # Properties can be stringfy json file
        if isinstance(self.properties, basestring):
            self.properties = json.loads(self.properties)

    def _convert_earliest_latest_to_relative(self, latest, earliest):
        """
        Convert latest and earliest value to relative value

        @type latest: int
        @param latest: latest time

        @type earliest: int
        @param earliest: latest time

        @rtype: tuple
        @return: new_latest and new_earliest time
        """
        new_latest = "now"
        latest_datetime = datetime.fromtimestamp(latest)
        earliest_datetime = datetime.fromtimestamp(earliest)
        delta = latest_datetime - earliest_datetime
        new_earliest = str(math.trunc(delta.total_seconds()/60) * -1 ) + "m"
        return new_latest, new_earliest

    def get_search(self):
        """
        Return generated search

        @rtype: basestring
        @return: search string
        """
        if self.search_type == self.COMPOSITE_KPI_SEARCH_TYPE:
            threshold_score = self.properties.get(self.COMPOSITE_THRESHOLD_HS_FIELD)
            if threshold_score is None:
                raise ValueError(_("Threshold score is not set, for id={0}").format(id))
            search = self._get_composite_kpi_search(self.id, threshold_score)
            logger.info("Generated Composite KPI search:%s", search)
            # If suppression is enabled then update, earliest and latest of search interval and suppression criteria
            if self.properties.get(self.IS_SUPPRESSION_FIELD, False):
                if not self.properties.get(self.IS_CONSECUTIVE_FIELD):
                    search += " | reverse | suppressalert is_consecutive={0} count={1} suppression_period={2}".format(
                        self.properties.get(self.IS_CONSECUTIVE_FIELD), self.properties.get(self.COUNT_FIELD),
                        self.properties.get(self.SUPPRESSION_PERIOD_FIELD))
                else:
                    search += " | reverse | suppressalert is_consecutive={0} count={1}".format(
                        self.properties.get(self.IS_CONSECUTIVE_FIELD), self.properties.get(self.COUNT_FIELD))

            # Add meta data search
            search += " | `composite_kpi_meta_data`"
            return search
        else:
            search = self._get_multi_kpi_search()
            logger.info("Generated Composite KPI search:%s", search)
            return search

    def get_search_earliest_latest(self, latest, earliest):
        """
        Get latest and earliest time

        @type latest: basestring
        @param latest: latest time

        @param earliest: basestring
        @param earliest:  earliest string

        @rtype: tuple
        @return: latest and earliest time
        """
        if self.search_type == self.COMPOSITE_KPI_SEARCH_TYPE:
            new_latest = latest
            new_earliest = earliest
            if self.properties.get(self.IS_SUPPRESSION_FIELD, False):
                new_latest = 'now'
                run_every = int(self.properties.get(self.RUN_EVERY_FIELD))
                if self.properties.get(self.IS_CONSECUTIVE_FIELD):
                    sup_period = int(self.properties.get(self.COUNT_FIELD))
                    # consecutive
                    new_earliest = str((max(run_every, sup_period) + min(run_every, sup_period) - 1) * -1) + "m"
                else:
                    sup_period = int(self.properties.get(self.SUPPRESSION_PERIOD_FIELD))
                    # Non-consecutive
                    new_earliest = str(sup_period * -1) + "m"
            else:
                new_latest, new_earliest = self._get_earliest_latest(latest, earliest)

            return new_latest, new_earliest
        else:
            return self._get_earliest_latest(latest, earliest)

    # Converting time range to relative time range.
    # Ex: The time range between April 1 - April 2 is converted to latest="now" and earliest="-1440m".
    # Appropriately handling various scenarios of latest and earliest value being int, None, "" and 0.
    def _get_earliest_latest(self, latest, earliest):
        """
        Get latest and earliest time

        @type latest: String, int, None
        @param latest: latest time

        @param earliest: String, int, None
        @param earliest:  earliest time

        @rtype: tuple
        @return: new_latest and new_earliest time
        """
        new_latest = latest
        new_earliest = earliest
        if self._is_valid_timestamp(latest):
            # earliest == None or earliest == "" or earliest == 0:
            if not earliest:
                new_latest, new_earliest = self._convert_earliest_latest_to_relative(latest, 0)
            elif self._is_valid_timestamp(earliest):
                new_latest, new_earliest = self._convert_earliest_latest_to_relative(latest, earliest)
            else:
                new_latest = "now"
                new_earliest = earliest
        # latest == None or latest == "" or latest == 0:
        if not latest:
            if self._is_valid_timestamp(earliest):
                new_latest, new_earliest = self._convert_earliest_latest_to_relative(float(time.time()), earliest)
            # earliest == None or earliest == "" or earliest == 0:
            if not earliest:
                new_latest, new_earliest = self._convert_earliest_latest_to_relative(float(time.time()), 0)

        return new_latest, new_earliest

    def _is_valid_timestamp(self, ts):
        """
        Check if timestamp is valid.
        Def of valid timesatamp: If value is integer or float with value grater that 0.

        """
        if ts != None and ts > 0 and (isinstance(ts, float) or isinstance(ts, int)):
            return True

    def _get_composite_kpi_search(self, composite_kpi_id, threshold_score):
        """
            Properties needed to generate correlation search for composite KPI
                composite_info -- dict which hold information about Composite KPI data
                `composite_health_data` filter

            @type composite_kpi_id: basestring
            @param composite_kpi_id: kpi id

            @type threshold_score: basestring
            @param threshold_score: threshold score

            @return composite_kpi_id: search
            @rtype: basestring
        """
        filter_exp = self._get_composite_kpi_filter(composite_kpi_id, threshold_score)
        # Composite KPI searches should filter out maintenance health events identified by alert level -2
        search = "`composite_health_data` "
        if filter_exp is not None:
            search += filter_exp

            search = search + ' | join [search ' + search + ' | stats latest(alert_level) as latest_alert_level] ' + \
                '| search ((latest_alert_level != -2) AND (alert_level != -2))'
            # TODO validate the generated search
            return search
        else:
            # TODO Get no op search
            return ""

    def _get_composite_kpi_filter(self, composite_kpi_id, threshold_score):
        """
        Get filter the search
        @param {string} composite_kpi_id - composite kpi id
        @param {string} threshold_score: threshold score

        @return: filter for search
        @rtype: basestring
        """
        filter_exp = '"{0}"="{1}"'.format(self.COMPOSITE_KPI_FIELD, composite_kpi_id)
        post_filter = self._get_post_filter(threshold_score)
        if post_filter is not None:
            filter_exp += " AND " + post_filter

        return "(" + filter_exp + ")"

    def _get_post_filter(self, health_threshold):
        """
        Supporting function to return filter string
        @type health_threshold: int/basestring
        @param health_threshold: int/basestring which hold threshold value

        @return: return string for filter
        @rtype: basestring
        """
        if health_threshold is not None:
            # score is reverse order hence we need to compare with less than threshold value
            return self.HEALTH_SCORE_FIELD + "<=" + str(health_threshold)
        else:
            return None

    def get_service_ids_and_kpi_ids(self):
        """
        Return list of service ids and kpi ids belong to composite or multi kpi alerts
        @rtype: tuple
        @return: tuple of service and kpi ids
        """
        service_ids = []
        kpi_ids = []
        if self.search_type == self.COMPOSITE_KPI_SEARCH_TYPE:
            kpis = self.properties.get(self.COMPOSITE_KPIS, [])
            for data in kpis:
                if data.get(self.KPI_ID):
                    kpi_ids.append(data.get(self.KPI_ID))
                if data.get(self.SERVICE_ID) and data.get(self.SERVICE_ID) not in service_ids:
                    service_ids.append(data.get(self.SERVICE_ID))
        else:
            for kpi_info in self.properties.get(self.PERCENTAGE_BASED_KPIS, []):
                if kpi_info.get(self.SERVICE_ID) and kpi_info.get(self.SERVICE_ID) not in service_ids:
                    service_ids.append(kpi_info.get(self.SERVICE_ID))
                if kpi_info.get(self.KPI_ID):
                    kpi_ids.append(kpi_info.get(self.KPI_ID))
        return service_ids, kpi_ids

    def get_service_ids(self):
        """
        Get service ids for
        @rtype: basestring
        @return: list of service ids in comma separated string
        """
        service_ids, kpi_ids = self.get_service_ids_and_kpi_ids()
        if len(service_ids) == 0:
            return ''
        else:
            return ','.join(service_ids)

    def _get_multi_kpi_search(self):
        """
        Get multi kpi search

        @rtype: basestring
        @type: search string

        """
        kpis = self.properties.get(self.PERCENTAGE_BASED_KPIS, [])
        # Pre filter
        kpi_and_service_filters = []
        # Post filter
        threshold_filters = []
        for kpi in kpis:
            kpi_service_filter = 'itsi_kpi_id=' + kpi.get(self.KPI_ID, '') + ' AND itsi_service_id=' +\
                                 kpi.get(self.SERVICE_ID)
            label_thresholds = kpi.get(self.LABEL_THRESHOLDS)
            label_threshold_conditions = []
            for threshold in label_thresholds.get(self.THRESHOLDS):
                # Create condition:  Example: "(severity=critical AND percentage>=93)"
                condition = '( severity={0} AND percentage{1}{2} )'.format(threshold.get('severity'),
                                                                           threshold.get('percentage_operation'),
                                                                           threshold.get('percentage'))
                label_threshold_conditions.append(condition)
            final_label_condition = ' {0} '.format(label_thresholds.get('operation', 'OR')).join(label_threshold_conditions)

            threshold_filters.append('( {0} AND ( {1} ))'.format(kpi_service_filter, final_label_condition))
            kpi_and_service_filters.append('( {0} ) '.format(kpi_service_filter))

        thresholds_filter = ' OR '.join(threshold_filters)
        kpis_and_services_filter = ' OR '.join(kpi_and_service_filters)

        time_label = self.properties.get(self.MULTI_KPI_TIME_LABEL, '')

        generated_search = ''
        if len(kpi_and_service_filters) > 0:
            # Assuming that each KPI search is producing only one result each time
            # Note: ServiceHealthScore does not store its name in summary index but
            # other kpis will always store values hence using
            # `|eval gs_kpi_name = coalesce(gs_kpi_name, "ServiceHealthScore")` ',
            # if this behavior changes then search need to be updated.
            base_search = '`get_itsi_summary_index` `service_level_max_severity_and_service_health_score` '\
                          + kpis_and_services_filter + \
                          '| stats count as occurances latest(*) as * by alert_severity itsi_kpi_id itsi_service_id ' \
                          '| rename alert_severity as severity ' \
                          '| eval kpi = coalesce(kpi, "ServiceHealthScore") | `getPercentage(alert_period, occurrence)`'
            generated_search = base_search + " | search " + thresholds_filter + \
                               '| `kpi_correlation_meta_data("' + time_label + \
                               '")` | where total_kpis >=' + \
                               str(len(threshold_filters)) + ' | fields - total_kpis'

        return generated_search
