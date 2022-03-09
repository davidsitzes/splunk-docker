# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import logging
import json
from collections import namedtuple

from ITOA.itoa_common import get_conf
from ITOA.setup_logging import setup_logging
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from itsi.objects.itsi_service import ItsiService
from maintenance_services.objects.operative_maintenance_record import OperativeMaintenanceRecord

from splunk.util import normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n

# Tuple to store alert/threshold level data
AlertData = namedtuple('AlertData', ['color', 'level', 'health_weight', 'health_min', 'health_max', 'is_min_included',
                                     'is_max_included', 'score_contribution', 'weighted_contribution'])

# Tuple to store intermediate score result when we parse all search results
IntermediateScoreData = namedtuple('Intermediate',
                                   [
                                       'total_score',
                                       'total_weight',
                                       'min_boom',
                                       'is_all_unknown',
                                       'is_all_maintenance',
                                       'is_all_disabled',
                                       'name',
                                       'is_service_in_maintenance'
                                   ]
                                   )
# Tuple to store final score
ComputedScoreData = namedtuple('ComputedScoreData', ['score', 'name', 'in_maintenance', 'is_service_in_maintenance', 'is_disabled'])
# Tuple to store composite kpi data in dict
CompositeKpiData = namedtuple('CompositeKpiData', ['urgency', 'composite_kpi_id', 'composite_kpi_name'])
# Tuple to store depending service info
DependingHealthKpiData = namedtuple('DependingHealthKpiData', ['service_id', 'urgency'])
# Tuple to store service dependency in dict
DependentKpiData = namedtuple('DependentKpiData', ['dep_service_id', 'dep_service_name', 'urgency'])


class ScoreCalculation(object):
    NOT_AVAILABLE = 'N/A'
    UNKNOWN_COLOR = '#CCCCCC'
    UNKNOWN_LEVEL = '-1'
    UNKNOWN_THRESHOLD_FILED = 'unknown'

    MAINTENANCE_LEVEL = -2
    MAINTENANCE_THRESHOLD_FILED = 'maintenance'

    DISABLED_LEVEL = -3
    DISABLED_THRESHOLD_FIELD = 'disabled'

    @staticmethod
    def get_boom_score(alert_level, severity_name, urgency, threshold_data):
        """
        Get boom score for each given urgency(importance) and status
        :param {int} alert_level: int value of severity status
        :param {string} severity_name: severity name
        :param {int} urgency: importance or urgency of given status
        :param {namedtuple} threshold_data: threshold settings
        :return: a tuple of [flag if it is boom score, boom score]
        """
        is_boom = False
        # if something is not a "boom" it could still be considered a max health boom as boom just sets minimum health
        boom_score = 100
        if urgency == 11 and alert_level > 1:
            is_boom = True
            severity_data = threshold_data.get(severity_name)
            boom_score = severity_data.weighted_contribution
        return is_boom, boom_score

    @staticmethod
    def get_kpi_inverted_score(alert_level, severity_name, urgency, threshold_data):
        """
        Get inverted score (means 100-info, 0-critical) for each given urgency(importance) and status
        :param {int} alert_level: int value of severity status
        :param {string} severity_name: severity name
        :param {int} urgency: importance or urgency of given status
        :param {namedtuple} threshold_data: threshold settings
        :return: a tuple of inverted score, flag is it is boom score, boom score
        """
        normalized_alert_level = float(alert_level)
        # Work around ITOA-2586
        if (alert_level <= 1) and (normalized_alert_level != ScoreCalculation.MAINTENANCE_LEVEL):
            # Takes care of maintenance and unknown
            inverted_score = 0
        else:
            inverted_score = threshold_data.get(severity_name).weighted_contribution

        is_boom, boom_score = ScoreCalculation.get_boom_score(alert_level, severity_name, urgency, threshold_data)

        return inverted_score, is_boom, boom_score

    @staticmethod
    def combine_group_score(group_score_dict, alert_level, urgency, boom_score, inverted_score,
                            group_id='default_group', group_name='default_group', is_service_in_maintenance=False):
        """
        Supporting function to group the health score. It's add data to given dict (group_score_dict) for given id
        :param {dict} group_score_dict: dict which hold score for given group id
        :param {float|int} alert_level: alert level
        :param {float|int} urgency: urgency
        :param {float|int} boom_score: boom score
        :param {float|int} inverted_score: calculate kpi score where (0-info, 100-critical)
        :param {string} group_id: id to group into (optional)
        :param {string} group_name: name of group (optional)
        :param {boolean} is_service_in_maintenance: service maintenance status (optional)
        :return: None but update dict where value is named tuple
        """
        normalized_alert_level = float(alert_level)

        if group_id in group_score_dict:
            data = group_score_dict.get(group_id)
            min_boom = min(data.min_boom, boom_score)
            is_all_unknown = (data.is_all_unknown and
                              ((normalized_alert_level <= 1) and
                               (normalized_alert_level != ScoreCalculation.MAINTENANCE_LEVEL) and
                               (normalized_alert_level != ScoreCalculation.DISABLED_LEVEL))
                              )
            is_all_maintenance = data.is_all_maintenance and normalized_alert_level == ScoreCalculation.MAINTENANCE_LEVEL
            is_all_disabled = data.is_all_disabled and normalized_alert_level == ScoreCalculation.DISABLED_LEVEL
            # All levels less than 1 do not contribute to health scores that means urgency cannot contribute to weight
            if alert_level <= 1:
                group_score_dict[group_id] = IntermediateScoreData(data.total_score,
                                                                   data.total_weight,
                                                                   min_boom,
                                                                   is_all_unknown,
                                                                   is_all_maintenance,
                                                                   is_all_disabled,
                                                                   group_name,
                                                                   is_service_in_maintenance)
            else:
                group_score_dict[group_id] = IntermediateScoreData(data.total_score + urgency * inverted_score,
                                                                   data.total_weight + urgency,
                                                                   min_boom,
                                                                   is_all_unknown,
                                                                   is_all_maintenance,
                                                                   is_all_disabled,
                                                                   group_name,
                                                                   is_service_in_maintenance)
        else:
            min_boom = boom_score
            is_all_unknown = (normalized_alert_level <= 1) and \
                             (normalized_alert_level != ScoreCalculation.MAINTENANCE_LEVEL) and \
                               (normalized_alert_level != ScoreCalculation.DISABLED_LEVEL)
            is_all_maintenance = normalized_alert_level == ScoreCalculation.MAINTENANCE_LEVEL
            is_all_disabled = normalized_alert_level == ScoreCalculation.DISABLED_LEVEL
            # All levels less than 1 do not contribute to health scores, note that urgency must be 0 to avoid weight
            if alert_level <= 1:
                group_score_dict[group_id] = IntermediateScoreData(0,
                                                                   0,
                                                                   min_boom,
                                                                   is_all_unknown,
                                                                   is_all_maintenance,
                                                                   is_all_disabled,
                                                                   group_name,
                                                                   is_service_in_maintenance)
            else:
                group_score_dict[group_id] = IntermediateScoreData(urgency * inverted_score,
                                                                   urgency,
                                                                   min_boom,
                                                                   is_all_unknown,
                                                                   is_all_maintenance,
                                                                   is_all_disabled,
                                                                   group_name,
                                                                   is_service_in_maintenance)

    @staticmethod
    def get_final_score_per_service(sid, group_score_dict):
        """
        Supporting function to compute final health score for a single service
        :param {basestring} sid: the string for a service id
        :param {dict} group_score_dict: get data and store final score in same dict
        :return: None but update dict where value is named tuple
        """
        # Score data is tuple of total_score, total_weight, max_boom score, all_KPI has unknown score and name
        score_data = group_score_dict.get(sid, None)
        # If the service has not already had calculations performed on it, then it is in an invalid state and you should make sure it shows N/A
        if score_data is None:
            group_score_dict[sid] = ComputedScoreData(
                ScoreCalculation.NOT_AVAILABLE,
                '',
                False,
                False,
                False
            )
            return

        name = score_data.name
        # if all unknown then N/A
        if score_data.is_all_disabled:
            group_score_dict[sid] = ComputedScoreData(
                ScoreCalculation.NOT_AVAILABLE,
                name,
                False,
                score_data.is_service_in_maintenance,
                True
            )
        elif score_data.is_all_unknown:
            group_score_dict[sid] = ComputedScoreData(
                ScoreCalculation.NOT_AVAILABLE,
                name,
                False,
                score_data.is_service_in_maintenance,
                False
            )
        else:
            try:
                min_score = min((score_data.total_score / score_data.total_weight), score_data.min_boom)
                round_min_score = round(min_score, 2)
                group_score_dict[sid] = ComputedScoreData(
                    round_min_score,
                    name,
                    score_data.is_all_maintenance,
                    score_data.is_service_in_maintenance,
                    False
                )
            except ZeroDivisionError:
                # Importance zero should not reflect score hence N/A, unless in maintenance
                if score_data.is_service_in_maintenance or score_data.is_all_maintenance:
                    group_score_dict[sid] = ComputedScoreData(
                        100,
                        name,
                        True,
                        True,
                        False
                    )
                else:
                    group_score_dict[sid] = ComputedScoreData(
                        ScoreCalculation.NOT_AVAILABLE,
                        name,
                        score_data.is_all_maintenance,
                        score_data.is_service_in_maintenance,
                        False
                    )

    @staticmethod
    def get_final_score(group_score_dict):
        """
        Supporting function to compute final health score for composite and service health
        :param {dict} group_score_dict: get data and store final score in same dict
        :return: None but update dict where value is named tuple
        """
        # Note this is editing an object while iterating, but as keys are not added or removed, so it is safe in python
        for sid, score_data in group_score_dict.iteritems():
            ScoreCalculation.get_final_score_per_service(sid, group_score_dict)

    @staticmethod
    def calculate_score(list_severity_importance, threshold_data, severity_level_field, severity_name_field,
                        urgency_field):
        """
        Given list of urgency and severity, calculate score
        @param list_severity_importance: list of severity and urgency
        @type list_severity_importance: list
        @param threshold_data: dict of threshold data (this is namedtuple)- refer ThresholdSettings for more info
        @type threshold_data: namedtuple
        @param severity_level_field: field name which hold severity level in the given list
        @type severity_level_field: str
        @param severity_name_field: field name which hold severity name in the given list
        @type severity_name_field: str
        @param urgency_field: field name which hold urgency in the given list
        @type urgency_field: str

        @return score: the final health score
        @rtype int
        """
        score_data = {}
        for data in list_severity_importance:
            # FIXME: this line of code is extremely suspect, it implies that the is service in maintenance can be set just by having 1 KPI in maintenance that happens to be last
            # Commenting on the FIXME:
            # The ScoreCalculation implementation being reused here needs this field populated and is really not going to
            # affect anything.
            # In this code path, health scores are used independent of other records.
            # Health score in maintenance does not really care is service is also in maintenance.
            # Also note that in this code path, one health entry will not cause other health entries to go into maintenance.
            # In other usages of the shared code, is_service_in_maintenance needs to be accurate.
            # For clarity, it may be nice to refactor in future.
            is_service_in_maintenance = (data.get(severity_level_field) == float(ScoreCalculation.MAINTENANCE_LEVEL))
            urgency = data.get(urgency_field)
            inverted_score, is_boom, boom_score = ScoreCalculation.get_kpi_inverted_score(
                data.get(severity_level_field),
                data.get(severity_name_field),
                urgency,
                threshold_data)
            ScoreCalculation.combine_group_score(
                score_data,
                data.get(severity_level_field),
                urgency,
                boom_score,
                inverted_score,
                is_service_in_maintenance=is_service_in_maintenance
            )
        ScoreCalculation.get_final_score(score_data)
        if score_data.get('default_group').score != ScoreCalculation.NOT_AVAILABLE:
            score = round(score_data.get('default_group').score, 2)
        else:
            score = score_data.get('default_group').score
        return score

    @staticmethod
    def get_health_severity(score, threshold_settings, in_maintenance=False, is_disabled=False):
        """
        Get Health score severity and color code
        @param score: health score
        @type score: float|int
        @param threshold_settings: ranges for particular threshold values
        @type threshold_settings: dict
        @param in_maintenance: indicates if score is for an object in maintenance
        @type in_maintenance: boolean
        @param is_disabled: indicates if score is for an object that is disabled
        @type is_disabled: boolean

        @return: a tuple identifying severity label, color and level
        @rtype: tuple
        """
        if in_maintenance and (ScoreCalculation.MAINTENANCE_THRESHOLD_FILED in threshold_settings):
            severity = ScoreCalculation.MAINTENANCE_THRESHOLD_FILED
            return severity, threshold_settings[severity].color, threshold_settings[severity].level

        if score == ScoreCalculation.NOT_AVAILABLE:
            if is_disabled:
                return ScoreCalculation.DISABLED_THRESHOLD_FIELD, ScoreCalculation.UNKNOWN_COLOR, ScoreCalculation.DISABLED_LEVEL
            else:
                return ScoreCalculation.UNKNOWN_THRESHOLD_FILED, ScoreCalculation.UNKNOWN_COLOR, ScoreCalculation.UNKNOWN_LEVEL

        score = float(score)
        for severity, data in threshold_settings.iteritems():
            if ((data.is_min_included and data.health_min <= score) or
                    (not data.is_min_included and data.health_min < score)) \
                    and \
                    ((data.is_max_included and score <= data.health_max) or
                     (not data.is_max_included and score < data.health_max)):
                return severity, data.color, data.level

        return ScoreCalculation.UNKNOWN_THRESHOLD_FILED, ScoreCalculation.UNKNOWN_COLOR, ScoreCalculation.UNKNOWN_LEVEL

    @staticmethod
    def get_health_min_max(status, threshold_settings):
        """
        Get health min and max value based status
        :param {string} status: health valid status
        :param {dict} threshold_settings: dict
        :return: a tuple of min, is_min_included, max and is_max_included limit of status
        """
        for key, data in threshold_settings.iteritems():
            if key == status:
                return data.health_min, data.is_min_included, data.health_max, data.is_max_included
        return None, None, None, None


class ThresholdSettings(object):
    THRESHOLD_FILED_CRITICAL = 'critical'

    @staticmethod
    def _check_and_raise_error(content, field):
        """
        Check if field exists in dict, otherwise raise error
        :param {dict} content: dict which hold values
        :param {string} field: field name
        :return: field value or raise Value exception
        """
        if content.get(field) is not None:
            return content.get(field)
        else:
            raise ValueError(_('{0} does not exist in conf file').format(field))

    @staticmethod
    def get_thresholds_weight(session_key):
        """
        Get threshold information from conf file, and return it
        @param session_key: the splunkd session key
        @type session_key: str

        @returns threshold_data: dict of named tuples of the conf information and calculated information
        @rtype: dict
        """
        threshold_data = {}
        res = get_conf(session_key, 'threshold_labels')
        if res.get('response', {}).get('status') == '200':
            content = json.loads(res.get('content'))
            entries = content.get('entry')

            for entry in entries:
                threshold_name = entry.get('name')
                content = entry.get('content', {})
                color = ThresholdSettings._check_and_raise_error(content, 'color')
                health_weight = float(ThresholdSettings._check_and_raise_error(content, 'health_weight'))
                health_max = float(ThresholdSettings._check_and_raise_error(content, 'health_max'))
                health_min = float(ThresholdSettings._check_and_raise_error(content, 'health_min'))
                alert_level = float(ThresholdSettings._check_and_raise_error(content, 'threshold_level'))
                score_contribution = float(ThresholdSettings._check_and_raise_error(content, 'score_contribution'))
                weighted_contribution = score_contribution * health_weight
                is_min_included = False
                is_max_included = True
                if threshold_name == ThresholdSettings.THRESHOLD_FILED_CRITICAL:
                    is_min_included = True
                threshold_data[threshold_name] = AlertData(color=color, level=alert_level,
                                                           health_weight=health_weight, health_max=health_max,
                                                           health_min=health_min, score_contribution=score_contribution,
                                                           is_min_included=is_min_included,
                                                           is_max_included=is_max_included,
                                                           weighted_contribution=weighted_contribution)
        return threshold_data


class HealthMonitor(object):
    """
        A class which calculate health score for
            Each Kpi defined in the environment
            Each Composite defined in the environment
            Each Service defined in the environment
    """
    # Threshold field name
    THRESHOLD_FILED_CRITICAL = 'critical'
    THRESHOLD_FILED_HIGH = 'high'
    THRESHOLD_FILED_MEDIUM = 'medium'
    THRESHOLD_FILED_LOW = 'low'
    THRESHOLD_FILED_NORMAL = 'normal'
    THRESHOLD_FILED_INFO = 'info'
    THRESHOLD_FILED_MAINTENANCE = 'maintenance'
    THRESHOLD_FIELD_DISABLED = 'disabled'
    # Defining default weight based upon existing definition
    # Sum all weight should be 100
    DEFAULT_WEIGHTS = {
        THRESHOLD_FILED_INFO: AlertData(color='#AED3E5', level=1, health_weight=0, health_max=100,
                                        score_contribution=100, weighted_contribution=0,
                                        health_min=100, is_min_included=False, is_max_included=True),
        # Should not effect score
        THRESHOLD_FILED_NORMAL: AlertData(color='#99D18B', level=2, health_weight=1, health_max=100,
                                          score_contribution=100, weighted_contribution=100,
                                          health_min=80, is_min_included=False, is_max_included=True),
        THRESHOLD_FILED_LOW: AlertData(color='#FFE98C', level=3, health_weight=1, health_max=80,
                                       score_contribution=70, weighted_contribution=70,
                                       health_min=60, is_min_included=False, is_max_included=True),
        THRESHOLD_FILED_MEDIUM: AlertData(color='#FCB64E', level=4, health_weight=1, health_max=60,
                                          score_contribution=50, weighted_contribution=50,
                                          health_min=40, is_min_included=False, is_max_included=True),
        THRESHOLD_FILED_HIGH: AlertData(color='#F26A35', level=5, health_weight=1, health_max=40,
                                        score_contribution=30, weighted_contribution=30,
                                        health_min=20, is_min_included=False, is_max_included=True),
        THRESHOLD_FILED_CRITICAL: AlertData(color='#B50101', level=6, health_weight=1, health_max=20,
                                            score_contribution=0, weighted_contribution=0,
                                            health_min=0, is_min_included=True, is_max_included=True),
        # Maintenance mode is same as info
        THRESHOLD_FILED_MAINTENANCE: AlertData(color='#5C6773', level=-2, health_weight=0, health_max=100,
                                               score_contribution=100, weighted_contribution=0,
                                               health_min=100, is_min_included=False, is_max_included=True),
        # disabled mode is same as info
        THRESHOLD_FIELD_DISABLED: AlertData(color='#5C6773', level=-3, health_weight=0, health_max=100,
                                               score_contribution=100, weighted_contribution=0,
                                               health_min=100, is_min_included=False, is_max_included=True),
    }

    # UNKNOWN COLOR
    UNKNOWN_COLOR = '#CCCCCC'
    UNKNOWN_THRESHOLD_FIELD = 'unknown'
    UNKNOWN_LEVEL = '-1'
    MAINTENANCE_THRESHOLD_FIELD = 'maintenance'
    MAINTENANCE_LEVEL = -2
    # Input fields
    FIELD_URGENCY = 'urgency'
    FIELD_KPI_ALERT_LEVEL = 'alert_level'
    FIELD_SERVICE_IN_MAINTENANCE = 'is_service_in_maintenance'
    FIELD_KPI_IDS = ['itsi_kpi_id', 'kpiid']  # list of kpi id fields
    FIELD_KPI_NAME = 'kpi'
    FIELD_SERVICE_IDS = ['itsi_service_id', 'serviceid']  # list of service id fields
    FIELD_SERVICE_NAME = 'service'

    # Output fields
    # sourcetype fields get rename by orig_sourcetype if this is run as summary index search
    FIELD_SOURCETYPE_NAME = 'scoretype'
    FIELD_HEALTH_SCORE = ['health_score', 'severity_value']
    FIELD_SERVICE_HEALTH_SOURCETYPE_VALUE = 'service_health'
    FIELD_COMPOSITE_HEALTH_SOURCETYPE_VALUE = 'compositekpi_health'
    FIELD_COLOR = 'color'
    FIELD_ALERT_LEVEL = 'alert_level'
    FIELD_SEVERITY_NAME = ['severity_label', 'alert_severity']
    FIELD_COMPOSITE_KPI_FIELD = 'composite_kpi_id'
    FIELD_COMPOSITE_KPI_NAME = 'composite_kpi_name'
    FIELD_COMPOSITE_ALL_SERVICE_KPI_IDS = 'all_service_kpi_ids'

    HEALTH_SCORE_KPI_NAME_FOR_SERVICE = 'ServiceHealthScore'
    NOT_AVAILABLE = 'N/A'

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
        self.logger = setup_logging('itsi_searches.log', 'itsi.command.healthscore', is_console_header=False,
                                    level=level)

        self.results = []
        self.settings = settings
        self.records = read_results

        self.service_depends_on_kpis_relationship = {}
        self.service_depends_on_health_kpis_relationship = {}
        # Use to tracked if service health is added or not, in case of service does not have any kpis in it
        self.all_services = {}
        # Store all kpis to filter out deleted kpis
        self.all_kpis = {}
        self._get_service_kpis_relationship()

        # Store composite kpi and kpi relationship to compute health score
        self.composite_kpi_relationship = {}
        # To store all kpi and service ids to outputs in the resultset
        self.composite_kpi_data = {}
        self._get_composite_kpi_relationship()

        self.threshold_data = {}
        self.get_thresholds_weight()

        self.shkpi_record_map = {}
        self.maintenance_services = None

        self.output_fields = set()

    def _is_service_health_kpi(self, id_):
        """
        Check if give kpi id is Service Health Score id or not
        :param {string} id_: KPI id
        :return: true if given id is Search Health Score id
        :rtype boolean
        """
        return id_ is not None and str(id_).startswith('SHKPI')

    def _get_service_kpis_relationship(self):
        """
        Get dependent kpis information for each service and store relationship in defined dict to access it later
        :return: None
        """
        service_object = ItsiService(self.settings['sessionKey'], 'nobody')
        self.all_services = service_object.get_bulk('nobody',
                                                    fields=['_key', 'title', 'kpis._key', 'services_depends_on', 'enabled'])
        for service in self.all_services:
            service_name = service.get('title')
            service_id = service.get('_key')

            # Store all kpis to filter out deleted kpis
            for kpi in service.get('kpis', []):
                self.all_kpis[kpi.get('_key')] = service_id

            # If a service is disabled, none of its dependencies should be processed
            if service.get('enabled', 1) == 0:
                continue
            for depends_on in service.get('services_depends_on', []):

                # If a dependent service is disabled, its health should not affect other services
                dependent_service_id = depends_on.get('serviceid')
                dependency_enabled = [
                    svc.get('enabled', 1) for svc in self.all_services if dependent_service_id == svc.get('_key')
                ]
                if len(dependency_enabled) == 1 and dependency_enabled[0] == 0:
                    continue

                for kpi in depends_on.get('kpis_depending_on', []):
                    # Get urgencies for dependent services
                    urgency = None
                    overloaded_urgencies = depends_on.get('overloaded_urgencies')
                    # This will happen if the user does not change the urgencies for dependent services in the UI
                    if overloaded_urgencies and kpi in overloaded_urgencies:
                        urgency = float(overloaded_urgencies[kpi])
                    if self._is_service_health_kpi(kpi):
                        # Value should be a tuple of service dependent on that kpi and service owning this kpi
                        if service_id in self.service_depends_on_health_kpis_relationship:
                            self.service_depends_on_health_kpis_relationship[service_id].append(
                                DependingHealthKpiData(kpi[6:], urgency))
                        else:
                            self.service_depends_on_health_kpis_relationship[service_id] = [
                                DependingHealthKpiData(kpi[6:], urgency)]
                    else:
                        if kpi in self.service_depends_on_kpis_relationship:
                            self.service_depends_on_kpis_relationship.get(kpi).append(
                                DependentKpiData(service_id, service_name, urgency))
                        else:
                            self.service_depends_on_kpis_relationship[kpi] = [
                                DependentKpiData(service_id, service_name, urgency)]
        # Delete variable which is no longer required to free some memory
        del service_object

    def _get_composite_kpi_relationship(self):
        """
        Get Composite KPI information and store relationship in defined dict to access it later
        :return: None
        """
        composite_object = ItsiCorrelationSearch(
            self.settings['sessionKey'],
            logger=self.logger
        )
        search = 'action.itsi_event_generator.param.search_type=composite_kpi_score_type'

        composite_kpis = composite_object.get_bulk(None, search=search)
        for composite_kpi in composite_kpis:
            composite_kpi_data_string = composite_kpi.get('action.itsi_event_generator.param.meta_data')
            if not composite_kpi_data_string:
                continue
            try:
                composite_kpi_data = json.loads(composite_kpi_data_string)
            except Exception as e:
                self.logger.error('Could not properly read composite kpi data, with Exception: %s', e)
                continue
            all_service_kpi_ids = []
            for kpi in composite_kpi_data.get('score_based_kpis', []):
                kpiid = kpi.get('kpiid')
                serviceid = kpi.get('serviceid')
                # Add to both values
                all_service_kpi_ids.append(serviceid + ':' + kpiid)
                over_written_urgency = float(kpi.get('urgency'))
                if kpiid in self.composite_kpi_relationship:
                    # Append to composite KPI list
                    self.composite_kpi_relationship.get(kpiid).append(
                        CompositeKpiData(
                            over_written_urgency,
                            composite_kpi.get('name'),
                            composite_kpi.get('name'))
                    )
                else:
                    # Store as tuple of urgency which is overwritten during composite KPI def
                    self.composite_kpi_relationship[kpiid] = [
                        CompositeKpiData(
                            over_written_urgency,
                            composite_kpi.get('name'),
                            composite_kpi.get('name')
                        )
                    ]
            # Add service and kpi id in specific format so notable review page can read the values
            self.composite_kpi_data[composite_kpi.get('name')] = ' '.join([str(kid) for kid in all_service_kpi_ids])

    def get_thresholds_weight(self):
        """
        Get threshold weight from conf file, and store it in instance variable
        :return: None
        """
        try:
            data = ThresholdSettings.get_thresholds_weight(self.settings['sessionKey'])
            if len(data) > 0:
                self.threshold_data = data
            else:
                self.logger.error('Failed to get conf file data, switching to default')
                self.threshold_data = self.DEFAULT_WEIGHTS
        except Exception:
            self.logger.exception('Failed to get conf file data, switching to default')
            self.threshold_data = self.DEFAULT_WEIGHTS

    def _get_alert_name(self, level):
        """
        Get severity name based upon level value
        :param {float} level: Alert/Severity Level
        :return: serverity name
        :rtype: basestring
        """
        normalized_level = float(level)
        # Special cases for unknown and maintenance
        if normalized_level == self.MAINTENANCE_LEVEL:
            return self.MAINTENANCE_THRESHOLD_FIELD
        elif normalized_level < 1:
            return self.UNKNOWN_THRESHOLD_FIELD

        ret_val = None
        for severity, data in self.threshold_data.iteritems():
            if data.level == normalized_level:
                ret_val = severity
                break

        if ret_val is None:
            raise ValueError(_('Invalid alert ret_value={0}, for level={1}.').format(ret_val, level))
        else:
            self.logger.debug('Alert Name is:%s, for level:%s', ret_val, level)
            return ret_val

    def _get_color(self, score, in_maintenance=False, is_disabled=False):
        """
        Get Health score severity and color code

        @type score: {float|int}
        @param score: health score

        @type in_maintenance: boolean
        @param in_maintenance: indicates if score is for in maintenance service/kpi

        @type is_disabled: boolean
        @param is_disabled: indicates if score is for an object that is disabled

        @return: a tuple which severity name and color code
        @rtype: tuple
        """
        severity, color, level = ScoreCalculation.get_health_severity(
            score,
            self.threshold_data,
            in_maintenance,
            is_disabled
        )
        self.logger.debug('For score:%s, hence health severity=%s color=%s', score, severity, color)
        return severity, color, level

    def _get_ids_field_value(self, record, ids):
        """
            return a value of one of fields from given ids list, otherwise exception
        :param {dict} record: dict which hold values for one or more fields
        :param {list} ids: list of fields name
        :return: return field value
        :rtype: basestring
        """
        is_found = False
        value = None
        for id_ in ids:
            if id_ in record:
                value = record.get(id_)
                is_found = True
                break

        if not is_found:
            raise ValueError(_('None of fields:{0} exist in to get data').format(str(ids)))
        return value

    def _get_service_kpi_fields(self, record, result):
        """
        Get kpi or service fields and store into results
        :param {dict} record: data which hold value for service and kpi fields
        :param {dict} result: dict to store service and kpi data
        """
        kpi_id = self._get_ids_field_value(record, self.FIELD_KPI_IDS)
        service_id = self._get_ids_field_value(record, self.FIELD_SERVICE_IDS)

        for ki in self.FIELD_KPI_IDS:
            result[ki] = kpi_id
        result[self.FIELD_KPI_NAME] = record.get(self.FIELD_KPI_NAME)

        for si in self.FIELD_SERVICE_IDS:
            result[si] = service_id
        result[self.FIELD_SERVICE_NAME] = record.get(self.FIELD_SERVICE_NAME)

    def _get_health_fields(self, score, result, in_maintenance=False, is_disabled=False):
        """
        Get health score related fields value and store into results

        @type score: {float|int}
        @param score: health sore

        @type result: dict
        @param result: dict to store value

        @type in_maintenance: boolean
        @param in_maintenance: indicates if score is for a maintenance service/kpi

        @type is_disabled: boolean
        @param is_disabled: indicates if score is for an object that is disabled
        """
        severity, color, level = self._get_color(score, in_maintenance, is_disabled)
        result[self.FIELD_COLOR] = color
        result[self.FIELD_ALERT_LEVEL] = int(level)
        for sn in self.FIELD_SEVERITY_NAME:
            result[sn] = severity
        for hs in self.FIELD_HEALTH_SCORE:
            result[hs] = score

    def _add_to_score_to_dict(
            self,
            score_dict,
            gid,
            alert_level,
            urgency,
            boom_score,
            kpi_inverted_score,
            name,
            is_service_in_maintenance=False
    ):
        """
        Supporting function for service and composite kpi health score. It's add data to given dict based upon existence
        of key
        :param {dict} score_dict: dict which hold score for composite or service
        :param {string} gid: service or composite kpi id
        :param {float|int} alert_level: alert level
        :param {float|int} urgency: urgency
        :param {float|int} boom_score: boom score
        :param {float|int} kpi_inverted_score: calculate kpi score where (0-info, 100-critical)
        :param {string} name: name of composite or service kpi
        :param {boolean} is_service_in_maintenance: service maintenance status
        :return: None
        """
        ScoreCalculation.combine_group_score(score_dict, alert_level, urgency, boom_score, kpi_inverted_score, gid,
                                             name, is_service_in_maintenance=is_service_in_maintenance)
        self.logger.debug("Updated score for %s with score_data='%s'", name, score_dict[gid])

    def _get_final_score(self, scores_dict):
        """
        Supporting function to compute final health score for composite and service health
        :param {dict} scores_dict: get data and store final score in same dict
        :return: None
        """
        ScoreCalculation.get_final_score(scores_dict)

    def _get_service_health_kpi_id(self, id_):
        """
        Get service health kpi id
        :param {string} id_: service id
        :return: id for SHKPI
        :rtype: basestring
        """
        return 'SHKPI-' + id_

    def get_kpi_health_score(self, record):
        """
        Get KPI score and store in results object
        :param {dict} record: event data pass by search pipeline
        :return: None
        """
        alert_level = float(record.get(self.FIELD_KPI_ALERT_LEVEL, -1))
        urgency = float(record.get(self.FIELD_URGENCY))
        severity_name = self._get_alert_name(alert_level)

        # Find out if service itself was in maintenance state when KPI alert level was determined
        record['in_maintenance'] = float(alert_level) == self.MAINTENANCE_LEVEL
        # Sets the urgency/importance of the data to 0, this should not be necessary but whatever
        if record['in_maintenance']:
            record[self.FIELD_URGENCY] = 0

        kpi_inverted_score, is_boom, boom_score = ScoreCalculation.get_kpi_inverted_score(alert_level, severity_name,
                                                                                          urgency, self.threshold_data)

        # Store these values to future use
        record['is_boom'] = is_boom
        record['boom_score'] = boom_score
        record['kpi_inverted_score'] = kpi_inverted_score
        self.logger.debug(
            'Generated kpi_inverted_score=%s, is_boom:%s, boom_score=%s for kpi:%s of service:%s, ',
            kpi_inverted_score, is_boom, boom_score,
            record.get(self.FIELD_KPI_NAME), record.get(self.FIELD_SERVICE_NAME))

    def compute_composite_kpi_health_score(self, record, composite_kpi_scores):
        """
        Calculate and store intermediate values to dict res
        :param {dict} record: event data pass by search pipeline
        :param {dict} composite_kpi_scores: dict to store intermediate results
        :return:
        """
        kpi_id = self._get_ids_field_value(record, self.FIELD_KPI_IDS)
        if kpi_id in self.composite_kpi_relationship:
            alert_level = float(record.get(self.FIELD_KPI_ALERT_LEVEL))
            kpi_inverted_score = record.get('kpi_inverted_score', 0)
            composite_kpis_data = self.composite_kpi_relationship.get(kpi_id)
            in_maintenance = record.get('in_maintenance', False)
            for composite_kpi_data in composite_kpis_data:
                # Get boom score for the KPI computed for the urgency specified in the composite KPI referencing
                # the KPI, not the one computed with the KPI's urgency
                is_boom, boom_score = ScoreCalculation.get_boom_score(
                    alert_level,
                    self._get_alert_name(alert_level),
                    composite_kpi_data.urgency if not in_maintenance else 0,
                    self.threshold_data
                )
                self._add_to_score_to_dict(
                    composite_kpi_scores,
                    composite_kpi_data.composite_kpi_id,
                    alert_level,
                    composite_kpi_data.urgency if not in_maintenance else 0,
                    boom_score,
                    kpi_inverted_score,
                    composite_kpi_data.composite_kpi_name,
                    is_service_in_maintenance=False
                )

    def add_composite_kpi_score_to_results(self, composite_scores):
        """
        Calculate final score and send to search pipeline
        :param {dict} composite_scores: dict which hold intermediate results
        :return: None
        """
        self._get_final_score(composite_scores)
        # Composite kpi contains score
        for cid, data in composite_scores.iteritems():
            result = {}
            health_score = data.score
            in_maintenance = data.in_maintenance or data.is_service_in_maintenance
            name = data.name
            result[self.FIELD_SOURCETYPE_NAME] = self.FIELD_COMPOSITE_HEALTH_SOURCETYPE_VALUE
            self._get_health_fields(health_score, result, in_maintenance, data.is_disabled)
            result[self.FIELD_COMPOSITE_KPI_FIELD] = cid
            result[self.FIELD_COMPOSITE_KPI_NAME] = name
            # Adding all_service_kpi_ids
            result[self.FIELD_COMPOSITE_ALL_SERVICE_KPI_IDS] = self.composite_kpi_data[cid]
            self.logger.debug('Adding Composite KPI score:%s, name:%s', health_score, name)
            self.results.append(result)
        if composite_scores:
            for k in self.results[-1].keys():
                self.output_fields.add(k)

    def compute_service_health_score(self, record, services_score):
        """
        Calculate intermediate score and store to dict
        :param {dict} record: event data pass by search pipeline
        :param {dict} services_score: dict which hold intermediate results
        :return:
        """
        # Get service dependency
        kpi_id = self._get_ids_field_value(record, self.FIELD_KPI_IDS)
        service_id = self._get_ids_field_value(record, self.FIELD_SERVICE_IDS)
        alert_level = float(record.get(self.FIELD_KPI_ALERT_LEVEL))
        urgency = float(record.get(self.FIELD_URGENCY))
        boom_score = record.get('boom_score', 100)
        kpi_inverted_score = record.get('kpi_inverted_score', 0)
        service_name = record.get(self.FIELD_SERVICE_NAME)
        # Add score to service to which this kpi belongs
        self._add_to_score_to_dict(
            services_score,
            service_id,
            alert_level,
            urgency,
            boom_score,
            kpi_inverted_score,
            service_name,
            is_service_in_maintenance=normalizeBoolean(record.get('is_service_in_maintenance', False))
        )
        # KPI is part of dependent relationship of service
        if kpi_id in self.service_depends_on_kpis_relationship:
            # Add of all dependent service score
            for data in self.service_depends_on_kpis_relationship.get(kpi_id, []):
                dependent_urgency = data.urgency if data.urgency != None else urgency
                temp_record = {
                    'alert_level': alert_level,
                    'urgency': dependent_urgency
                }
                self.get_kpi_health_score(temp_record)
                self._add_to_score_to_dict(
                    services_score,
                    data.dep_service_id,
                    temp_record['alert_level'],
                    temp_record['urgency'],
                    temp_record['boom_score'],
                    temp_record['kpi_inverted_score'],
                    data.dep_service_name,
                    is_service_in_maintenance=self._is_service_currently_in_maintenance(data.dep_service_id)
                )

    def _is_service_currently_in_maintenance(self, service_key):
        if not isinstance(self.maintenance_services, list):
            operative_maintenance_record_object = OperativeMaintenanceRecord(
                self.settings['sessionKey'],
                'nobody')

            maintenance_objects = operative_maintenance_record_object.get_bulk(
                'nobody',
                filter_data={'maintenance_object_type': 'service'},
                fields=['maintenance_object_key', 'maintenance_object_type']
            )

            self.maintenance_services = []
            if maintenance_objects is not None:
                self.maintenance_services = [maintenance_object.get('maintenance_object_key') for maintenance_object
                                             in maintenance_objects]

        return service_key in self.maintenance_services

    def _add_health_score_record_to_calculation(self, urgency, service_id, service_id_to_add, services_final_score):
        """
        Create a record for a service's health score and add it to a service's calculation
        :param {integer} urgency: The urgency of the service health score to add
        :param {string} service_id: the service id to add this new record to
        :param {string} service_id_to_add: the service id of the record to add
        :param {string} services_final_score: dict which hold intermediate and final results
        :return:
        """
        # if the service to be added is not the the final score then something is wrong, and don't add it
        if type(services_final_score[service_id_to_add]) != ComputedScoreData:
            return
        score = services_final_score[service_id_to_add].score
        # If the score is N/A or the service is in maintenance, then don't add it to the calculation
        if score == ScoreCalculation.NOT_AVAILABLE or services_final_score[service_id_to_add].is_service_in_maintenance:
            return
        field = None
        if score <= float(20):
            field = 'critical'
        elif score <= float(40):
            field = 'high'
        elif score <= float(60):
            field = 'medium'
        elif score <= float(80):
            field = 'low'
        elif score <= float(100):
            field = 'normal'

        # No overrided urgency set by the ui
        if urgency == None:
            urgency = 11
        # Create a temporary record to simulate the service health score of another service
        temp_record = {
            'alert_level': self.DEFAULT_WEIGHTS[field].level,
            'urgency': urgency
        }
        # Get service health score record info
        self.get_kpi_health_score(temp_record)
        self._add_to_score_to_dict(
            services_final_score,
            service_id,
            temp_record['alert_level'],
            temp_record['urgency'],
            temp_record['boom_score'],
            temp_record['kpi_inverted_score'],
            None,
            is_service_in_maintenance=normalizeBoolean(services_final_score[service_id_to_add].is_service_in_maintenance)
        )

    def _cascade_service_health_calculation(self, sid, services_final_score, visit):
        """
        Goes through a service dependency chain until we reach a service without dependencies
        or a cycle, then calculate the final health score and cascade the results back up to the original service
        :param {string} sid: The service id of the service in the dependency chain
        :param {dict} services_final_score: dict which hold intermediate and final results
        :param {dict} visit: dict to track whether a service has been visited
        :return:
        """
        dep_service_list = self.service_depends_on_health_kpis_relationship.get(sid, None)
        # If the service has no more dependencies or is in maintenance mode, then we want to get the final calculation
        # and trickle it back up
        if not dep_service_list or (services_final_score.get(sid) and services_final_score.get(sid).is_service_in_maintenance):
            ScoreCalculation.get_final_score_per_service(sid, services_final_score)
            return
        for service_info in dep_service_list:
            if not services_final_score.get(service_info.service_id) or type(services_final_score[service_info.service_id]) == IntermediateScoreData:
                visit[sid] = True
                # We have found a cycle in the dependencies
                # Add the previous health score value to this service's calculation
                if visit.get(service_info.service_id, False):
                    prev_shkpi_record = self.shkpi_record_map.get(self._get_service_health_kpi_id(service_info.service_id), None)
                    # If we have a record for the previous health score for the kpi then use that
                    # otherwise ignore it and calculate the final health score for this service
                    if prev_shkpi_record:
                        prev_shkpi_record['urgency'] = service_info.urgency
                        # No overrided urgency set by the ui
                        if prev_shkpi_record['urgency'] == None:
                            prev_shkpi_record['urgency'] = 11
                        self.get_kpi_health_score(prev_shkpi_record)
                        self._add_to_score_to_dict(
                            services_final_score,
                            sid,
                            prev_shkpi_record['alert_level'],
                            prev_shkpi_record['urgency'],
                            prev_shkpi_record['boom_score'],
                            prev_shkpi_record['kpi_inverted_score'],
                            None,
                            is_service_in_maintenance=normalizeBoolean(prev_shkpi_record.get('is_service_in_maintenance', False))
                        )
                        continue
                else:
                    self._cascade_service_health_calculation(service_info.service_id, services_final_score, visit)
            self._add_health_score_record_to_calculation(service_info.urgency, sid, service_info.service_id, services_final_score)
        ScoreCalculation.get_final_score_per_service(sid, services_final_score)

    def _get_final_service_health_score(self, services_final_score):
        """
        Factor in health score dependencies and calculate
        :param {dict} services_final_score: dict which hold intermediate results to be converted to ComputedScoreData
        :return:
        """
        # If service dependents on service health kpi
        for service_id, dep_service_list in self.service_depends_on_health_kpis_relationship.iteritems():
            # service_info is tuple which hold first element as dependent service and second one is kpi service itself
            if not services_final_score.get(service_id) or type(services_final_score[service_id]) == IntermediateScoreData:
                for service_info in dep_service_list:
                    if not services_final_score.get(service_info.service_id) or type(services_final_score[service_info.service_id]) == IntermediateScoreData:
                        visit = {service_id: True}
                        self._cascade_service_health_calculation(service_info.service_id, services_final_score, visit)
                        del visit
                    self._add_health_score_record_to_calculation(service_info.urgency, service_id, service_info.service_id, services_final_score)
                ScoreCalculation.get_final_score_per_service(service_id, services_final_score)
        # Calculates the final scores for the services that don't have dependencies
        for sid, score_data in services_final_score.iteritems():
            if type(score_data) == IntermediateScoreData:
                ScoreCalculation.get_final_score_per_service(sid, services_final_score)

    def add_service_health_score_to_results(self, services_final_score):
        """
        Get final health score for service and send it to search pipeline
        :param {dict} services_final_score: hold intermediate results
        :return:
        """
        # Get score
        self._get_final_service_health_score(services_final_score)

        # Get Service Source which is not defined in summary index (means service with no kpi)
        for service in self.all_services:
            key = service.get('_key')
            name = service.get('title')
            enabled = service.get('enabled', 1)
            if key not in services_final_score:
                self.logger.debug('Found service with no kpi, title=%s, _key=%s', name, key)
                in_maintenance = self._is_service_currently_in_maintenance(key)
                score = (
                    self.DEFAULT_WEIGHTS[self.THRESHOLD_FILED_MAINTENANCE].health_max
                    if in_maintenance else self.NOT_AVAILABLE
                )
                services_final_score[key] = ComputedScoreData(score, name, in_maintenance, in_maintenance, enabled == 0)

        # Delete no longer required data
        del self.service_depends_on_health_kpis_relationship
        del self.service_depends_on_kpis_relationship

        # Generate results set
        for id_, data in services_final_score.iteritems():
            result = {}
            health_score = data.score
            service_name = data.name
            result[self.FIELD_SOURCETYPE_NAME] = self.FIELD_SERVICE_HEALTH_SOURCETYPE_VALUE
            for ki in self.FIELD_KPI_IDS:
                result[ki] = self._get_service_health_kpi_id(id_)
            result[self.FIELD_KPI_NAME] = self.HEALTH_SCORE_KPI_NAME_FOR_SERVICE

            for si in self.FIELD_SERVICE_IDS:
                result[si] = id_
            result[self.FIELD_SERVICE_NAME] = service_name
            in_maintenance = data.in_maintenance or data.is_service_in_maintenance
            self._get_health_fields(health_score, result, in_maintenance, data.is_disabled)
            self.logger.debug('Generated service score=%s for service:%s', health_score, service_name)
            self.logger.debug("Adding HealthScore for service='%s'", result)
            self.results.append(result)
        if services_final_score:
            for k in self.results[-1].keys():
                self.output_fields.add(k)

    def is_service_kpi_exists(self, itsi_kpi_id, itsi_service_id):
        """
        Check if kpi id and service id exist in KV store
        @param itsi_kpi_id: kpi id
        @param itsi_service_id: service id

        @rtype bool
        @return: True if exists otherwise False
        """
        if itsi_kpi_id in self.all_kpis and self.all_kpis[itsi_kpi_id] == itsi_service_id:
            return True
        else:
            return False

    def get_output_fields(self):
        """
        Returns a list of all the keys to be in the header for the output data

        @rtype list
        @return: a list of all keys to be output for the search
        """
        return list(self.output_fields)

    def execute(self):
        """
            Function which calculates all type of scores
            Splunk search should provide fields
                kpiid or itsi_kpi_id, serviceid or itsi_service_id, urgency, alert_level,  service name and kpi name

            Output results should have following fields
                _time, health_score, sourcetype (service_health_monitor for service), color, severity_label, serviceid,
                alert_severity(same as severity_label), gs_kpi_id, gs_service_id, severity_value
        """
        services_score = {}
        composite_scores = {}
        for record in self.records:
            # Filter records if kpi or service already deleted
            service_id = self._get_ids_field_value(record, self.FIELD_SERVICE_IDS)
            kpi_id = self._get_ids_field_value(record, self.FIELD_KPI_IDS)
            if not self.is_service_kpi_exists(kpi_id, service_id):
                self.logger.info('kpi_id=%s of service id=%s is deleted', kpi_id, service_id)
                continue
            if self._is_service_health_kpi(kpi_id):
                self.shkpi_record_map[kpi_id] = record
            else:
                # This call will implicitly edit the record by reference to encode the information
                self.get_kpi_health_score(record)
        for record in self.records:
            kpi_id = self._get_ids_field_value(record, self.FIELD_KPI_IDS)
            if not self._is_service_health_kpi(kpi_id):
                self.compute_composite_kpi_health_score(record, composite_scores)
                self.compute_service_health_score(record, services_score)
        # Add to results
        self.add_service_health_score_to_results(services_score)
        self.add_composite_kpi_score_to_results(composite_scores)
        del composite_scores
        del services_score
        return self.results
