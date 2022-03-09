# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from splunk.util import normalizeBoolean

from itsi.searches.itsi_searches import ItsiKpiSearches
from ITOA.itoa_object import ItoaObject
from ITOA.saved_search_utility import SavedSearch
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
from ITOA.itoa_exceptions import ItoaDatamodelContextError
import ITOA.itoa_common as utils

logger = utils.get_itoa_logger('itsi.object.kpi')

BASE_SEARCH_KPI_ATTRIBUTES = [
    'base_search',
    'search_alert_earliest',
    'is_entity_breakdown',
    'entity_id_fields',
    'entity_breakdown_id_fields',
    'entity_alias_filtering_fields',
    'alert_period',
    'alert_lag',
    'is_service_entity_filter',
    'metric_qualifier',
    'sec_grp'
    ]

BASE_SEARCH_METRIC_KPI_ATTRIBUTES = [
    'threshold_field',
    'unit',
    'entity_statop',
    'aggregate_statop'
    ]

DEFAULT_VALUE_KPI_ATTRIBUTES_DICT = {
    'search_alert_earliest': '5',
    'metric_qualifier': '',
    'alert_period': '5',
    'alert_lag': '30',
    '_owner': 'nobody'
}

ANOMALY_DETECTION_ATTRBUTES = [
    'anomaly_detection_is_enabled',
    'cohesive_anomaly_detection_is_enabled',
    'anomaly_detection_alerting_enabled',
    'trending_ad',
    'cohesive_ad'
]

GENERATED_SEARCH_ATTRIBUTES = [
    'search',
    'search_aggregate',
    'kpi_base_search',
    'search_entities',
    'search_time_series',
    'search_time_series_aggregate',
    'search_time_series_entities',
    'search_time_compare',
    'search_alert',
    'search_alert_entities'
]

BACKFILL_ATTRIBUTES = [
    'backfill_enabled',
    'backfill_earliest_time'
]

class ItsiKpi(ItoaObject):
    """
    Implements ITSI KPI
    """

    collection_name = 'itsi_services'

    def __init__(self, session_key, current_user_name):
        super(ItsiKpi, self).__init__(session_key, current_user_name, 'kpi', collection_name=self.collection_name)

    @staticmethod
    def get_kpi_threshold_fields(for_kvstore_fetch=False):
        """
        Get fields to store thresholds information in KPI.

        NOTE: Sorted by attribute value size (increasing order) for quick comparison. Maintain the order.

        @type for_kvstore_fetch: bool
        @param for_kvstore_fetch: True, if needs list of fields that can directly be passed
                                for kvstore fetch operation
                                False, if needs normal list of fields
        @return: list of fields
        """
        if not for_kvstore_fetch:
            return [
                'kpi_threshold_template_id',
                'tz_offset',
                'time_variate_thresholds',
                'adaptive_thresholds_is_enabled',
                'adaptive_thresholding_training_window',
                'gap_severity',
                'gap_severity_color',
                'gap_severity_value',
                'gap_severity_color_light',
                'aggregate_thresholds',
                'entity_thresholds',
                'time_variate_thresholds_specification',
            ]
        else:
            return [
                'kpis.kpi_threshold_template_id',
                'kpis.tz_offset',
                'kpis.time_variate_thresholds',
                'kpis.adaptive_thresholds_is_enabled',
                'kpis.adaptive_thresholding_training_window',
                'kpis.gap_severity',
                'kpis.gap_severity_color',
                'kpis.gap_severity_value',
                'kpis.gap_severity_color_light',
                'kpis.aggregate_thresholds',
                'kpis.entity_thresholds',
                'kpis.time_variate_thresholds_specification',
            ]

    @staticmethod
    def get_kpi_search_attributes(for_kvstore_fetch=False):
        """
        Get search attributes for a Service Template KPI.
        @type for_kvstore_fetch: bool
        @param for_kvstore_fetch: True, if needs list of fields that can directly be passed
                                for kvstore fetch operation
                                False, if needs normal list of fields
        @return: list of fields
        """
        if not for_kvstore_fetch:
            return [
                'base_search_id',
                'is_service_entity_filter',
                'is_entity_breakdown',
                'entity_breakdown_id_fields',
                'alert_period',
                'base_search',
                'search_alert_earliest',
                'title',
                'alert_lag',
                'unit',
                'entity_id_fields',
                'threshold_field',
                'entity_alias_filtering_fields',
                'search_type',
                'entity_statop',
                'base_search_metric',
                'aggregate_statop',
                'metric_qualifier'
            ]
        else:
            return [
                'kpis.base_search_id',
                'kpis.is_service_entity_filter',
                'kpis.is_entity_breakdown',
                'kpis.entity_breakdown_id_fields',
                'kpis.alert_period',
                'kpis.base_search',
                'kpis.search_alert_earliest',
                'kpis.title',
                'kpis.alert_lag',
                'kpis.unit',
                'kpis.entity_id_fields',
                'kpis.threshold_field',
                'kpis.entity_alias_filtering_fields',
                'kpis.search_type',
                'kpis.entity_statop',
                'kpis.base_search_metric',
                'kpis.aggregate_statop',
                'kpis.metric_qualifier'
            ]

    @staticmethod
    def get_kpi_saved_search_name(kpi_id):
        if not isinstance(kpi_id, basestring):
            message = _('Invalid type="%s" for kpi_id. Expecting string type.') % type(kpi_id).__name_
            logger.error(message)
            raise TypeError(message)
        return 'Indicator - ' + kpi_id  + ' - ITSI Search'

    def _populate_with_base_search_attr(self, kpi, sec_grp):
        """
        Populate given KPI object with base search attributes if applicable.

        @type kpi: dict
        @param kpi: kpi object to populate

        @type sec_grp: basestring
        @param sec_grp: security group of service

        @rtype: None
        @returns: Nothing. Given KPI object is modified in-place.
        """
        if not isinstance(kpi, dict):
            message = _('Invalid type="%s" for KPI. Expecting a dictionary.') % type(kpi).__name__
            logger.error(message)
            raise TypeError(message)

        if kpi.get('search_type') != 'shared_base':
            # guard against inadvertent call
            logger.warning('Search type="%s" not applicable. Will pass.', kpi.get('search_type'))
            return

        backend = self.storage_interface.get_backend(self.session_key)
        shared_base_search = backend.get(self.session_key, 'nobody', 'kpi_base_search', kpi.get('base_search_id'))

        if not isinstance(shared_base_search, dict):
            msg = _('Base search with id="%s" does not exist. No attributes to populate.') % kpi.get('base_search_id')
            logger.warning(msg)
            return

        if shared_base_search.get('sec_grp') not in [sec_grp, GLOBAL_SECURITY_GROUP_CONFIG.get('key')]:
            self.raise_error(logger, 'Shared base search configured on KPI "%s" does not match security ' \
                    'group of KPI/Service. Check the team on the service.' % kpi.get('title'))

        for attr in BASE_SEARCH_KPI_ATTRIBUTES:
            kpi[attr] = shared_base_search.get(attr, '')

        metrics = shared_base_search.get('metrics', [])
        for metric in metrics:
            if isinstance(metric, dict) and metric.get('_key') != kpi.get('base_search_metric'):
                continue # configured kpi isnt concerned with this metric
            for attr in BASE_SEARCH_METRIC_KPI_ATTRIBUTES:
                kpi[attr] = metric.get(attr, '')
            break # there can be only one selected metric, we got ours.
        return

    def _gen_and_update_searches(self, kpi, service_entity_rules, sec_grp):
        """
        Update KPI search strings for given KPI

        @type kpi: dict
        @param kpi: kpi object

        @type service_entity_rules: list
        @param service_entity_rules: entity rules corresponding to the service

        @type: basestring
        @param sec_grp: security group of the service

        @rtype: none
        @return: nothing. updates search strings in the KPI passed in.
        """
        # Now generate search strings for KPI & update the KPI.
        searches = ItsiKpiSearches(self.session_key,
                kpi, service_entity_rules, sec_grp=sec_grp).gen_kpi_searches(gen_alert_search=True)

        kpi['kpi_base_search'] = searches['kpi_base_search']
        kpi['search'] = searches['alert_search']
        kpi['search_aggregate'] = searches['single_value_search']
        kpi['search_entities'] = searches['single_value_search']
        kpi['search_time_series'] = searches['time_series_search']
        kpi['search_time_series_aggregate'] = searches['time_series_search']
        kpi['search_time_series_entities'] = searches['entity_time_series_search']
        kpi['search_time_compare'] = searches['compare_search']
        kpi['search_alert'] = searches['alert_search']

        # Assume search fields are always present
        if kpi.get('search_type', 'adhoc') == 'datamodel':
            # Assume default to be true to avoid accidental overwrite here
            # User specifies base_search for adhoc searches but is generated
            # for datamodel searches, so set it explicitly after generation
            kpi['base_search'] = kpi['kpi_base_search']

        # KPI thresholds searches need to be updated too.
        # we do not need to save search strings in threshold objects
        if (isinstance(kpi.get('aggregate_thresholds'), dict) and
            isinstance(kpi['aggregate_thresholds'].get('search'), basestring)):
            kpi['aggregate_thresholds']['search'] = ''

        if (isinstance(kpi.get('entity_thresholds'), dict) and
            isinstance(kpi['entity_thresholds'].get('search'), basestring)):
            kpi['entity_thresholds']['search'] = ''

        # KPI time variate threshold searches need to be updated too
        policies = kpi.get('time_variate_thresholds_specification', {}).get('policies', {}).itervalues()
        for policy in policies:
            if isinstance(policy, dict):
                aggregate_thresholds = policy['aggregate_thresholds']
                if 'search' in aggregate_thresholds:
                    aggregate_thresholds['search'] = ''
                entity_thresholds = policy['entity_thresholds']
                if 'search' in entity_thresholds:
                    entity_thresholds['search'] = ''
        return

    def populate(self, kpi, service_entity_rules, service_id, service_title, service_is_enabled, sec_grp):
        """
        populate a KPI object.
        @type kpi: dict
        @param kpi: kpi object

        @type service_entity_rules: list
        @param service_entity_rules: entity rules for service

        @type service_id: basestring
        @param service_id: identifier of the service

        @type service_title: basestring
        @param service_title: title of the service

        @type service_is_enabled: boolean
        @param service_is_enabled: Indicates if service is enabled or disabled.

        @type: basestring
        @param sec_grp: security group of the service

        @rtype None
        @returns: nothing. in-place population.
        """
        if not isinstance(kpi, dict):
            raise TypeError(_('Invalid type for kpi. Expecting a dictionary.'))
        if not isinstance(service_entity_rules, list):
            # if service_entity_rules is set to none explictly, convert to list
            if service_entity_rules is None:
                service_entity_rules = []
            else:
                raise TypeError(_('Invalid type for service_entity_rules. Expecting valid list'))
        if not isinstance(service_id, basestring):
            raise TypeError(_('Invalid type for service_id. Expecting valid string.'))
        if not isinstance(service_title, basestring):
            raise TypeError(_('Invalid type for service_title. Expecting valid string.'))
        if not isinstance(service_is_enabled, int):
            raise TypeError(_('Invalid type for service_is_enabled. Expecting int.'))

        if 'search_occurrences' in kpi:
            kpi['search_occurrences'] = int(kpi['search_occurrences']) # Convert to valid number

        kpi['service_id'] = service_id
        kpi['service_title'] = service_title
        kpi['enabled'] = service_is_enabled

        if kpi.get('search_type') == 'shared_base':
            self._populate_with_base_search_attr(kpi, sec_grp)

        self._gen_and_update_searches(kpi, service_entity_rules, sec_grp)

        # cleanup temporary keys added.
        kpi.pop('service_id', None)
        kpi.pop('service_title', None)

    def generate_saved_search_settings(self, kpi, service_entity_rules, sec_grp, acl_update=True):
        """
        Generate a dictionary represeting settings (kv pairs) for a savedsearches.conf stanza

        @type kpi: dict
        @param kpi: corresponding kpi object

        @type service_entity_rules: list
        @param service_entity_rules: entity rules for the given service

        @type: basestring
        @param sec_grp: security group of the service

        @rtype: dict
        @param: requested saved search settings
        """
        saved_search_settings = {}
        saved_search_id = self.get_kpi_saved_search_name(kpi['_key'])
        saved_search_settings['name'] = saved_search_id

        # NOTE: for savedsearches.conf, we will always generate entity filter in search strings.
        searches = ItsiKpiSearches(
                self.session_key,
                kpi, service_entity_rules,
                generate_entity_filter=True,
                sec_grp=sec_grp
        ).gen_kpi_searches(
                gen_alert_search=True
        )
        saved_search_settings['search'] = searches['alert_search']

        saved_search_settings['description'] = 'Auto created scheduled search during kpi creation'
        saved_search_settings['disabled'] = '0' if kpi.get('enabled') == 1 else '1'

        # Handle the timing of a KPI search, some data may not be coming in real time so we allow for a
        # configurable lag in the KPI search up to 30 minutes, our values are in seconds for lag, minutes for
        # earliest, so we convert all searches to seconds based time modifiers
        alert_lag = int(kpi.get('alert_lag', 30))
        alert_earliest = int(kpi.get('search_alert_earliest', 5)) * 60
        if alert_lag == 0:
            # Real Time case we need to set latest time to now
            saved_search_settings['dispatch.earliest_time'] = '-' + str(alert_earliest) + 's'
            saved_search_settings['dispatch.latest_time'] = 'now'
        elif alert_lag <= 1800:
            # Normal Case, adjust search timing to account for the lag
            saved_search_settings['dispatch.earliest_time'] = '-' + str(alert_earliest + alert_lag) + 's'
            saved_search_settings['dispatch.latest_time'] = '-' + str(alert_lag) + 's'
        else:
            raise ValueError(_("Invalid alert_lag passed to saved search management, must be below 30 minutes"))

        saved_search_settings['enableSched'] = '1'

        # Regenerate a random cron every time in order to take into account a change in the alert period
        # Technically this means on save there is a potential for a kpi to execute slightly off rhythm at
        # the point of save if the start point of the cron changes for a 5 or 15 period kpi
        saved_search_settings['cron_schedule'] = SavedSearch.generate_cron_schedule(kpi.get('alert_period', 5))

        saved_search_settings['alert.suppress'] = '0'
        saved_search_settings['alert.track'] = '0'
        saved_search_settings['alert.digest_mode'] = '1'

        saved_search_settings['actions'] = 'indicator'
        saved_search_settings['action.indicator._itsi_kpi_id'] = kpi.get('_key', '')
        saved_search_settings['action.indicator._itsi_service_id'] = kpi.get('service_id', '')
        saved_search_settings['kpi_title'] = kpi.get('title', '')
        saved_search_settings['acl_update'] = acl_update
        return saved_search_settings

    def check_perc_value(self, statop):
        """
        Checks for valid stats operator.
        If the stats operator is percNN, make sure NN is within the valid percentage range
        @type statop: string
        @param statop: stats operator
        @type return: None
        @param return: raises exceptions on invalid stats operators
        """
        if not utils.is_stats_operation(statop):
            self.raise_error_bad_validation(
                    logger,
                    'An invalid aggregation operator is specified for a KPI. Please check ITSI doc for a list' \
                    'of valid operators and syntax.'
            )

        # if the statop is 'percNN', validate the percentage range
        # the format of string 'perc' has already been validated by is_stats_operation()
        if 'perc' in statop:
            if not utils.is_valid_perc(statop[4:]):
                self.raise_error_bad_validation(
                        logger,
                        'Invalid percentile value enter, the value has to be a whole number between ' \
                        '1 and 99'
                )

    def _set_entity_breakdown_field(self, kpi):
        """
        Set entity_breakdown_id_fields to entity_id_fields,
        if entity_breakdown_id_fields is missing or empty.
        @param kpi: kpi object
        @return: None
        """
        # PBL-5603: changes made in this story, allow user to split KPI by a different entity field from
        # entity filtering field. As a part of this change, new field 'entity_breakdown_id_fields'
        # was added to kpi object. To guard against migration issues and cases where
        # 'entity_breakdown_id_fields' would be missing in kpi object, added following check. We fall back
        # to 'entity_id_fields', in cases when 'entity_breakdown_id_fields' is missing.
        if kpi.get('is_entity_breakdown', False):
            entity_breakdown_id_fields = kpi.get('entity_breakdown_id_fields', None)
            if entity_breakdown_id_fields is None or len(entity_breakdown_id_fields) == 0:
                kpi['entity_breakdown_id_fields'] = kpi.get('entity_id_fields', '')
                logger.debug('entity_breakdown_id_fields missing from kpi object = {}. '
                             'Setting it to entity_id_fields.'.format(kpi.get('_key')))

    def validate_kpi_basic_structure(self, kpi, for_base_service_template=False):
        """
        Validate only the KPI level validation, skips any validation that depends on parent object.
        @type kpi: iterable list
        @param kpi: a valid list of KPIs in json format
        @type return: None
        @param return: None, raise exceptions on invalid KPIs
        """
        if not utils.is_valid_str(kpi.get('title')):
            self.raise_error_bad_validation(logger, 'KPIs must have a valid title.')

        ITOAInterfaceUtils.validate_aggregate_thresholds(kpi)
        ITOAInterfaceUtils.validate_entity_thresholds(kpi)

        if not for_base_service_template:
            field_validation_list = ['backfill_enabled',
                                     'time_variate_thresholds',
                                     'adaptive_thresholds_is_enabled',
                                     'anomaly_detection_is_enabled',
                                     'cohesive_anomaly_detection_is_enabled',
                                     'anomaly_detection_alerting_enabled']

        else:  # do not need to validate backfill fields for Base Service Template KPIs
            field_validation_list = ['time_variate_thresholds',
                                     'adaptive_thresholds_is_enabled',
                                     'anomaly_detection_is_enabled',
                                     'cohesive_anomaly_detection_is_enabled',
                                     'anomaly_detection_alerting_enabled']

        for field_name in field_validation_list:
            if field_name not in kpi:
                kpi[field_name] = False
            else:
                field_value = kpi[field_name]
                kpi[field_name] = normalizeBoolean(field_value, enableStrictMode=True)

        alert_on = kpi.get('alert_on')
        if alert_on and alert_on not in ['aggregate', 'entity', 'both']:
            kpi['alert_on'] = 'aggregate'

        alert_period = kpi.get('alert_period')
        if alert_period and (utils.is_string_numeric(alert_period) or utils.is_valid_num(alert_period)):
            kpi['alert_period'] = int(alert_period)

        self._set_entity_breakdown_field(kpi)

        # Validate if minimal fields for search are populated
        if 'search_type' in kpi:
            search_type = kpi['search_type']
            if search_type != 'datamodel':
                if not utils.is_valid_str(kpi.get('base_search')):
                    self.raise_error_bad_validation(
                        logger,
                        'Adhoc search KPIs does not seem to have populated a base search. ' \
                        'Specify a base search for the KPI.'
                    )

                if not utils.is_valid_str(kpi.get('threshold_field')):
                    self.raise_error_bad_validation(
                        logger,
                        'A valid threshold field is not specified for a KPI with adhoc search. ' \
                        'Threshold fields must be specified for adhoc search based KPIs.'
                    )
            else: # Datamodel search based KPI
                datamodel_search_spec = kpi.get('datamodel')
                if not utils.is_valid_dict(datamodel_search_spec):
                    self.raise_error_bad_validation(
                        logger,
                        'Datamodel search KPIs do not seem to have specified a datamodel search. ' \
                        'Specify a datamodel based search for the KPI.'
                    )

                if (not (utils.is_valid_str(datamodel_search_spec.get('datamodel')) and
                    utils.is_valid_str(datamodel_search_spec.get('object')) and
                    utils.is_valid_str(datamodel_search_spec.get('field')) and
                    utils.is_valid_str(datamodel_search_spec.get('owner_field'))
                    )):
                    self.raise_error_bad_validation(
                        logger,
                        'Datamodel search based KPI does not seem to have specified a valid datamodel search. ' \
                            'Specify datamodel based search KPIs with all mandatory fields: ' \
                            'datamodel, object, field and owner_field.'
                    )

                datamodel_filters = kpi.get('datamodel_filter', [])
                if not utils.is_valid_list(datamodel_filters):
                    self.raise_error_bad_validation(
                        logger,
                        'Datamodel filters must be an array of filters. ' \
                            'Found a KPI with an invalid specification for datamodel filters.'
                    )

                for datamodel_filter in datamodel_filters:
                    if not utils.is_valid_dict(datamodel_filter):
                        self.raise_error_bad_validation(
                            logger,
                            'Each datamodel filter must be a valid JSON filter specification. ' \
                                    'Found a KPI with an invalid specification for a datamodel filter.'
                        )

                    if not (utils.is_valid_str(datamodel_filter.get('_field')) and
                        utils.is_valid_str(datamodel_filter.get('_value'))):
                        self.raise_error_bad_validation(
                            logger,
                            'Each datamodel filter must specify a field and value. ' \
                                'Found a KPI with no field or value specified for a datamodel filter.'
                        )

                    filter_operator = datamodel_filter.get('_operator')
                    if not (utils.is_valid_str(filter_operator) and (filter_operator in ['=', '>', '<'])):
                        self.raise_error_bad_validation(
                            logger,
                            'Each datamodel filter operator must be =, < or >. ' \
                                'Found a KPI with invalid operator specified for a datamodel filter.'
                        )

        # aggregate_statop is a mandatory field, check the syntax
        aggregate_statop = kpi.get('aggregate_statop')
        if isinstance(aggregate_statop, basestring):
            self.check_perc_value(aggregate_statop)
        else:
            #We can infer it from the old statop field if that is present
            old_statop = kpi.get('statop')
            if isinstance(old_statop, basestring):
                self.check_perc_value(old_statop)
                kpi['aggregate_statop'] = old_statop
            else:
                self.raise_error_bad_validation(
                    logger,
                    'A valid aggregation operator is not specified for a KPI. Aggregate operator must be specified.'
                )

        # entity_statop is an optional field, need to check syntax if it exists
        entity_statop = kpi.get('entity_statop')
        if isinstance(entity_statop, basestring):
            self.check_perc_value(entity_statop)

        alert_lag = kpi.get('alert_lag')
        try:
            if alert_lag is not None:
                alert_lag = int(alert_lag)
        except:
            self.raise_error_bad_validation(
                logger,
                'Invalid alert_lag, must be a positive integer less than 1800 (in s = 30 minutes).'
            )

        if not alert_lag < 1800:
            # 30 minutes enforced due to restrictions of the health scoring system for services
            self.raise_error_bad_validation(
                logger,
                'Invalid alert_lag, must be a positive integer less than 1800 (in s = 30 minutes). ' \
                    'Specified: {0}'.format(alert_lag)
            )

    def convert_invalid_datamodel_kpi_to_adhoc(self, kpi, cached_datamodel_dict):
        """
        Fix up datamodel KPIs with invalid datamodels - this is to avoid errors during saving in several scenarios
        IMPORTANT: this should really be used only in upgrade scenarios. In standard configuration, this is not needed.
        @type kpi: dict
        @param kpi: a single KPI

        @type cached_datamodel_dict: dict
        @param kpi: a prefetched list of datamodels

        @type return: boolean
        @param return: True if a conversion was performed
        """
        if kpi.get('search_type', '') == 'datamodel':
            try:
                datamodel_spec = kpi.get('datamodel', {})
                ItsiKpiSearches.get_datamodel_context(self.session_key,
                    'nobody',
                    datamodel_spec.get('field'),
                    datamodel_spec.get('datamodel'),
                    datamodel_object_name=datamodel_spec.get('object'),
                    cached_datamodel_dict=cached_datamodel_dict)

            except ItoaDatamodelContextError as e:
                '''
                Mark the searches as invalid adhoc searches to provide a cue in KPI config. Altering the search
                is needed since an invalid datamodel search will fail saved search creation.
                '''
                kpi['search_type'] = 'adhoc'
                kpi['base_search'] = 'Invalid datamodel search "' + kpi.get('base_search', '') + '"'

                logger.error('Found KPI (Id: %s) with stale datamodel specification. Auto converting ' \
                    'this KPI to adhoc search type to prevent migration/upgrade failures.', kpi.get('_key'))
                return True

        return False
