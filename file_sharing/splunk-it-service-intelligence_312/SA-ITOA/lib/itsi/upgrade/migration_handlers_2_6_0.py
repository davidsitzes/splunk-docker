# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.util import localTZ
from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
from ITOA.itoa_factory import instantiate_object
from ITOA.itoa_common import is_valid_str, normalize_num_field
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_time_block_utils import ItsiTimeBlockUtils, CRON_ELEMENT_TYPES
from ITOA.event_management.hec_utils import HECUtil
from migration.migration import MigrationFunctionAbstract

logger = setup_logging('itsi_migration.log', 'itsi.migration')

def _get_local_tz_offset_to_utc_sec():
    """
    Identifies the seconds offset to apply to an epoch to convert it from local server timezone to UTC

    @rtype: float
    @return: the offset in seconds of the local server's timezone from UTC
    """
    local_tz_offset = localTZ.utcoffset(localTZ)
    return float((local_tz_offset.days * 24 * 3600) + local_tz_offset.seconds)


_local_server_utc_offset = _get_local_tz_offset_to_utc_sec()


"""
UI interprets indefinite end time for maintenance windows as JS Date(2038, 0, 18)
The epoch value for JS Date(2038, 0, 18) can vary for different timezones
The minimum value for indefinite maintenance window epoch will therefore be considered
JS Date(2038, 0, 18) - 24 hours (maximum possible timezone offset) = 2147414400 - 86400 = 2147328000
Backend will consider any epoch end time greater than 2147328000 as indefinite end time
"""
_maintenance_calendar_min_indefinite_end_time = 2147328000


def _is_maintenance_end_time_indefinite(maintenance_calendar_json):
    """
    Helper method to detect if maintenance calendar is configured with indefinite end time

    @type maintenance_calendar_json: JSON dict
    @param maintenance_calendar_json: JSON payload of maintenance configuration

    @rtype: boolean
    @return: True if yes, False if no
    """
    if not isinstance(maintenance_calendar_json, dict):
        return False

    end_time = maintenance_calendar_json.get('end_time')
    if isinstance(end_time, str) or isinstance(end_time, int):
        try:
            end_time = float(end_time)
        except (TypeError, ValueError):
            # Ignore any conversion failures
            pass
    return isinstance(end_time, float) and end_time >= _maintenance_calendar_min_indefinite_end_time


def apply_timezone_offset(json_data, json_field, offset_in_sec):
    """
    Utility method to apply a timezone offset to an epoch field

    @type json_data: json dict
    @param json_data: the payload to update

    @type json_field: basestring
    @param json_field: the name of the field in the payload containing epoch value to update

    @type offset_in_sec: float
    @param offset_in_sec: the seconds offset to apply to the epoch

    @rtype: None
    @return: None, the json payload is updated in place
    """
    if not isinstance(json_data, dict):
        message = _('json_data is not a valid dictionary, found type %s. Cannot apply timezone offset.') % type(
            json_data).__name__
        logger.error(message)
        raise TypeError(message)

    if not isinstance(json_field, basestring):
        message = _('json_field is not a valid string, found type %s. Cannot apply timezone offset.') % type(
            json_field).__name__
        logger.error(message)
        raise TypeError(message)

    if not (isinstance(offset_in_sec, float) or isinstance(offset_in_sec, int)):
        message = _('offset_in_sec is not a valid number, found type %s. Cannot apply timezone offset.') % type(
            offset_in_sec).__name__
        logger.error(message)
        raise TypeError(message)

    if json_field in json_data:
        normalize_num_field(json_data, json_field, numclass=float)
        json_data[json_field] += offset_in_sec


class ServiceSchemaCronMigrator(MigrationFunctionAbstract):
    """
    Migration handler for migrating service schema for:
    1. Service Schema Optimization.
        KPIs subojects in kvstore where "filter by entities" is enabled will no
        longer have a constructed entity filter in search strings but will
        instead contain a splunk sub-search. This will populate the required
        entity filter at search time rather than saving it in kvstore.
        savedsearches.conf though, will continue to have this filter generated.
    2. Service enable/disable
        Existing services will be marked enabled.
    3. Timezone updates to time blocks
        Migration handling for KPIs to convert currently stored local server time based policy time blocks
        to UTC per timezone handling feature in ITOA-5881. Note that policy time blocks were set pre-2.5.0
        in UI using browser timezone hence the need for this migration as a best effort for cases where browser time
        is same as server time. Users should use KV store to JSON tool to set to required offset in addition if needed.
    """
    def __init__(self, session_key, owner=None):
        """
        @type session_key: basestring
        @param session_key: splunkd session key

        @type owner: basestring
        @param owner: context.
        """
        super(ServiceSchemaCronMigrator, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'

    @staticmethod
    def apply_timezone_offset(service, offset_in_min):
        """
        Given the number of hours needed to offset timeblocks, apply the change to all KPIs in a service

        @type service: object
        @param service: Service object instance to update

        @type offset_in_min: int
        @param offset_in_min: the # of hours of offset to apply

        @rtype: None
        @return: None although service input reference will be updated
        """
        # Compute the day/hour/minute change as needed for the time blocks based on the offset
        if not (-1440 <= offset_in_min <= 1440):
            message = _('Timezone offset specified looks invalid, must be within 24 hour aka 1440 minute range. Specified value: %s ') % offset_in_min
            logger.error(message)
            raise ValueError(message)

        if not isinstance(service, dict):
            message = _('Service is not a valid dictionary, found type %s. Cannot apply timezone offset.') % type(service).__name__
            logger.error(message)
            raise TypeError(message)

        if not isinstance(offset_in_min, int):
            message = _('offset_in_min is not a valid int, found type %s. Cannot apply timezone offset.') % type(offset_in_min).__name__
            logger.error(message)
            raise TypeError(message)

        # Only migrate valid time blocks, ignore bad config
        for kpi in service.get('kpis', []):
            if not isinstance(kpi, dict):
                logger.warn('KPI looks invalid, skipping timezone offset adjustment for KPI "%s"', kpi)
                continue  # Ignore

            policy_spec = kpi.get('time_variate_thresholds_specification')
            if not isinstance(policy_spec, dict):
                logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                continue  # Ignore

            policies = policy_spec.get('policies')
            if not isinstance(policies, dict):
                logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                continue  # Ignore

            for policy_key, policy in policies.iteritems():
                if not isinstance(policy, dict):
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                time_blocks = policy.get('time_blocks')
                if not isinstance(time_blocks, list):
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                new_time_blocks = []
                for time_block in time_blocks:
                    try:
                        # validate time block before applying offset
                        ItsiTimeBlockUtils.expand_time_block(time_block)
                    except Exception as e:
                        logger.exception(e)
                        logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                        continue  # Ignore

                    # expand time block into time blocks with single numbers only aka no ranges
                    expanded_time_blocks = ItsiTimeBlockUtils.expand_time_block_cron(time_block)
                    if not len(expanded_time_blocks) > 0:
                        logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                        continue  # Ignore

                    shifted_time_blocks = []
                    for expanded_time_block in expanded_time_blocks:
                        split_time_block_cron = expanded_time_block[0].split(' ')

                        expanded_time_block_min = int(split_time_block_cron[CRON_ELEMENT_TYPES.index('minute')])
                        expanded_time_block_hour = int(split_time_block_cron[CRON_ELEMENT_TYPES.index('hour')])
                        expanded_time_block_day = int(split_time_block_cron[CRON_ELEMENT_TYPES.index('day_of_week')])

                        new_time_block_min = (expanded_time_block_min + offset_in_min) % 60
                        overflow_hours = (expanded_time_block_min + offset_in_min) / 60
                        new_time_block_hour = (expanded_time_block_hour + overflow_hours) % 24
                        overflow_days = (expanded_time_block_hour + overflow_hours) / 24
                        new_time_block_day = (expanded_time_block_day + overflow_days) % 7

                        new_time_block = [
                            ' '.join([
                                str(new_time_block_min),
                                str(new_time_block_hour),
                                '*',
                                '*',
                                str(new_time_block_day)
                            ]),
                            expanded_time_block[1]
                        ]
                        shifted_time_blocks.append(new_time_block)

                    # collapse shifted time blocks into a single time block
                    list_of_days = [int(shifted_time_block[0].split(' ')[CRON_ELEMENT_TYPES.index('day_of_week')]) for shifted_time_block in shifted_time_blocks]
                    collapsed_list_of_days = ItsiTimeBlockUtils.convert_numbers_to_cron_element(list_of_days)

                    first_time_block = shifted_time_blocks[0]
                    first_split_time_block_cron = first_time_block[0].split(' ')
                    time_block_to_add = [
                        ' '.join([
                            str(first_split_time_block_cron[0]),
                            str(first_split_time_block_cron[1]),
                            '*',
                            '*',
                            collapsed_list_of_days
                        ]),
                        first_time_block[1]
                    ]

                    new_time_blocks.append(time_block_to_add)

                kpi['time_variate_thresholds_specification']['policies'][policy_key]['time_blocks'] = new_time_blocks

    @staticmethod
    def convert_time_blocks(service):
        """
        Go through KPIs in service, convert time blocks to new schema, and remove old time blocks
        Note: This method edits service in place

        @type service: dict
        @param service: service that holds KPIs to update
        """
        for kpi in service.get('kpis', []):
            if not isinstance(kpi.get('time_variate_thresholds_specification'), dict):
                logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                continue  # Ignore
            if not isinstance(kpi['time_variate_thresholds_specification'].get('time_blocks'), list):
                logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                continue  # Ignore

            # convert time blocks to new schema
            converted_time_blocks = ItsiTimeBlockUtils.convert_hour_time_blocks(kpi['time_variate_thresholds_specification'].get('time_blocks'))
            # update existing policies with converted time blocks
            for policy_key, policy_time_blocks in converted_time_blocks.iteritems():
                # set time blocks as converted time blocks aka the new schema
                kpi['time_variate_thresholds_specification']['policies'][policy_key]['time_blocks'] = policy_time_blocks
            # remove old time blocks structure as it is now useless
            try:
                del kpi['time_variate_thresholds_specification']['time_blocks']
            except Exception:
                logger.exception('Failed to delete KPI threshold template, kpi["time_variate_thresholds_specification"]["time_blocks"] may not exist for policy')

    @staticmethod
    def convert_time_blocks_thresholds(threshold_template):
        """
        Go through a threshold template, convert time blocks to new schema, and remove old time blocks
        Note: This method edits threshold_templates in place

        @type threshold: dict
        @param threshold_template: a time variant threshold template that holds KPIs to update
        """
        if not isinstance(threshold_template.get('time_variate_thresholds_specification'), dict):
            logger.warn('template time block policy looks invalid, threshold specification is not a dict: %s', threshold_template.get('time_variate_thresholds_specification'))
        if not isinstance(threshold_template.get('time_variate_thresholds_specification').get('time_blocks'), list):
            logger.warn('template time block policy looks invalid, time_blocks are not a list: %s', threshold_template['time_variate_thresholds_specification'].get('time_blocks'))

        # convert time blocks to new schema
        converted_time_blocks = ItsiTimeBlockUtils.convert_hour_time_blocks(threshold_template['time_variate_thresholds_specification'].get('time_blocks'))
        # update existing policies with converted time blocks
        for policy_key, policy_time_blocks in converted_time_blocks.iteritems():
            # set time blocks as converted time blocks aka the new schema
            threshold_template['time_variate_thresholds_specification']['policies'][policy_key]['time_blocks'] = policy_time_blocks
        # remove old time blocks structure as it is now useless
        try:
            del threshold_template['time_variate_thresholds_specification']['time_blocks']
        except Exception:
            logger.exception('Failed to delete threshold template, kpi["time_variate_thresholds_specification"]["time_blocks"] may not exist for policy')

    def _fetch_and_migrate(self):
        """
        Fetch all services and do required migration.
        @rtype: boolean/None
        @return True on success. False/None on failure.
        """
        statusTemplate = None
        statusService = None
        try:
            logger.info('Starting migration of KPI Threshold Templates collection')
            # get all threshold templates
            threshold_template_itr = self.get_object_iterator('kpi_threshold_template', get_raw=True)
            all_templates = []
            for threshold_template in threshold_template_itr:
                # convert time variant thresholds collection from old schema to new, cron-based schema
                ServiceSchemaCronMigrator.convert_time_blocks_thresholds(threshold_template)
                all_templates.append(threshold_template)

            # save the threshold templates back
            statusTemplate = self.save_object('kpi_threshold_template', all_templates)
        except Exception:
            logger.exception('Failed to migrate service schema')
            message = _('Failed to migrate service schema to 2.6.0. Unable to save. Please check ITSI internal logs.')
            ITOAInterfaceUtils.create_message(self.session_key, message)
        logger.info('No exceptions when saving threshold template changes. Save status=%s', statusTemplate)

        try:
            logger.info('Starting migration of Service KPI Threshold')
            # get all services
            service_itr = self.get_object_iterator('service', get_raw=True)
            all_services = []
            for service in service_itr:
                # convert time variant thresholds structure from old schema to new, cron-based schema
                ServiceSchemaCronMigrator.convert_time_blocks(service)
                all_services.append(service)

            # save all services, this should help with optimizing the service
            statusService = self.save_object('service', all_services)
        except Exception:
            logger.exception('Failed to migrate service schema')
            message = _('Failed to migrate service schema to 2.6.0. Unable to save. Please check ITSI internal logs.')
            ITOAInterfaceUtils.create_message(self.session_key, message)
        logger.info('No exceptions when saving services changes. Save status=%s', statusService)
        return statusService and statusTemplate

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._fetch_and_migrate()


def migrate_timezones_tool(splunkd_session_key, tool_options):
    """
    In addition to the above migration handlers, we need a manual tool for admins to apply timezone offsets
    to objects that were configures in browser timezone which we cannot auto detect. This tool will be exposed
    as a mode in existing kvstore_to_json tool. But keeping its implementation logic here owing to relevance
    in this migration code

    Performs timezone offset operations for mode 3 of the tool

    @param splunkd_session_key: Session key for Splunkd operations

    @param tool_options: options passed in from the tool

    @return: None, output is written to stdout
    """
    owner = 'nobody'

    # Validate group options
    object_type = tool_options.object_type
    object_title = tool_options.object_title
    is_get = tool_options.is_get

    tz_logger = setup_logging('itsi_config.log', 'itsi.timezone.operations', is_console_header=True)

    object_title_filter = None
    if is_valid_str(object_title):
        object_title_filter = {'title': object_title}

    try:
        object_type_instance = instantiate_object(splunkd_session_key, owner, object_type, logger=tz_logger)
    except Exception as e:
        logger.exception(e)
        raise Exception(_('Specified object type "%s" seems invalid.') % object_type)

    objects = object_type_instance.get_bulk(owner, filter_data=object_title_filter)

    if len(objects) < 1:
        print 'No objects matched request. Stopping here'
        return

    print '\n%s object(s) match request' % len(objects) if objects is not None else 0
    if is_get:
        print 'Retrieved requested object(s):\n' + str(objects)
    else:
        print 'Applying timezone change on requested object(s): ' + str([data.get('title') for data in objects])
        object_attributes_map = {
            'maintenance_calendar': ['start_time', 'end_time']
        }

        offset_in_sec = None
        try:
            offset_in_sec = float(tool_options.offset_in_sec)
        except:
            pass  # Will detect below and show meaningful error
        if not isinstance(offset_in_sec, float):
            raise Exception(_('Specified timezone offset to apply is invalid. Please pick an number.'))

        for json_data in objects:
            if object_type == 'service':
                ServiceSchemaCronMigrator.apply_timezone_offset(json_data, int(offset_in_sec / 60))
            else:
                for json_field in object_attributes_map[object_type]:
                    # Only convert offset if end_time is not set to "Indefinite" for maintenance calendars

                    if (
                        object_type == 'maintenance_calendar' and
                        json_field == 'end_time' and
                        _is_maintenance_end_time_indefinite(json_data)
                    ):
                        continue
                    apply_timezone_offset(json_data, json_field, offset_in_sec)

        object_type_instance.save_batch(owner, objects, True)
        print 'Timezone offset has been applied on the objects requested.\n'


class HecTokenHandler(MigrationFunctionAbstract):
    """
    This class is being used to delete old itsi_group_alerts_sync_token
    """

    def __init__(self, session_key, token_name, index, host=None, source=None, sourcetype=None,
                 app='itsi', is_use_ack=False, owner=None):
        """
        @type session_key: basestring
        @param session_key: splunkd session key

        @type owner: basestring
        @param owner: context.
        """
        super(HecTokenHandler, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'
        self.hec_utils = HECUtil(self.session_key)
        self.token_name = token_name
        self.index = index
        self.host = host
        self.source = source
        self.sourcetype = sourcetype
        self.app = app
        self.is_use_ack = is_use_ack

    def _post_error_message(self):
        """
        Post error message
        @return None
        """
        msg = _("Failed to delete the HEC token {0} during upgrade. To proceed, you must delete this token manually.").format(
            self.token_name)
        logger.error(msg)
        ITOAInterfaceUtils.create_message(self.session_key, msg)

    def _delete_token(self):
        """
        Delete token
        @return boolean flag (always true for now)
        """
        if self.token_name is None:
            return  # nothing to delete
        try:
            ret = self.hec_utils.delete_token(self.token_name)
            if ret:
                logger.info("Successfully delete %s hec token", self.token_name)
                # create one to cover case when migration run after initial hec_init modular input. If we do not do it
                # user need to wait for 10 mins
                self.hec_utils.setup_hec_token(session_key=self.session_key, token_name=self.token_name,
                                               index=self.index, host=self.host, source=self.source,
                                               app=self.app, sourcetype=self.sourcetype, is_use_ack=self.is_use_ack)
            else:
                self._post_error_message()
        except Exception as e:
            logger.exception(e)
            self._post_error_message()
        finally:
            return True

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._delete_token()

