# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time

from splunk.util import localTZ
from splunk.appserver.mrsparkle.lib import i18n

from ITOA.itoa_common import normalize_num_field, get_current_utc_epoch
from migration.migration import MigrationFunctionAbstract
from ITOA.setup_logging import setup_logging
from itsi.itsi_utils import ITOAInterfaceUtils, SECURABLE_OBJECT_LIST
from ITOA.itoa_common import is_valid_str
from ITOA.itoa_factory import instantiate_object

logger = setup_logging("itsi_migration.log", "itsi.migration")


def _get_local_tz_offset_to_utc_sec():
    """
    Identifies the seconds offset to apply to an epoch to convert it from local server timezone to UTC

    @rtype: float
    @return: the offset in seconds of the local server's timezone from UTC
    """
    local_tz_offset = localTZ.utcoffset(localTZ)
    return float((local_tz_offset.days * 24 * 3600) + local_tz_offset.seconds)

_local_server_utc_offset = _get_local_tz_offset_to_utc_sec()
'''
UI interprets indefinite end time for maintenance windows as JS Date(2038, 0, 18)
The epoch value for JS Date(2038, 0, 18) can vary for different timezones
The minimum value for indefinite maintenance window epoch will therefore be considered
JS Date(2038, 0, 18) - 24 hours (maximum possible timezone offset) = 2147414400 - 86400 = 2147328000
Backend will consider any epoch end time greater than 2147328000 as indefinite end time
'''
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
        except TypeError, ValueError:
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


class ServiceSchemaMigrator(MigrationFunctionAbstract):
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
        super(ServiceSchemaMigrator, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'

    @staticmethod
    def apply_timezone_offset(service, offset_in_hours):
        """
        Given the number of hours needed to offset timeblocks, apply the change to all KPIs in a service

        @type service: object
        @param service: Service object instance to update

        @type offset_in_hours: int
        @param offset_in_hours: the # of hours of offset to apply

        @rtype: None
        @return: None although service input reference will be updated
        """
        # Compute the day/hour change as needed for the time blocks based on the offset
        if not (-24 <= offset_in_hours <= 24):
            message = _('Timezone offset specified seems invalid, must be within 24 hour range. ' \
                    'Specified value: %s ') % offset_in_hours
            logger.error(message)
            raise ValueError(message)

        if not isinstance(service, dict):
            message = _('Service is not a valid dictionary, found type %s. Cannot apply timezone offset.') % type(
                service).__name__
            logger.error(message)
            raise TypeError(message)

        if not isinstance(offset_in_hours, int):
            message = _('offset_in_hours is not a valid int, found type %s. Cannot apply timezone offset.') % type(
                offset_in_hours).__name__
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

            time_blocks = policy_spec.get('time_blocks')
            if not isinstance(time_blocks, list):
                logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                continue  # Ignore

            new_time_blocks = []

            for time_block in time_blocks:
                if not isinstance(time_block, dict):
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                # Time block keys are values from 00-00 to 06-23
                time_block_spec_str = time_block.get('time_block_key')
                if not isinstance(time_block_spec_str, basestring) or len(time_block_spec_str) != 5:
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                time_block_spec = time_block_spec_str.split('-')
                if not isinstance(time_block_spec, list) or len(time_block_spec) != 2:
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                try:
                    time_block_day = int(time_block_spec[0])
                    time_block_hour = int(time_block_spec[1])
                except Exception as e:
                    logger.exception(e)
                    logger.warn('KPI time block policy looks invalid, skipping timezone offset adjustment for policy')
                    continue  # Ignore

                # offset_in_hours is expected to be less than 24 hours here so simply up/down day by 1
                if offset_in_hours > 0:
                    if (time_block_hour + offset_in_hours) > 23:
                        time_block_day = (time_block_day + 1) % 7
                else:
                    if (time_block_hour + offset_in_hours) < 0:
                        time_block_day = (time_block_day - 1) % 7
                time_block_hour = (time_block_hour + offset_in_hours) % 24

                def _make_time_block_str(number):
                    num_as_str = str(number)
                    if len(num_as_str) == 1:
                        num_as_str = '0' + num_as_str
                    return num_as_str

                new_time_blocks.append({
                    'policy_key': time_block.get('policy_key'),
                    'time_block_key': _make_time_block_str(time_block_day) + '-' + _make_time_block_str(time_block_hour)
                })
            kpi['time_variate_thresholds_specification']['time_blocks'] = new_time_blocks

    def _fetch_and_migrate(self):
        """
        Fetch all services and do required migration.
        @rtype: boolean/None
        @return True on success. False/None on failure.
        """
        status = None
        try:
            # get all services
            service_itr = self.get_object_iterator('service', get_raw=True)
            all_services = []

            # Seconds to apply as offset for local server to UTC is in _local_server_utc_offset in seconds
            # Compute hours as offset for time blocks. Round down the hours for extra seconds from the offset
            offset_in_hours = -1 * int(_local_server_utc_offset / 3600)

            for service in service_itr:
                # if an existing service has the "enabled" flag, respect it, else, set to 1
                service['enabled'] = service.get('enabled', 1)

                ServiceSchemaMigrator.apply_timezone_offset(service, offset_in_hours)

                all_services.append(service)

                # save all services, this should help with optimizing the service
            # schema as well...replace existing searches with entity filters
            # with something more concise, like a subsearch.
            logger.info('Service enable/disable done locally. Attempting to save. Will migrate schema in process.')
            status = self.save_object('service', all_services)
        except Exception:
            logger.exception('Failed to migrate service schema')
            message = _('Failed to migrate service schema to 2.5.0. Unable to save. Please check ITSI internal logs.')
            ITOAInterfaceUtils.create_message(self.session_key, message)
        logger.info('No exceptions when saving. Save status=%s', status)
        return status

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._fetch_and_migrate()


class MaintenanceWindowMigrator(MigrationFunctionAbstract):
    """
    Migration handler for maintenance windows to convert currently stored local server time start and end times
    to UTC per timezone handling feature in ITOA-5881. Note that maintenance calendar times were set pre-2.5.0
    in UI using browser timezone hence the need for this migration as a best effort for cases where browser time
    is same as server time. Users should use KV store to JSON tool to set to required offset in addition if needed.
    """
    def __init__(self, session_key, owner=None):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: current owner; usually `nobody`
        """
        super(MaintenanceWindowMigrator, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all maintenance calendar that already exist.
        """
        # Pre 2.5.0, time.time() was used to compare start and end times to identify active maintenance windows
        # Since time.time() could in some settings give local server time, we need to only migrate
        # in those environments. Hence detect if time.time() is different from utc time and only
        # continue with migration if its true.
        current_epoch_from_time = time.time()
        current_epoch_utc = get_current_utc_epoch()
        if int(current_epoch_from_time) == int(current_epoch_utc):
            # Dont need to migrate, start and end times are already in UTC
            logger.info('Skipping maintenance calendar migration since time sensitive values are already in UTC.')
            return True

        maintenance_calendars = self.get_object_iterator('maintenance_calendar')
        logger.debug(
            'Type = %s, fetched maintenance calendars',
            type(maintenance_calendars).__name__
        )

        status = False
        try:
            maintenance_calendar_collection = []
            for maintenance_calendar in maintenance_calendars:
                apply_timezone_offset(maintenance_calendar, 'start_time', -1 * _local_server_utc_offset)
                # Only convert offset if end_time is not set to "Indefinite"
                if not _is_maintenance_end_time_indefinite(maintenance_calendar):
                    apply_timezone_offset(maintenance_calendar, 'end_time', -1 * _local_server_utc_offset)

                maintenance_calendar_collection.append(maintenance_calendar)

            logger.debug('Committing %s of updated maintenance calendars', len(maintenance_calendar_collection))
            status = self.save_object('maintenance_calendar', maintenance_calendar_collection)

        except Exception:
            message = _('Failed to migrate maintenance calendars to 2.5.0. Unable to save. Please check ITSI internal logs.')
            logger.exception(message)
            ITOAInterfaceUtils.create_message(self.session_key, message)

        return status

    def execute(self):
        return self._fetch_and_migrate()


class BackupRestoreJobsMigrator(MigrationFunctionAbstract):
    """
    Migration handler for backup restore jobs to convert currently stored local server time start and end times
    to UTC per timezone handling feature in ITOA-5881.
    """
    def __init__(self, session_key, owner=None):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: current owner; usually `nobody`
        """
        super(BackupRestoreJobsMigrator, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all backup restore jobs that already exist.
        """

        # Pre 2.5.0, time.time() was used to set start and end times in backup restore jobs
        # Since time.time() could in some settings give local server time, we need to only migrate
        # in those environments. Hence detect if time.time() is different from utc time and only
        # continue with migration if its true.
        current_epoch_from_time = time.time()
        current_epoch_utc = get_current_utc_epoch()
        if int(current_epoch_from_time) == int(current_epoch_utc):
            # Dont need to migrate, job start and end times are already in UTC
            logger.info('Skipping backup restore jobs migration since time sensitive values are already in UTC.')
            return True

        backup_restore_jobs = self.get_object_iterator('backup_restore')
        logger.debug(
            'Type = %s, fetched backup restore jobs',
            type(backup_restore_jobs).__name__
        )

        try:
            backup_restore_jobs_collection = []
            for backup_restore_job in backup_restore_jobs:
                apply_timezone_offset(backup_restore_job, 'start_time', -1 * _local_server_utc_offset)
                apply_timezone_offset(backup_restore_job, 'end_time', -1 * _local_server_utc_offset)

                backup_restore_jobs_collection.append(backup_restore_job)

            logger.debug('Committing %s of updated backup restore jobs', len(backup_restore_jobs_collection))
            return self.save_object('backup_restore', backup_restore_jobs_collection)

        except Exception, e:
            message = _('Failed to migrate backup restore jobs to 2.5.0. Unable to save. Please check ITSI internal logs.')
            logger.exception(message)
            ITOAInterfaceUtils.create_message(self.session_key, message)

        return False

    def execute(self):
        return self._fetch_and_migrate()


class IdentifyingNamesLowerCaseMigrator(MigrationFunctionAbstract):
    """
    Migration handler for setting the identifying name of all objects to be stored in lower case
    Details in ITOA-5730.
    """
    def __init__(self, session_key):
        """
        @type session_key: basestring
        @param session_key: session key
        """
        super(IdentifyingNamesLowerCaseMigrator, self).__init__(session_key)

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all objects changing the identifying name to lower case.
        """

        object_types = [
            'deep_dive',
            'entity',
            'glass_table',
            'home_view',
            'kpi_base_search',
            'service',
            'event_management_state',
            'notable_aggregation_policy',
            'maintenance_calendar',
            'kpi_threshold_template',
            'kpi_template',
            'backup_restore'
        ]

        for object_type in object_types:
            if object_type in SECURABLE_OBJECT_LIST:
                object_iterator = self.get_object_iterator(object_type, get_raw=True)
            else:
                object_iterator = self.get_object_iterator(object_type)

            modified_object_collection = []
            for knowledge_object in object_iterator:
                name = knowledge_object.get('identifying_name')
                if name is None:
                    logger.warning('No identifying name found for object="%s" of type="%s", using title',
                               knowledge_object.get('title'), object_type)
                    name = knowledge_object.get('title')
                knowledge_object['identifying_name'] = str(name).strip().lower()

                modified_object_collection.append(knowledge_object)

            self.save_object(object_type, modified_object_collection)

        return True

    def execute(self):
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

    tz_logger = setup_logging("itsi_config.log", "itsi.timezone.operations", is_console_header=True)

    object_title_filter = None
    if is_valid_str(object_title):
        object_title_filter = {'title': object_title}

    object_type_instance = None
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
                ServiceSchemaMigrator.apply_timezone_offset(json_data, int(offset_in_sec / 3600))
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
