# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import get_itoa_logger, calculate_default_schedule_time
from itsi.itsi_utils import DEFAULT_SCHEDULED_BACKUP_KEY
from itsi_backup_restore import ItsiBackupRestore

logger = get_itoa_logger('itsi.scheduled_backup.object', 'itsi_scheduled_backup.log')

DEFAULT_SCHEDULE = {
    'title': 'Default Scheduled Backup',
    'object_type': 'backup_restore',
    'job_type': 'Backup',
    'scheduled': 1,
    'scheduled_time': '',
    'frequency': 'daily',
    'path': '',
    '_owner': 'nobody',
    '_user': 'nobody',
    'status': 'Scheduled Daily',
    'last_error':'',
    'enabled': 1,
    '_key': DEFAULT_SCHEDULED_BACKUP_KEY
}

DEFAULT_HOUR = 1

class ScheduledBackup(ItsiBackupRestore):
    '''
    Implements scheduled backup object.
    Used as the primary interface to perform automated backup operation in regular basis.
    '''

    log_prefix = '[Scheduled Backup Object] '

    def __init__(self, session_key, current_user_name):
        """
        Constructor

        @type session_key: string
        @param session_key: session_key

        @type current_user_name: string
        @param current_user_name: " user invoking this call

        @rtype: None
        @return: None
        """
        self._session_key = session_key
        self.collection_name = 'itsi_backup_restore_queue'
        self._user = current_user_name
        super(ScheduledBackup, self).__init__(session_key,
                                              current_user_name)

    def _get_scheduled_backup(self):
        """
        Verify if default scheduled backup exists

        @rtype: list
        @return: list of one scheduled backup object
        """
        status_filter = {"scheduled": 1}
        collections = self.get_bulk(self._user,
                                    filter_data = status_filter,
                                    limit=1)
        return collections

    def _update_scheduled_backup(self, scheduled_backup_job_key, updated_info):
        """
        update default scheduled backup job

        @type scheduled_backup_job_key: str
        @param scheduled_backup_job_key: scheduled backup job key
        
        @type updated_info: dict
        @param updated_info: contains updated key-value pairs
        
        @rtype: Boolean
        @return: True if backup job succeeds, False if fails 
        """
        try:
            response = self.update(self._user,
                                   scheduled_backup_job_key,
                                   updated_info,
                                   is_partial_data=True)
            logger.debug("Update scheduled backup response=%s", response)
            return True
        except:
            return False

    def _create_scheduled_backup(self):
        """
        Create default scheduled backup

        @rtype: list
        @return: list of two elements, a Boolean value indicates the create results and next scheduled time in UTC epoch
        """
        frequency = DEFAULT_SCHEDULE.get('frequency', 'daily')
        DEFAULT_SCHEDULE['scheduled_time'] = calculate_default_schedule_time(logger,
                                                                             frequency = frequency,
                                                                             scheduled_hour = DEFAULT_HOUR)
        try:
            response = self.create(self._user,
                                   DEFAULT_SCHEDULE)
            logger.debug("Creating scheduled backup response=%s", response)
            return True, DEFAULT_SCHEDULE['scheduled_time']
        except:
            return False, None


