# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import os
from time import sleep
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n
from SA_ITOA_app_common.solnlib.server_info import ServerInfo

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.objects.itsi_scheduled_backup import ScheduledBackup
from ITOA.itoa_common import get_itoa_logger, get_current_utc_epoch, post_splunk_user_message
from itsi.itsi_utils import DEFAULT_SCHEDULED_BACKUP_KEY
from itsi.service_template.service_template_utils import ServiceTemplateUtils

logger = get_itoa_logger("itsi.scheduled_backup", "itsi_scheduled_backup.log")
BACKUP_PATH = make_splunkhome_path(['var', 'itsi', 'backups'])


class BackupScheduler(object):
    def __init__(self, session_key, app="SA-ITOA", user='nobody'):
        """
        Constructor

        @type: string
        @param: session_key

        @type: string
        @param app: context of app invoking the request

        @type: string
        @param owner: "owner" user invoking this call

        @rtype: None
        @return: None
        """
        self._session_key = session_key
        self._app = app
        self._user = user

    def _verify_initial_setup(self, scheduled_backup_object):
        """
        Verify if default scheduled backup exists

        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @rtype: list
        @return: list of one scheduled backup object
        """
        return scheduled_backup_object._get_scheduled_backup()

    def _create_default_schedule(self, scheduled_backup_object):
        """
        Create default scheduled backup

        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @rtype: list
        @return: list of two elements, a Boolean value indicates the create results and next scheduled time in UTC epoch
        """
        return scheduled_backup_object._create_scheduled_backup()

    def _adhoc_backup_job_completed(self, scheduled_backup_object, scheduled_backup_job_key):
        """
        Wait for backup job to complete

        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @type scheduled_backup_job_key: str
        @param scheduled_backup_job_key: scheduled backup job key
        
        @rtype: Boolean
        @return: True if backup job succeeds, False if fails 
        """
        while True:
            backup_job = scheduled_backup_object.get(self._user, scheduled_backup_job_key)
            status = backup_job.get('status')
            sleep_time = 10
            if status != 'Completed':
                if status in ['Queued', 'In Progress']:
                    logger.info('Scheduled backup job is %s.' % status.lower())
                    sleep(sleep_time)
                elif status == 'Failed':
                    logger.error('Scheduled backup job failed, will run again soon.')
                    return False
            else:
                logger.info('Scheduled backup job completed.')
                return True

    def _update_default_backup_job(self, scheduled_backup_object, scheduled_backup_object_key, updated_info):
        """
        update default scheduled backup job

        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @type scheduled_backup_job_key: str
        @param scheduled_backup_job_key: scheduled backup job key
        
        @type updated_info: dict
        @param updated_info: contains updated key-value pairs
        
        @rtype: Boolean
        @return: True if backup job succeeds, False if fails 
        """
        return scheduled_backup_object._update_scheduled_backup(scheduled_backup_object_key, updated_info)

    def _update_default_schedule_after_backup(self,
                                              scheduled_backup_object,
                                              scheduled_backup_job_key,
                                              scheduled_time,
                                              frequency):
        """
        update default scheduled backup job to next scheduled time
        
        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @type scheduled_backup_job_key: str
        @param scheduled_backup_job_key: scheduled backup job key
        
        @type scheduled_time: int
        @param scheduled_time: original scheduled time in UTC epoch
        
        @rtype: list
        @return: A Boolean value indicates if update operation succeeds, and next scheduled time in UTC epoch
        """
        updated_info = {}
        if frequency == 'weekly':
            next_scheduled_time = scheduled_time + 60*60*24*7
            updated_info['status'] = 'Scheduled Weekly'
        elif frequency == 'daily':
            next_scheduled_time = scheduled_time + 60*60*24
            updated_info['status'] = 'Scheduled Daily'
        updated_info['scheduled_time'] = next_scheduled_time
        return self._update_default_backup_job(scheduled_backup_object, scheduled_backup_job_key, updated_info), next_scheduled_time

    def _compare_timestamp(self, scheduled_time, current_time):
        """
        Compare scheduled time and current time

        @type scheduled_time: int
        @param scheduled_time: original scheduled time in UTC epoch
        
        @type current_time: int
        @param scheduled_time: current time in UTC epoch
        
        @rtype: Boolean
        @return: A Boolean value indicates if current time is later or equal to scheduled time
        """
        return scheduled_time <= current_time

    def _should_run_scheduled_backup(self, scheduled_time):
        """
        Compare scheduled time and current time
        Also block scheduled backup from running if service template sync job in progress

        @type scheduled_time: int
        @param scheduled_time: original scheduled time in UTC epoch

        @rtype: Boolean
        @return: A Boolean value indicates if scheduled backup job should run
        """
        current_time = get_current_utc_epoch()
        return (self._compare_timestamp(scheduled_time, current_time) and
                not ServiceTemplateUtils(self._session_key, self._user).service_template_sync_job_in_progress_or_sync_now())

    def _execute(self, scheduled_backup_object, scheduled_backup_job_key):
        """
        Change scheduled backup job status to Queued for picking up

        @type scheduled_backup_object: ScheduledBackup object
        @param scheduled_backup_object: scheduled backup object to perform all operations
        
        @type scheduled_backup_job_key: str
        @param scheduled_backup_job_key: scheduled backup job key

        @rtype: Boolean
        @return: True if backup job succeeds, False if fails 
        """
        info = ServerInfo(self._session_key)
        local_search_head_id = info.guid
        updated_info = {}
        updated_info['search_head_id'] = local_search_head_id
        updated_info['status'] = 'Queued'
        logger.info('Update search head id to %s and status to Queued' % local_search_head_id)
        self._update_default_backup_job(scheduled_backup_object, scheduled_backup_job_key, updated_info)
        if self._adhoc_backup_job_completed(scheduled_backup_object, scheduled_backup_job_key):
            return True
        else:
            return False

    def run_scheduled_backup(self):
        """
        The entry point of Modular Input. Takes care of all scheduled backup related operations
        
        @rtype: None
        """
        # Check if default scheduled backup exists. Create one if not.
        logger.info('Start checking scheduled backup')
        scheduled_backup_object = ScheduledBackup(self._session_key, self._user)
        collection = self._verify_initial_setup(scheduled_backup_object)
        initial_backup = False
        if len(collection) == 0:
            logger.info('No default scheduled backup found. Creating one now.')
            result, next_scheduled_time = self._create_default_schedule(scheduled_backup_object)
            if result:
                logger.info('Successfully create scheduled backup. The initial backup will run immediately')
                # Get scheduled backup once again
                collection = self._verify_initial_setup(scheduled_backup_object)
                initial_backup = True
            else:
                logger.error('Fail to create scheduled backup. See itsi.log for more information.')
                sys.exit(1)

        scheduled_time = collection[0]['scheduled_time']
        frequency = collection[0]['frequency']
        enabled = collection[0]['enabled']

        if not initial_backup:
            logger.info('Default scheduled backup found with next backup operation at %s.' % scheduled_time)
        scheduled_backup_job_key = collection[0].get('_key', '')
        if scheduled_backup_job_key != DEFAULT_SCHEDULED_BACKUP_KEY:
            logger.error("Invalid key in scheduled backup job. Will not execute.")
            return False

        # Performs scheduled backup if it's enabled and it's time to run
        if (initial_backup or self._should_run_scheduled_backup(scheduled_time))and enabled:
            execute_result = self._execute(scheduled_backup_object, scheduled_backup_job_key)

            # Update scheduled time to next one based on the frequency if backup succeeded
            # Post Splunk message and wait for the next run if failed
            # Added one step of timestamp check here to make sure we only update scheduled time when it is past
            # For developing purpose
            if execute_result:
                if not initial_backup:
                    update_result, next_scheduled_time = self._update_default_schedule_after_backup(scheduled_backup_object,
                                                                                                    scheduled_backup_job_key,
                                                                                                    scheduled_time,
                                                                                                    frequency)
                    if not update_result:
                        logger.error('Failed to update scheduled backup time.')
                    else:
                        message = _('Scheduled backup job updated successfully. ' \
                                  'The next scheduled backup job will run at %s.') % next_scheduled_time
                        logger.info(message)
                else:
                    logger.info('Initial backup operation finished. The next scheduled backup job will run at %s.' % scheduled_time)
                    update_status = 'Scheduled Daily' if frequency == 'daily' else 'Scheduled Weekly'
                    update_result = self._update_default_backup_job(scheduled_backup_object,
                                                                    scheduled_backup_job_key,
                                                                    {'status': update_status})
                    if not update_result:
                        logger.error('Failed to update scheduled backup time.')

            else:
                message = _('Scheduled backup job failed.' \
                          'The next scheduled backup job will run in an hour.')
                post_splunk_user_message(message, self._session_key)
                logger.error(message)

        else:
            logger.info('Scheduled backup job will run at %s.' % scheduled_time)



