# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This module implements a backup-restore queue utility to enable backup and restore functionality.
"""
import sys
import errno
from time import time
from .constants import (BACKUP_RESTORE_ADVANCED_MODE)
import json
import re
import os

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n
import splunk.rest as rest
from splunk.util import normalizeBoolean, safeURLQuote

from ITOA.storage import statestore
from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import post_splunk_user_message, get_current_utc_epoch

from itsi.upgrade.kvstore_backup_restore import KVStoreBackupRestore
from itsi.upgrade.kvstore_backup_restore import FileManager
from itsi.objects.itsi_backup_restore import ItsiBackupRestore


class ITSIBackupRestoreJobsQueueAdapter(object):
    """
    Provides an interface to set get and delete backup_restore queue entries
    """

    def __init__(self, session_key, logger):
        self.logger = logger
        self._session_key = session_key
        self._owner = 'nobody'

        self.backup_restore_job_object = ItsiBackupRestore(self._session_key, self._owner)

        self.job_queue_timeout = None

    def get_backup_restore_jobs_keys(self, key_filter={}):
        """
        Get a list of keys for backup/restore jobs in the kvstore that match the key_filter

        @type key_filter: dict
        @param key_filter: filter for keys for the backup/restore jobs

        @returns: list of keys (of backup/restore jobs) or None for an invalid filter
        @rtype : list
        """
        if isinstance(key_filter, dict):
            return self.backup_restore_job_object.get_bulk(
                self._owner,
                filter_data = key_filter,
                fields=['_key']
            )
        else:
            return None


    def get_earliest_backup_restore_job(self):
        """
        Get earliest backup_restore job (sorted by last queued time). Returns list containing 1 job.
        Filters only for 'queued' and 'In progress' jobs
        Returns an empty list in certain error scenarios

        NOTE: Each host should get earliest available and then compare local guid so they dont start parallel jobs to
        process.

        @returns: list of refresh jobs
        @rtype: list
        """
        # Retrieve earliest Queued/In Progress job
        status_filter = {'$or': [{"status": "Queued"},{"status": "In Progress"}]}
        return self.backup_restore_job_object.get_bulk(
            self._owner,
            filter_data = status_filter,
            sort_key = 'last_queued_time',
            sort_dir = 'asc',
            limit = 1
        )

    def set_job_start_status(self, job):
        """
        Sets jobs status to in progress.Sets the start_time, last_queued_time and resets end_time

        @type job_key: string
        @param job_key: string indicating id for the job

        @rtype: None
        @return: None
        """

        job['start_time'] = get_current_utc_epoch()
        job['end_time'] = None
        job['status'] = 'In Progress'
        status_in_progress_json = {
            '_key': job.get('_key'),
            'start_time': job['start_time'],
            'end_time': job['end_time'],
            'status': job['status']
            }
        self.backup_restore_job_object.update(
            self._owner,
            job.get('_key'),
            status_in_progress_json,
            is_partial_data = True
        )

    def set_job_completion_status(self, job):
        """
        Sets jobs status to complete or failed.Sets end_time

        @type job: object
        @param job: job that needs to be updated

        @rtype: None
        @return: None
        """
        job_key = job.get('_key')
        job['start_time'] = get_current_utc_epoch() if job.get('start_time') is None else job.get('start_time')
        job['end_time'] = get_current_utc_epoch()
        status_json = {
            '_key': job_key,
            'path': job.get('path', ''),
            'status': job.get('status', 'Failed'),
            'last_error': job.get('last_error'),
            'start_time': job['start_time'],
            'end_time': job['end_time']
            }
        self.backup_restore_job_object.update(
            self._owner,
            job_key,
            status_json,
            is_partial_data=True
        )

    def get_job_queue_timeout(self):
        """
        Gets the timeout in seconds for host availability in SHC beyond which jobs queued for the host would be
        failed

        @rtype: number
        @return: queue timeout in seconds
        """
        if self.job_queue_timeout is not None:
            return self.job_queue_timeout

        self.job_queue_timeout = 43200 # 12 hours default in seconds
        try:
            stanza_name = 'backup_restore'
            response, content = rest.simpleRequest(
                '/servicesNS/nobody/SA-ITOA/configs/conf-itsi_settings/' + stanza_name,
                sessionKey=self._session_key,
                getargs={'output_mode': 'json'}
            )
            if response.status == 200:
                entries = json.loads(content).get('entry')
                for entry in entries:
                    name = entry.get('name')
                    if name != stanza_name:
                        continue
                    settings = entry.get('content', {})
                    self.job_queue_timeout = int(settings.get('job_queue_timeout', 3600))
                    break
        except Exception as e:
            # use default
            self.logger.exception(e)
            pass

        self.logger.debug(
            'Identified job_queue_timeout for backup/restore jobs as %s seconds from conf file', self.job_queue_timeout
        )

        # If timeout is < 3600 seconds, set the timeout to 3600 seconds
        if self.job_queue_timeout < 3600:
            self.job_queue_timeout = 3600
        self.logger.debug(
            'Set job_queue_timeout for backup/restore jobs as %s seconds', self.job_queue_timeout
        )
        return self.job_queue_timeout

    def get_shc_member_info(self, host_id):
        """
        Get the dict of host information for the shcluster member identified by its host_id
        Note that this method is only expected to be used in an SHC

        @type: string
        @param host_id: guid id of the host member in the SHC

        @rtype: dict
        @return: dictionary containing host information
        """

        response, content = rest.simpleRequest(
            'shcluster/member/members/' + safeURLQuote(host_id),
            sessionKey=self._session_key,
            getargs={'output_mode': 'json'}
        )
        if response.status == 200:
            entries = json.loads(content).get('entry')
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict) or entry.get('name') != host_id:
                        continue
                    host_info = entry.get('content')
                    return host_info
        return None

    def get_shc_member_last_heartbeat(self, host_id):
        """
        Get the last heartbeat for host member identified by host_id in an SHC
        Note that this method is only expected to be used in an SHC

        @type: string
        @param host_id: guid id of the host member in the SHC

        @rtype: float
        @return: timestamp of last heartbeat received from this member in seconds

        """
        try:
            host_info = self.get_shc_member_info(host_id)
            if isinstance(host_info, dict):
                heartbeat = float(host_info.get('last_heartbeat'))
                self.logger.debug('Identified heartbeat for host %s as %s.', host_id, heartbeat)
                return heartbeat
        except Exception as e:
            # use default
            self.logger.exception(e)
            pass

        self.logger.debug(
            'Could not identify heartbeat for host %s, treating as unavailable and returning 0.',
            host_id
        )
        return 0

    def get_shc_member_hostname(self, host_id):
        """
        Get the hostname for host member identified by host_id in an SHC
        Note that this method is only expected to be used in an SHC

        @type: string
        @param host_id: guid id of the host member in the SHC

        @rtype: string
        @return: hostname received from this member

        """
        try:
            host_info = self.get_shc_member_info(host_id)
            if isinstance(host_info, dict):
                mgmt_uri = host_info.get('mgmt_uri')
                self.logger.debug('Identified mgmt_uri for host %s as %s.', host_id, mgmt_uri)
                regex = "https?\:\/\/(.+):.*"
                match_pattern = re.compile(regex, re.IGNORECASE)
                if mgmt_uri:
                    matched_object = match_pattern.match(mgmt_uri)
                    if matched_object is not None:
                        return matched_object.group(1)
        except Exception as e:
            # use default
            self.logger.exception(e)
            pass

        self.logger.debug(
            'Could not identify hostname for host %s, treating as unavailable and returning "None".',
            host_id
        )
        return "None"


class ITSIBackupRestoreJobsProcessor(object):
    """
    Abstracted functionality of the modular input for testing purposes
    """
    basedir = make_splunkhome_path(['var', 'itsi', 'backups'])

    def __init__(self, session_key, server_info,  log_level = 'INFO'):
        self.session_key = session_key
        self.server_info = server_info
        self.logger = setup_logging("itsi_config.log", "itsi.backup_restore_jobs", level = log_level)
        self.adapter = ITSIBackupRestoreJobsQueueAdapter(self.session_key, self.logger)

    def _is_job_timed_out(self, job, is_shc=False):
        """
        For a given job, does time out validations and fails the job on timeout with error info

        @type: dict
        @param job: the backup/restore job config json

        @type: boolean
        @param is_shc: bool indicating if this host is an shc setup

        @rtype: tuple(boolean, string)
        @return: (True if job has timed out or False otherwise, text stating reason for failure)
        """

        # Method not used externally, skip input validation

        if not is_shc:
            # Wont timeout on non-SHC scenario since current single host is obviously up and running
            return False, 'None'

        # Detect if owning host of the job has been down for longer than the timeout grace period
        # If yes, the job has timed out
        job_queue_timeout = self.adapter.get_job_queue_timeout()
        grace_period_timestamp = time() - job_queue_timeout

        host_heartbeat = self.adapter.get_shc_member_last_heartbeat(job.get('search_head_id'))
        if host_heartbeat == 0 and job.get('last_queued_time') is not None:
            # If we could not get a heartbeat possibly owing to node being down temporarily, lets use the queued time
            # of the job to allow for grace period in timeout
            try:
                host_heartbeat = float(job.get('last_queued_time'))
                self.logger.debug(
                    'Heartbeat is 0 for host %s, so using the last queued time of the job %s',
                    job.get('search_head_id'),
                    host_heartbeat
                )
            except (ValueError, TypeError) as e:
                # We could not find a good value for last queued time, stick to 0 for heartbeat indicating node is down
                self.logger.exception(e)
                pass

        if host_heartbeat < grace_period_timestamp:
            if self.adapter.get_shc_member_hostname(job.get('search_head_id')) != 'None':
                return True, _("Job {}'s owning host {} seems to be unavailable. Cannot process job. Retry once host is up.").format(
                    job.get('title'),
                    self.adapter.get_shc_member_hostname(job.get('search_head_id'))
                )
            else:
                return True, _("Job {}'s owning host with search head id {} seems to be unavailable. Cannot process job. Retry once host is up.").format(
                    job.get('title'),
                    job.get('search_head_id')
                )

        return False, 'None'

    def run(self):
        """
        Runs the main logic of the jobs processor mod input. Abstracted out of the run method
        for testing purposes

        @return: count of total processed jobs (for testing)
        @rtype: int
        """

        def _cleanup():
            """
            Checks to see if there are any backup files that are left behind as a result of a previous bulk delete
            operation on another search head and deletes them from the file system
            """
            # Get list of backups on local disk.
            backups_on_disk = FileManager.get_zip_file_names(ITSIBackupRestoreJobsProcessor.basedir)
            self.logger.debug('Backup files found on disk: %s', backups_on_disk)
            if isinstance(backups_on_disk, list):
                local_backups_key_list = [{'_key':key} for key in backups_on_disk]
                self.logger.debug('Local backup keys dict: %s', local_backups_key_list)
                local_backups_key_filter = {'$or':local_backups_key_list}

                # Retrieve backup/restore jobs from kvstore that match the filter criteria.
                backup_restore_jobs_list = self.adapter.get_backup_restore_jobs_keys(local_backups_key_filter)
                self.logger.debug('Backup/Restore jobs from kvstore matching key filter: %s', backup_restore_jobs_list)

                # Given a list of dicts({'_key': '<value>'}) the function returns a flattened list of key values.
                get_keys_list = lambda key, inputData: [subVal[key] for subVal in inputData if key in subVal]

                # Populate list of keys that exist on local disk but are not in the kvstore
                delete_backups_list = list(set(get_keys_list('_key', local_backups_key_list)) -
                                           set(get_keys_list('_key', backup_restore_jobs_list)))
                self.logger.info('List of backups that will be deleted: %s', delete_backups_list)
                for backup_file in delete_backups_list:
                    FileManager.delete_file(os.path.join(ITSIBackupRestoreJobsProcessor.basedir, backup_file+'.zip'))
                    self.logger.debug('Cleaning up backup file %s from disk', backup_file)
            return
        try:
            _cleanup()
        except Exception:
            self.logger.error('Failed cleanup of backup files')
            raise

        processed_job_count = 0
        failed_jobs = 0
        successful_jobs = 0
        self.logger.debug('In main backup restore jobs processing loop')
        keep_running = True

        local_host_id = self.server_info.guid
        if not isinstance(local_host_id, basestring) or len(local_host_id) < 1:
            self.logger.error('Could not retrieve guid for local server, exiting now, splunk will restart jobs '
                              'processor based on mod input interval')
            return 0

        def _mark_job_as_completed(job):
            """
            Marks completion of job and posts message to user

            @type: dict
            @param job: the job to be marked
            """
            job['status'] = 'Completed'
            job['last_error'] = 'None'
            message = _('{} job "{}" has completed successfully.').format(job.get('job_type'), job.get('title'))
            self.adapter.set_job_completion_status(job)
            self.logger.debug('%s', message)
            # only post successfully completed message if the job isn't regularly scheduled
            if job.get('scheduled') != 1:
                post_splunk_user_message(message, session_key=self.session_key)

        def _mark_job_as_failed(job):
            """
            Marks failure in job and posts message to user
            Assumes specific last_error has already been set

            @type: dict
            @param job: the job to be marked
            """
            job['status'] = 'Failed'
            message = _('{} job "{}" has failed. Error: {}').format(
                job.get('job_type'),
                job.get('title'),
                job.get('last_error')
            )

            self.adapter.set_job_completion_status(job)
            post_splunk_user_message(message, session_key=self.session_key)
            self.logger.error('%s', message)
            # if this is a failed Backup job, clean the working directory
            if job.get('job_type') == 'Backup':
                if FileManager.is_exists(os.path.join(ITSIBackupRestoreJobsProcessor.basedir, job.get('_key'))):
                    FileManager.delete_working_directory(os.path.join(ITSIBackupRestoreJobsProcessor.basedir, job.get('_key')))

        while keep_running:
            job = self.adapter.get_earliest_backup_restore_job()
            # if no job found, no-op
            if len(job) == 0:
                self.logger.debug(
                    'No backup restore jobs found, exiting now, splunk will restart jobs processor ' \
                        'based on mod input interval.'
                )
                keep_running = False
                continue

            job_owning_host_id = job[0].get('search_head_id')

            # If job found does not have the search_head_id as this host's guid, then this host cannot process the job
            # Since only one job could be active at a time, quit without processing any at this time
            # Could pick up any jobs for this host in subsequent scheduled runs
            if job_owning_host_id != local_host_id:
                is_job_failed = False
                if not isinstance(job_owning_host_id, basestring) or len(job_owning_host_id) < 1:
                    job[0]['last_error'] = 'Job {} does not contain valid search_head_id'.format(job[0].get('title'))
                    is_job_failed = True

                is_shc = self.server_info.is_shc_member()
                # If standalone setup and search head id doesnt match local host, something is wrong, fail the job
                if not is_shc:
                    job[0]['last_error'] = 'Job {} contains search head id {} which does not match the local host. ' \
                        'Check the job configuration.'.format(job[0].get('title'), job[0].get('search_head_id'))
                    is_job_failed = True

                # For job for remote host, if remote host is down, we should mark the job as failed to prevent
                # the job from holding the queue indefinitely
                is_timed_out, reason = self._is_job_timed_out(job[0], is_shc=is_shc)
                if is_timed_out:
                    self.logger.error(reason)
                    job[0]['last_error'] = reason
                    is_job_failed = True

                if is_job_failed:
                    _mark_job_as_failed(job[0])
                    continue

                self.logger.info(
                    'No queued backup/restore job found for this host. Job search_head_id:%s host id:%s'
                    'Will exit now and splunk will kick off modular input in next interval',
                    job[0].get('search_head_id'),
                    local_host_id
                )
                keep_running = False
                continue

            # If job found and has the same search_head_id as this host's local_host_id, process it
            job = job[0]
            self.logger.info('Found backup/restore job "%s" to process for the local host (id: %s)',
                job.get('title'),
                job.get('search_head_id')
            )

            if job.get('status') == 'In Progress':
                self.logger.debug(
                    'Job "%s" identified to execute is marked as in progress currently. This indicates ' \
                    'that the job was stopped in an incomplete state the last time around possibly ' \
                    'owing to a splunk restart. Retrying the job now.', job.get('title'))

            is_job_complete = False
            self.logger.debug('Processing job type: %s', job['job_type'])
            self.logger.debug('Working directory for backup zip file: %s', job.get('path'))
            self.adapter.set_job_start_status(job)
            try:
                worker = KVStoreBackupRestore(
                    self.session_key,
                    job.get('path'),
                    job.get('job_type') == 'Backup', # Identifies if backup or restore
                    persist_data = True, # Append existing KV store contents
                    br_version = None,  # None implies current app version for backup, auto extracted from backup path for restore
                    dupname_tag = '_dup_from_Backup_Restore_Jobs_Processor',
                    is_debug = True, # Use verbose logging
                    logger_instance = self.logger,
                    is_dry_run = False, # Its the real deal
                    rule_file_path = None, # For now, backups and restores will be full,
                    mode = BACKUP_RESTORE_ADVANCED_MODE # Using advanced mode to do the workflow with zip/unzip
                )
                worker.execute()
                is_job_complete = True
            except IOError as e:
                if e.errno == errno.ENOENT:
                    msg = _('File not found.')
                    job['last_error'] = msg
                    self.logger.exception(msg)
                else:
                    job['last_error'] = str(e)
                    self.logger.exception(e)
            except Exception as e:
                job['last_error'] = str(e)
                self.logger.exception(e)
                # Clean up the backup working directory created in _init_ of KVStoreBackupRestore
                KVStoreBackupRestore.cleanup_backup_working_directory(job.get('_key'))
            finally:
                # Accumulate end time here to be saved below in set_jobs_status to optimize write to KV store
                job['end_time'] = get_current_utc_epoch()

            if is_job_complete:
                _mark_job_as_completed(job)
            else:
                # last_error is set above in except clause
                _mark_job_as_failed(job)

            processed_job_count += 1
            self.logger.info('Job status at the end of jobs processor loop: %s', job)

        return processed_job_count
