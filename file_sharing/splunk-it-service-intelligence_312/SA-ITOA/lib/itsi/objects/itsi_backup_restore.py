# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import os
import sys
import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from time import time

from itsi.itsi_utils import ITOAInterfaceUtils, DEFAULT_SCHEDULED_BACKUP_KEY

import splunk
from splunk.clilib.bundle_paths import make_splunkhome_path

from itsi.upgrade.file_manager import FileManager

from SA_ITOA_app_common.solnlib.server_info import ServerInfo

logger = utils.get_itoa_logger('itsi.object.backup_restore')

BACKUP_PATH = make_splunkhome_path(['var', 'itsi', 'backups'])

class ItsiBackupRestore(ItoaObject):
    """
    Implements ITSI Backup Restore
    """
    logger = logger
    log_prefix = '[ITSI Backup Restore] '
    collection_name = 'itsi_backup_restore_queue'
    ITOA_OBJECT_TYPE = 'backup_restore'

    def __init__(self, session_key, current_user_name):
        session_key = session_key
        super(ItsiBackupRestore, self).__init__(session_key,
                                                current_user_name,
                                                'backup_restore',
                                                collection_name=self.collection_name,
                                                title_validation_required=True)

    """
    Not adding any validations here since its only used internally
    In future if we see need, we could add validations.

    Schema for this object and how its used internally:

    create_time	- set when it creates the job
    start_time	- set when the job starts running
    end_time	- set when the job ends running
    last_queued_time - set when the job is queued
    status	    - 'Not Started'/'Queued'/'Completed'/'Failed'
    path	    - file path to the backup, uses upload/download endpoints
    job_type	- 'Backup' or 'Restore'
    last_error	- Last error seen when job tried to backup/restore, if any, else None
    """

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        info = ServerInfo(self.session_key)
        local_search_head_id = info.guid

        for json_data in objects:
            # Assume json_data is valid

            # If creating a backup job or a restore job, generate key and assign path
            if method == CRUDMethodTypes.METHOD_CREATE:
                # if it's default scheduled backup, no need to generate a new key
                if not (json_data.get('_key') == DEFAULT_SCHEDULED_BACKUP_KEY and json_data.get('scheduled') == 1):
                    json_data['_key'] = ITOAInterfaceUtils.generate_backend_key()
                # for a new restore job created from the default scheduled job, we do not want to overwrite the path
                if not json_data.get('path'):
                    json_data['path'] = os.path.join(make_splunkhome_path(['var', 'itsi', 'backups']), json_data["_key"], 'backup')
                if not json_data.get('search_head_id'):
                    json_data['search_head_id'] = local_search_head_id
                if json_data.get('status') == 'Queued' and (
                    not isinstance(json_data.get('last_queued_time'), basestring) or len(
                            json_data.get('last_queued_time')) < 1):
                    json_data['last_queued_time'] = time()

            if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:
                if json_data['path'] == '':
                    path = os.path.join(BACKUP_PATH,json_data['_key'], 'backup')
                    json_data['path'] = path

                # if Backup zip file exists locally, populate search_head_id to current host's guid
                path_to_backup_zip = os.path.join(BACKUP_PATH, json_data['_key'] + '.zip')
                if FileManager.is_exists(path_to_backup_zip):
                    json_data['search_head_id'] = local_search_head_id

                    if json_data['status'] == 'Queued' and (
                        not isinstance(json_data.get('last_queued_time'), basestring) or len(
                                json_data.get('last_queued_time')) < 1):
                        json_data['last_queued_time'] = time()

    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        """
        Identifying dependencies due to the changes and instead of creating a refresh job, immediately handling the job
            @param {string} owner: user which is performing this operation
            @param {list} objects: list of object
            @param {string} method: method name
            @param {string} req_source: request source
            @return: a tuple
            {boolean} set to true/false if dependency update is required
            {list} list - list of refresh job, each element has the following
                change_type: <identifier of the change used to pick change handler>,
                changed_object_key: <Array of changed objects' keys>,
                changed_object_type: <string of the type of object>
        """
        if method == CRUDMethodTypes.METHOD_DELETE:
            for object in objects:
                path_to_directory = os.path.join(BACKUP_PATH, object.get('_key'))
                path_to_zip = os.path.join(BACKUP_PATH, object.get('_key') + '.zip')
                if FileManager.is_exists(path_to_directory):
                    FileManager.delete_working_directory(path_to_directory)
                if FileManager.is_exists(path_to_zip):
                    FileManager.delete_file(path_to_zip)
        return False, None

    def is_any_backup_restore_job_in_progress(self, owner, req_source='unknown'):
        """
        Checks for any backup/restore job in progress. Returns True, if
        there is at least on job is in progress. Else, returns False.
        @type owner: basestring
        @param owner: user performing operation
        @type req_source: basestring
        @param req_source: request source
        @return: bool
        """
        job_fetch_filter = {'status': 'In Progress'}
        backup_restore_job = self.get_bulk(owner, filter_data=job_fetch_filter, limit=1, req_source=req_source)

        is_job_in_progress = False
        if backup_restore_job and len(backup_restore_job) > 0:
            is_job_in_progress = True

        return is_job_in_progress


