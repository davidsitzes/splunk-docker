# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
KVBackupRestore performs most of the backup and restoration operations
This, along with migration, allow us to take snapshots of any system and restore from
at least 2 versions back.
"""
import sys
import os
import errno
import json
import logging
import glob
import re
import time
import zipfile
import shutil
import glob

from splunk.appserver.mrsparkle.lib import i18n
from splunk.rest import simpleRequest
from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import normalizeBoolean

from ITOA.storage import itoa_storage
from ITOA.itoa_factory import instantiate_object
from ITOA.itoa_common import save_batch, FileManager
from migration.migration import MigrationBaseMethod

import itsi_migration
from itsi.upgrade.itsi_module_related_migration import MigrateModuleKPIsToSharedBaseSearch, AddItsiRoleEntityRuleToServices, \
    UpdateChangedDatamodelKPIs_2_2_0_to_2_3_0
from ITOA.setup_logging import setup_logging
from ITOA.version_check import VersionCheck
from itsi.itsi_utils import ITOAInterfaceUtils, OBJECT_COLLECTION_MATRIX, DEFAULT_SCHEDULED_BACKUP_KEY
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from itsi.backup_restore.constants import (BACKUP_RESTORE_ADVANCED_MODE)
from itsi.objects.itsi_scheduled_backup import ScheduledBackup
from itsi.objects.itsi_backup_restore import BACKUP_PATH
from itsi.service_template.service_template_utils import ServiceTemplateUtils

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccessStore

from SA_ITOA_app_common.solnlib.server_info import ServerInfo

# FIXME: Revert this change after APPSC-1175 is fixed, append app_common in sys.path.
# Adding current app's lib/app_common to sys.path
# Only for Ember. Galaxy should have no such problems with make_splunkhome_path
# injecting bin/ of all apps in PYTHONPATH"
from SA_ITOA_app_common.apifilesave.filesave import ApifilesaveService
from SA_ITOA_app_common.apiiconcollection.iconcollection import IconService

logger = setup_logging("itsi_config.log", "itsi.kvstore.operations",
                       is_console_header=True)

WAIT_FOR_COMPLETE_TIMER = 5

class KVStoreBackupRestore(object):
    """
    Module that lets a caller:
    - backup data from KV Store to given file path or basedir
    - restore data from basedir on disk to KV Store
    """
    LIMIT = 10000
    ITSI_CORRELATION_SEARCH_COLLECTION = "itsi_correlation_search"
    ITSI_SERVICES_COLLECTION = "itsi_services"
    ITSI_PAGES_COLLECTION = "itsi_pages"
    ITSI_BASE_SERVICE_TEMPLATE_COLLECTION = "itsi_base_service_template"
    ITSI_SERVICE_ANALYZER_COLLECTION = "itsi_service_analyzer"
    ITSI_MIGRATION_COLLECTION = "itsi_migration"
    ITSI_NOTABLE_EVENT_COMMENT_COLLECTION = "itsi_notable_event_comment"
    ITSI_NOTABLE_EVENT_TAG_COLLECTION = "itsi_notable_event_tag"
    ITSI_NOTABLE_EVENT_TICKETING_COLLECTION = "itsi_notable_event_ticketing"
    ITSI_NOTABLE_EVENT_GROUP_COLLECTION = "itsi_notable_event_group"
    ITSI_NOTABLE_EVENT_STATE_COLLECTION = "itsi_notable_event_state"
    ITSI_NOTABLE_EVENT_AGGREGATION_POLICY_COLLECTION = "itsi_notable_event_aggregation_policy"
    ITSI_SECURITY_GROUP_COLLECTION = 'itsi_team'
    ITSI_NOTABLE_EVENT_SEED_GROUP_COLLECTION = "itsi_correlation_engine_group_template"
    ITSI_ENTITY_RELATIONSHIP_COLLECTION = "itsi_entity_relationships"
    ITSI_ENTITY_RELATIONSHIP_RULE_COLLECTION = "itsi_entity_relationship_rules"
    ITSI_SCHEDULED_BACKUP_COLLECTION = "itsi_backup_restore_queue"
    UA_APP_CAPABILITIES_COLLECTION = "app_capabilities"
    UA_APP_ACL_COLLECTION = "app_acl"
    GLASS_TABLE_IMAGES_COLLECTION = 'SA-ITOA_files'
    GLASS_TABLE_ICONS_COLLECTION = 'SA-ITOA_icon_collection'

    # Failed import file
    ITSI_FAILED_IMPORT_PREFIX = "failed_restore"

    FILE_EXTENSION_PREFIX = ".json"

    # Working directory for placing backup zip files for backups created from UI
    BACKUP_PATH = make_splunkhome_path(['var', 'itsi', 'backups'])

    def __init__(self, session_key, file_path, backup_data,
                 persist_data=True, br_version=None, dupname_tag=None,
                 is_debug=False, logger_instance=None, is_dry_run=False,
                 rule_file_path=None, mode=None):
        """
        The init method

        @param session_key: The splunkd session key of the username
        @type session_key: basestring

        @param file_path: location on disk from where we read from/write to
            ex: /home/users/foobar/backup/splunk
        @type file_path: basestring

        @param old_version: indicates if we are working with a ITSI version 1.2 or older
            How does this change things? Version 1.2/older only has 1 collection
            Version 2.0 onwards will have atleast 5 collections
            Restoration/Backup processes are drastically different.
        @type old_version: bool

        @param backup_data: indicates if caller wants to backup data.
            False implies that caller wants to 'restore' data from disk
        @type backup_data: bool

        @param persist_data: applicable when backup_data is False ie. caller wants restoration from disk
            True will drive us to append data from disk to KV Store
            False will drive us to wipe out what exists in KV Store and replace it with what exists on disk
        @type persist_data: bool

         @param is_debug: debug flag
         @type: bool

         @param mode: use BACKUP_RESTORE_ADVANCED_MODE when using utility from ui.
         @type mode: basestring
        """
        self.username = 'nobody'
        self.session_key = session_key
        self.migration_object = MigrateSchema(session_key, self.username)
        self.basedir = file_path
        self.backup_data = backup_data
        self.persist_data = persist_data
        self.is_dry_run = is_dry_run
        self.dupname_tag = dupname_tag
        self.current_app_version = ITOAInterfaceUtils.get_app_version(
            self.session_key,
            'itsi',
            self.username,
            fetch_conf_only=True
        )
        self.mode = mode
        self._backup_key = None

        # Notable type objects:
        self.notable_type_objects = set(['notable_event_tag', 'notable_event_comment', 'external_ticket', 'notable_event_group', 'notable_event_state', 'notable_aggregation_policy', 'notable_event_seed_group'])

        # Migration base class methods:
        self.mi_method = MigrationBaseMethod(self.session_key)

        if logger_instance is not None:
            global logger
            logger = logger_instance

        if is_debug:
            logger.setLevel(logging.DEBUG)

        logger.debug("Processing argument file_path=%s, is_backup=%s, is_persist=%s, is_debug=%s,"
                     "is_dry_run=%s", self.basedir, self.backup_data, self.persist_data, is_debug,
                     self.is_dry_run)

        self.rule_file_object = None

        # Validate rule file
        if rule_file_path:
            self.rule_file_object = RuleFile(rule_file_path)

        # Check if file path exists; else try creating it
        if self.backup_data:
            logger.debug("Creating backup directory %s", self.basedir)
            if self.mode == BACKUP_RESTORE_ADVANCED_MODE and FileManager.is_exists(self.basedir):
                FileManager.delete_working_directory(self.basedir)
            FileManager.create_directory(self.basedir)
            self.is_provided_path_is_file = False
        else:
            # Restore is supported from single file as well to support for failed attempts on specific objects
            if not FileManager.is_directory(self.basedir):
                logger.debug('Provided basedir is not directory: %s', str(self.basedir))
                self.is_provided_path_is_file = True
                for file_name in glob.glob(self.basedir):
                    if not FileManager.is_file(file_name):
                        logger.warning("Path=%s is not a file", file_name)
                        raise ValueError(_("Provided path is not neither a file nor a directory, provide a valid path"))
            else:
                self.is_provided_path_is_file = False

            # We will unzip for advanced mode in init to enable looking up backup info before starting the restore job
            if self.mode == BACKUP_RESTORE_ADVANCED_MODE:
                # self.basedir is of the format : $splunkhome/var/itsi/backups/<_key>/backup
                if len(self.basedir.split(os.sep)) >= 2:
                    key = self._get_key_from_path()
                    logger.debug("Attempting to restore from: %s", os.path.join(self.BACKUP_PATH, key +'.zip'))
                    if FileManager.is_exists(os.path.join(self.BACKUP_PATH, key +'.zip')):
                        self.unzip_backup(os.path.join(self.BACKUP_PATH, key + '.zip'), os.path.join(self.BACKUP_PATH, key))
                        self.is_provided_path_is_file = False
                    else:
                        raise IOError(_('Backup file not found. Please ensure backup zip file is present.'))
        # If ITSI version is available in backup path, thats the most reliable.
        # If that is not available, use the one passed in
        self.br_version = None
        if self.backup_data:
            self.br_version = self.current_app_version
        else:
            self.br_version = self._get_app_version_from_backup()
            if self.br_version is None and self._is_version_valid(br_version):
                self.br_version = br_version

        # defined collection
        # Unsed only in backup
        self.old_collections = [self.ITSI_SERVICES_COLLECTION, self.ITSI_CORRELATION_SEARCH_COLLECTION,
                                self.ITSI_PAGES_COLLECTION, self.ITSI_SERVICE_ANALYZER_COLLECTION,
                                self.ITSI_MIGRATION_COLLECTION, self.ITSI_SECURITY_GROUP_COLLECTION]
        # Correlation search will be picking up from the conf file instead of from the kv_store
        self.new_collections = list(set(
            OBJECT_COLLECTION_MATRIX.values() +
            [
                self.ITSI_SERVICES_COLLECTION,
                self.ITSI_CORRELATION_SEARCH_COLLECTION,
                self.ITSI_PAGES_COLLECTION,
                self.ITSI_BASE_SERVICE_TEMPLATE_COLLECTION,
                self.ITSI_SERVICE_ANALYZER_COLLECTION,
                self.ITSI_MIGRATION_COLLECTION,
                self.ITSI_NOTABLE_EVENT_TAG_COLLECTION,
                self.ITSI_NOTABLE_EVENT_COMMENT_COLLECTION,
                self.ITSI_NOTABLE_EVENT_TICKETING_COLLECTION,
                self.ITSI_NOTABLE_EVENT_GROUP_COLLECTION,
                self.ITSI_NOTABLE_EVENT_STATE_COLLECTION,
                self.ITSI_NOTABLE_EVENT_AGGREGATION_POLICY_COLLECTION,
                self.ITSI_NOTABLE_EVENT_SEED_GROUP_COLLECTION,
                self.UA_APP_CAPABILITIES_COLLECTION,
                self.UA_APP_ACL_COLLECTION,
                self.GLASS_TABLE_IMAGES_COLLECTION,
                self.GLASS_TABLE_ICONS_COLLECTION,
                self.ITSI_ENTITY_RELATIONSHIP_COLLECTION,
                self.ITSI_ENTITY_RELATIONSHIP_RULE_COLLECTION,
                self.ITSI_SCHEDULED_BACKUP_COLLECTION
            ]
        ))

        # old_version : below ITSI 2.2.0
        if self.br_version is None or VersionCheck.compare('2.2.0', self.br_version) > 0:
            logger.debug("Perform operation on old collections")
            self.collections = self.old_collections
        else:
            logger.debug("Perform operation on new collections")
            self.collections = self.new_collections

    @classmethod
    def cleanup_backup_working_directory(cls, key):
        """
        Method cleans up the backup directory $BACKUP_PATH/<key>, where <key> is the _key of the job

        @param key: key of the job, whose corresponding working directory will be deleted from disk
        @type key: basestring
        """
        if FileManager.is_exists(os.path.join(cls.BACKUP_PATH, key)):
            FileManager.delete_working_directory(os.path.join(cls.BACKUP_PATH, key))

    def _is_migration_needed(self):
        # If the data file version is less than the current app version, migration is needed
        if VersionCheck.compare(self.current_app_version, self.br_version) > 0:
            return True
        return False

    def _is_itsi_version_2_2(self):
        # Indicating whether data file is in 2.2.0 format
        if VersionCheck.compare(self.br_version, "2.2.0") >= 0:
            return True
        return False

    def _get_backend_storage(self, collection=None):
        """
        Get backend storage object

        @type collection: basestring
        @param collection: collection name

        @rtype: object
        @return: return object
        """
        if collection is None:
            collection = self.ITSI_SERVICES_COLLECTION
        return itoa_storage.ITOAStorage(collection=collection)

    def _get_itoa_object_instance(self, object_type):
        """
        Get itoa object instance

        @type object_type: basestring
        @param object_type: object_type

        @rtype: object
        @return: itoa_object instance
        """
        if object_type in ['link_table', 'service_entity_link']:
            logger.warning("Object type %s is deprecated. - Skipping backup or restore", object_type)
            return None
        return instantiate_object(self.session_key, self.username, object_type, logger=logger)

    def _print_dry_run_object_type(self, object_type):
        """
        Print object type for dry run

        @type object_type: basestring
        @param object_type: object_type

        @return: None
        """
        if object_type is not None and object_type != "":
            print "<<<<<<<<<<<<<<<<<<< Object Type = %s  >>>>>>>>>>>>>>>>>>>>>>>" % object_type

    def _print_dry_run_data_list(self, data_list):
        """
        Print data title for each object

        @type data_list: list
        @param data_list: object list to print title

        @return: None
        """
        for data in data_list:
            if 'title' in data:
                print "Title = %s (_key = %s)" % (data.get('title'), data.get('_key'))
            elif '_key' in data and data.get('_key', "") != "":
                print "Title field does not exist but _key=%s" % data.get('_key')

    def _read_data_from_collection(self, object_type, collection, file_path, file_rolling_number):
        """
        Read data from collection

        @type object_type: basestring
        @param object_type: object_type

        @type collection: basestring
        @param collection: collection name

        @type file_path: basestring
        @param file_path: file full path

        @type file_rolling_number: int
        @param file_rolling_number: rolling number

        @return:
        """

        skip = 0
        logger.info("Reading %s from kv store", object_type)
        retrieved = False

        while True:
            if (self._is_itsi_version_2_2()) and (object_type in self.notable_type_objects):
                if not retrieved:
                    data = self._get_object_content_from_collection('SA-ITOA', collection)
                    retrieved = True
            elif (self._is_itsi_version_2_2()) and (object_type == 'correlation_search'):
                if not retrieved:
                    data = self._get_correlation_searches()
                    retrieved = True
            elif (self._is_itsi_version_2_2()) and (object_type in [self.UA_APP_ACL_COLLECTION, self.UA_APP_CAPABILITIES_COLLECTION]):
                if not retrieved:
                    data = self._get_object_content_from_collection('SA-UserAccess', collection)
                    retrieved = True
            elif object_type == 'glass_table_images':
                if not retrieved:
                    data = self._get_images_from_filesave_api()
                    retrieved = True
            elif object_type == 'glass_table_icons':
                if not retrieved:
                    data = self._get_icons_from_iconcollection_api()
                    retrieved = True
            # get scheduled backup from itsi_backup_restore_queue collection
            elif object_type == 'backup_restore':
                if not retrieved:
                    data = self._get_default_scheduled_backup()
                    if len(data) > 0:
                        data[0]['status'] = 'Scheduled Weekly' if data[0].get('frequency') == 'weekly' else 'Scheduled Daily'
                    retrieved = True
            else:
                itoa_instance = self._get_itoa_object_instance(object_type)
                if not itoa_instance:
                    return
                data = itoa_instance.get_bulk(self.username, sort_key='identifying_name', sort_dir=1, skip=skip, limit=self.LIMIT)

            if data is None or len(data) == 0:
                logger.info("Successfully collected all data for object=%s", object_type)
                break
            # apply rules here
            data = self.apply_rules(data)
            # only display list of object title
            if self.is_dry_run:
                self._print_dry_run_data_list(data)
            else:
                if data and len(data) >= 0:
                    rolling_file_name = FileManager.get_rolling_file_name(file_path, file_rolling_number)
                    logger.debug("Rolling file name to save data is=%s", rolling_file_name)
                    FileManager.write_to_file(rolling_file_name, data)
                    logger.debug("Successfully wrote object=%s, length=%s data to file=%s",
                                 object_type,
                                 len(data),
                                 rolling_file_name)
            file_rolling_number += 1
            skip += self.LIMIT
            if retrieved:
                data = None

    def _write_data_to_collection(self, object_type, collection, data, is_skip_deletion=False, no_batch=False):
        """
        Write data to collection
        @type object_type: basestring
        @param object_type: object_type

        @type collection: basestring
        @param collection: collection name

        @param data: list
        @param data: data to write to collection in json form

        @param is_skip_deletion: bool
        @param is_skip_deletion: in case we want to skip deletion

        @param no_batch: bool
        @param no_batch: when user to save as single object instead of batch

        @return: None
        """
        ################
        # Exceptions
        ################

        if not self.persist_data:
            if not is_skip_deletion:
                logger.info("Deleting objecttype=%s data first", object_type)
                self.mi_method.migration_delete_kvstore(object_type)

        # special handling for scheduled backup job
        # replacing scheduled backup job key, search head id, start_time, end_time and path with current job in kvstore
        if object_type == 'backup_restore':
            logger.info("Replacing scheduled backup job fields with current job in kvstore")
            scheduled_backup = self._get_default_scheduled_backup()
            if len(data) == 0:
                logger.info('No scheduled backup job in backup file')
            elif len(data) == 1:
                try:
                    replace_fields = ['_key', 'search_head_id', 'path', 'start_time', 'end_time', 'last_error']
                    for field in replace_fields:
                        data_in_kvstore = scheduled_backup[0].get(field)
                        if data_in_kvstore:
                            data[0][field] = data_in_kvstore
                except:
                    data[0]['path'] = os.path.join(BACKUP_PATH, DEFAULT_SCHEDULED_BACKUP_KEY, 'backup')
                    data[0]['search_head_id'] = ServerInfo(self.session_key).guid
                    logger.info('No scheduled backup exists, '
                                'will just use the scheduled backup data from backup file')
            else:
                logger.warning('More than one scheduled backup job in backup file, '
                               'will not restore %s' % object_type)
                data = []

        try:
            self.mi_method.migration_save(object_type, data)
            logger.info("Successfully wrote %s of %s to local storage", len(data), object_type)
        except Exception as e:
            logger.info("Failed in moving data from backup file to local storage, object_type: %s", object_type)

    def _get_file_pattern(self, collection_name, object_type):
        """
        Get file name which follows patter <collection_name>___<object_name>___<rolling_number>.json
        Note: delimiter is ___
        Rolling number is added when before we start writing it

        @type object_type: basestring
        @param object_type: object_type

        @type collection_name: basestring
        @param collection_name: collection name

        @rtype: basestring
        @return: file name
        """
        return os.path.join(self.basedir, collection_name + FileManager.DELIMITER + object_type + self.FILE_EXTENSION_PREFIX)

    def _get_object_type_from_collection(self, collection):
        """
        Get all possible object type in given collection

        @type collection: basestring
        @param collection: collection name

        @rtype: list
        @return: list of unique object type in a collection
        """
        object_types = []

        ######## Fake object_types for the following cases. Its not applicable.
        ########

        # With version 2.2.0 or above, correlation_search are stored in savedsearch.conf.
        if self._is_itsi_version_2_2() and (collection == self.ITSI_CORRELATION_SEARCH_COLLECTION):
            object_types = ['correlation_search']
            return object_types

        # with version 2.2.0 or above, we have ACLs for shared objects stashed
        # away in SA-UserAccess in addition to app capabilities.
        if self._is_itsi_version_2_2() and (collection == self.UA_APP_ACL_COLLECTION):
            object_types = [self.UA_APP_ACL_COLLECTION]
            return object_types

        if self._is_itsi_version_2_2() and (collection == self.UA_APP_CAPABILITIES_COLLECTION):
            object_types = [self.UA_APP_CAPABILITIES_COLLECTION]
            return object_types

        ######## No more faking of object_type here on
        ########

        location = '/servicesNS/nobody/SA-ITOA/storage/collections/data/' + collection
        getargs = {'fields': 'object_type'}
        rsp, content = simpleRequest(location, sessionKey=self.session_key, raiseAllErrors=False, getargs=getargs)
        if rsp.status != 200:
            logger.error("Failed to get object type, response=%s, content=%s", rsp, content)
        else:
            for obj in json.loads(content):
                if obj.get('object_type') is not None and obj.get('object_type') not in object_types:
                    object_types.append(obj.get('object_type'))

        return object_types

    def _get_correlation_searches(self):
        '''Get existing correlation searches from conf file as a list of blobs
        @rtype: list of dicts
        @return existing correlation searches
        '''
        search_interface = ItsiCorrelationSearch(self.session_key)
        saved_searches = search_interface.get_bulk(None)
        return saved_searches

    def _get_object_content_from_collection(self, app, collection):
        """
        Get all possible object content of a given collection

        @type collection: basestring
        @param collection: collection name

        @rtype: json object
        @return: actual object content in json format
        """
        # Currently, kvstore backup script only supports two apps
        if app not in ['SA-ITOA', 'SA-UserAccess']:
            return None

        location = '/servicesNS/nobody/{0}/storage/collections/data/{1}'.format(app, collection)
        rsp, content = simpleRequest(location, sessionKey=self.session_key)
        if rsp.status != 200:
            logger.error("Failed to get object content, response=%s, content=%s", rsp, content)
            raise Exception(_("Failed to get object content"))
        try:
            return json.loads(content)
        except:
            message = _("Failed to convert object content to json format")
            logger.error(message)
            raise Exception(message)

    def _get_default_scheduled_backup(self):
        """
        Get scheduled backup from itsi_backup_restore queue collection

        @rtype: json object
        @return: actual object content in json format
        """
        scheduled_backup_object = ScheduledBackup(session_key=self.session_key, current_user_name='nobody')
        return scheduled_backup_object._get_scheduled_backup()


    def _get_images_from_filesave_api(self):
        """
        Get all the images from the filesave api endpoint

        @rtype: json object
        @return: actual object content in json format
        """
        api_filesave_service = ApifilesaveService(app_name='SA-ITOA', session_id=self.session_key, user_name='nobody', collection_name='SA-ITOA_files')
        data = api_filesave_service.get_all()
        return json.loads(data)

    def _save_images_in_filesave_api(self, data):
        """
        Save all the images from the json file into the kvstore

        @type data: json object
        @param data: image collection to be written to the filesave endpoint

        @return: None
        """
        api_filesave_service = ApifilesaveService(app_name='SA-ITOA', session_id=self.session_key, user_name='nobody', collection_name='SA-ITOA_files')
        if not self.persist_data:
            logger.debug('Deleting images for glass table')
            api_filesave_service.delete_all()
        for image in data:
            try:
                api_filesave_service.create(image)
            except:
                # in case there is already the same entry in the collection skip and go on
                logger.info('Image with key %s already found in collection', image['_key'])
                continue
        logger.info('Successfully added %s glass table images', str(len(data)))


    def _get_icons_from_iconcollection_api(self):
        """
        Get all the images from the iconcollection api endpoint

        @rtype: json object
        @return: actual object content in json format
        """
        icon_service = IconService(app_name='SA-ITOA', session_id=self.session_key, user_name='nobody', collection_name='SA-ITOA_icon_collection')
        data = icon_service.get_all({})
        return json.loads(data)['result']

    def _save_icons_in_iconcollection_api(self, data):
        """
        Save all the icons from the json file into the kvstore

        @type data: json object
        @param data: image collection to be written to the iconcollection endpoint

        @return: None
        """
        icon_service = IconService(app_name='SA-ITOA', session_id=self.session_key, user_name='nobody', collection_name='SA-ITOA_icon_collection')
        if not self.persist_data:
            logger.debug('Deleting icon collections for glass table')
            icon_service.bulk_delete_category('*')
        for icon in data:
            try:
                icon_service.create(icon)
            except:
                # in case there is already the same entry in the collection skip and go on
                logger.info('Icon with key %s already found in collection', icon['_key'])
                continue
        logger.info('Successfully added %s glass table icons', str(len(data)))

    def _collect_file_info_for_restore(self):
        """
        Get file name and its associated information from file system

        @rtype: dict
        @return: dict of all collection and object_type and file information
            {
                <collection_name>___<object_type> : list of files which hold information
            }

        """
        # Perform data
        file_collection_info = {}
        for file in os.listdir(self.basedir):
            if os.path.exists(os.path.join(self.basedir, file)):
                split_pattern = file.split(FileManager.DELIMITER)
                # File pattern should be <collection_name>__<object_type>__<rolling_number>
                # split should have three elements
                if len(split_pattern) != 3:
                    if file != 'app_info.json' and not file.startswith('.'):
                        logger.warning("Can't read file=%s because it does not follow file pattern. Make sure file "
                                       "pattern should be <collection_name>__<object_type>__<rolling_number>.json", file)
                        continue
                else:
                    key_name = split_pattern[0] + FileManager.DELIMITER + split_pattern[1]
                    if key_name in file_collection_info:
                        file_collection_info[key_name].append(os.path.join(self.basedir, file))
                    else:
                        file_collection_info[key_name] = [os.path.join(self.basedir, file)]
        return file_collection_info

    def _backup_app_info(self):
        '''
        Saves away app information in the backup folder before taking the backup

        Currently this consists of:
        > Current running version of the ITSI app

        @return: None
        '''
        if not self.is_provided_path_is_file:
            FileManager.write_to_file(
                self._get_backup_app_info_filepath(),
                {'itsi_version': self.current_app_version}
            )
        else:
            raise Exception(_('Method not supported on backup paths of type files'))

    def _get_backup_app_info_filepath(self):
        '''
        Helper method to construct path to app_info doe backup path

        @rtype: basestring
        @return: path to the app info file within the backup
        '''
        if self.is_provided_path_is_file:
            raise Exception(_('Method not supported on backup paths of type files'))
        else:
            return os.path.join(self.basedir, 'app_info' + self.FILE_EXTENSION_PREFIX)

    @staticmethod
    def _is_version_valid(version):
        '''
        Helper to validate version string
        @type: basestring
        @rtype version: version string to validate

        @rtype: boolean
        @return: True if valid, False otherwise
        '''
        return isinstance(version, basestring) and len(version.strip()) > 0 and VersionCheck.validate_version(version)

    def _get_app_version_from_backup(self):
        '''
        Retrieves app information from the backup path during a restore
        Used to determine version of the ITSI app on which the backup data was collected
        Knowing the correct app version of the backup helps restore operations pick the right migration APIs

        @return: None
        '''
        if self.backup_data:
            return self.current_app_version
        else:
            if self.is_provided_path_is_file:
                # Backup path does not contain app info
                return None
            else:
                app_info_filepath = self._get_backup_app_info_filepath()
                if FileManager.is_exists(app_info_filepath):
                    app_info = FileManager.read_data(app_info_filepath)
                    if isinstance(app_info, dict):
                        itsi_version = app_info.get('itsi_version')
                        if self._is_version_valid(itsi_version):
                            return itsi_version
        return None

    def get_app_version_of_backup(self):
        '''
        Used by external callers to query the ITSI version of backup path

        @rtype: basestring
        @return: version of ITSI app for the backup path
        '''
        return self.br_version

    def set_app_version_of_backup(self, backup_version):
        '''
        Sets the version of the ITSI app that is/was used to create the backup data
        This method is used to set a user defined version primarily by the commandline tool during restore

        @type: basestring
        @param backup_version: ITSI version to use for the backup data

        @rtype: boolean
        @return: True is version was set, False otherwise
        '''
        # If existing value is set, it is likely the auto extracted value which is more accurate, do not overwrite
        # Note that this method is expected to be used only when auto extract cant identify version
        if self.br_version is not None:
            return False

        # Overwrite existing version only if a valid one is specified
        # Ignore silently and let caller handle invalid case
        if self._is_version_valid(backup_version):
            self.br_version = backup_version
            return True

        return False

    def backup(self):
        """
        Perform backup
        """
        try:
            # First write the current version of the app to the backup
            self._backup_app_info()

            # Now backup all data
            for collection in self.collections:
                object_types = self._get_object_type_from_collection(collection)
                if collection == self.GLASS_TABLE_IMAGES_COLLECTION:
                    object_types.append('glass_table_images')
                elif collection == self.GLASS_TABLE_ICONS_COLLECTION:
                    object_types.append('glass_table_icons')
                for object_type in object_types:
                    # We need to just display it
                    if self.is_dry_run:
                        self._print_dry_run_object_type(object_type)
                    file_path = self._get_file_pattern(collection, object_type)
                    self._read_data_from_collection(object_type, collection, file_path, 0)

            # For advanced mode (UI), save the backup as a zip file
            if self.mode == BACKUP_RESTORE_ADVANCED_MODE:
                if(len(self.basedir.split(os.sep))) >= 2:
                    name_of_zip_file = self.basedir.split(os.sep)[-2]
                    self.zip_directory(self.basedir, name_of_zip_file)
        except Exception as e:
            if self.mode == BACKUP_RESTORE_ADVANCED_MODE:
                if (len(self.basedir.split(os.sep))) >= 2:
                    name_of_zip_file = self.basedir.split(os.sep)[-2]
                    if FileManager.is_exists(os.path.join(self.BACKUP_PATH, name_of_zip_file)):
                        FileManager.delete_working_directory(os.path.join(self.BACKUP_PATH, name_of_zip_file))
            raise e

    def _restore_data(self, data, collection, object_type):
        """
            Put data to collection after updating the schema

            @type data: list
            @param data: list of same objects type to restore

            @type collection: basestring
            @param collection: collection name where it need to be stored

            @type object_type: basestring
            @param object_type: object type
        """

        # apply rules here
        data = self.apply_rules(data)
        if self.is_dry_run:
            self._print_dry_run_data_list(data)
        else:
            #save one by one object. Large GT can't be saved in bulk
            no_batch = True if object_type == 'glass_table' else False
            self._write_data_to_collection(object_type, collection, data, no_batch=no_batch)

    def restore_from_folder(self):
        """
        Perform restore
        """
        file_infos = self._collect_file_info_for_restore()
        # Make entity should store before service
        sorted_keys = sorted(file_infos.keys(), key=lambda x: self._weight(x.split(FileManager.DELIMITER)[1]))
        for key in sorted_keys:
            file_paths = file_infos[key]
            collection, object_type = key.split(FileManager.DELIMITER)
            # Display object type of dry run
            if self.is_dry_run:
                self._print_dry_run_object_type(object_type)

            data = []
            for file_path in file_paths:
                data.extend(FileManager.read_data(file_path))
            self._restore_data(data, collection, object_type)
            time.sleep(WAIT_FOR_COMPLETE_TIMER)
        migration = itsi_migration.ItsiMigration(self.session_key, 
                                                 backup_version=self.br_version,
                                                 dupname_tag= self.dupname_tag)
        logger.info("Restoring in progress, please wait...")
        status = migration.run_migration()
        if status:
            logger.info("Restore completed successful from folder!")
        else:
            failure_msg = _("Restore failed, please check the itsi_migration.log for details.")
            logger.error(failure_msg)
            raise Exception(failure_msg)

    def _get_collection_name_for_object(self, object_type):
        """
            Get collection name based upon object_type
            @type object_type: basestring
            @param object_type: object_type
        """
        if object_type == "glass_table" or object_type == "deep_dive":
            return self.ITSI_PAGES_COLLECTION
        elif object_type == "home_view":
            return self.ITSI_SERVICE_ANALYZER_COLLECTION
        elif object_type == "migration":
            return self.ITSI_MIGRATION_COLLECTION
        elif object_type == "notable_event_comment":
            return self.ITSI_NOTABLE_EVENT_COMMENT_COLLECTION
        elif object_type == "notable_event_group":
            return self.ITSI_NOTABLE_EVENT_GROUP_COLLECTION
        elif object_type == "notable_event_state":
            return self.ITSI_NOTABLE_EVENT_STATE_COLLECTION
        elif object_type == "notable_aggregation_policy":
            return self.ITSI_NOTABLE_EVENT_AGGREGATION_POLICY_COLLECTION
        elif object_type == "notable_event_seed_group":
            return self.ITSI_NOTABLE_EVENT_SEED_GROUP_COLLECTION
        elif object_type == "notable_event_tag":
            return self.ITSI_NOTABLE_EVENT_TAG_COLLECTION
        elif object_type == "external_ticket":
            return self.ITSI_NOTABLE_EVENT_TICKETING_COLLECTION
        elif object_type == "team":
            return self.ITSI_SECURITY_GROUP_COLLECTION
        elif object_type == "entity_relationship":
            return self.ITSI_ENTITY_RELATIONSHIP_COLLECTION
        elif object_type == "entity_relationship_rule":
            return self.ITSI_ENTITY_RELATIONSHIP_RULE_COLLECTION
        elif object_type == 'backup_restore':
            return self.ITSI_SCHEDULED_BACKUP_COLLECTION
        elif object_type == 'base_service_template':
            return self.ITSI_BASE_SERVICE_TEMPLATE_COLLECTION
        else:
            return self.ITSI_SERVICES_COLLECTION

    def _weight(self, object_type):
        """
            Return the weight of different object types.
            This is needed when perform restoring.
            @type object_type: basestring
            @param object_type: object_type
        """
        if object_type == 'entity':
            return 0
        elif object_type == 'kpi_template':
            return 1
        elif object_type == 'kpi_base_search':
            return 2
        elif object_type == 'kpi_threshold_template':
            return 3
        elif object_type == 'service':
            return 4
        else:
            return 5

    def restore_from_files(self):
        """
            Restore it from file
        """
        for file_name in glob.glob(self.basedir):
            file_data_array = FileManager.read_data(file_name)
            store_object_data = {}
            for file_data in file_data_array:
                # object_type must to defined
                if file_data.get('object_type') is None and file_data.get('_type') is None:
                    continue
                object_type = file_data.get('object_type')
                if object_type in store_object_data:
                    store_object_data.get(object_type).append(file_data)
                else:
                    store_object_data[object_type] = [file_data]

            sorted_keys = sorted(store_object_data.keys(), key=lambda x: self._weight(x))
            for object_type_key in sorted_keys:
                data = store_object_data[object_type_key]
                if self.is_dry_run:
                    self._print_dry_run_object_type(object_type_key)
                self._restore_data(data, self._get_collection_name_for_object(object_type_key), object_type_key)
                time.sleep(WAIT_FOR_COMPLETE_TIMER)

    def apply_rules(self, data):
        """
        Apply rule set and return filter data

        @type data: list
        @param data: data to be filter if rule file is not defined then return same data back

        @rtype: list
        @return: filter or un-filter data
        """
        if self.rule_file_object:
            return self.rule_file_object.apply_rules(data)
        else:
            return data

    def _get_key_from_path(self):
        '''
        Helper to extract key for the backup job from the path
        Only applies to advanced mode
        Assumes a specific format for path: $splunkhome/var/itsi/backups/<_key>/backup

        @rtype: basestring
        @return: key if available
        '''
        if self._backup_key is not None:
            return self._backup_key

        if self.mode == BACKUP_RESTORE_ADVANCED_MODE:
            #self.basedir is of the format : $splunkhome/var/itsi/backups/<_key>/backup
            if len(self.basedir.split(os.sep)) >= 2:
                self._backup_key = self.basedir.split(os.sep)[-2]
                return self._backup_key
            else:
                logger.warn(
                    'Path specified for advanced mode of backup/restore seems invalid. Path: {0}'.format(self.basedir)
                )
        return None

    def restore(self):
        """
            Perform restore
        """

        def _restore_cleanup():
            if self.mode == BACKUP_RESTORE_ADVANCED_MODE:
                key = self._get_key_from_path()
                restore_path = os.path.join(self.BACKUP_PATH, key)
                if FileManager.is_exists(restore_path):
                    FileManager.delete_working_directory(restore_path)
                if FileManager.is_exists(restore_path):
                    logger.warn('Restore for job {0} could not cleanup restore working directory.'.format(key))

        if self.br_version is None:
            _restore_cleanup()
            raise Exception(_('We could not determine the ITSI version for which the backup data was collected. It is likely a ' +\
                  'backup taken from an old ITSI version. Please use the commandline tool to perform the restore ' +\
                  'operation by specifying the ITSI version on which the backup data was collected.'))
        else:
            logger.info(
                'Starting restore operation with ITSI version of the backup data as {0}.'.format(self.br_version)
            )

        if self.is_provided_path_is_file:
            logger.debug("Restoring from file(s)")
            self.restore_from_files()
        else:
            logger.debug("Restoring from folder")
            try:
                self.restore_from_folder()
            except OSError as e:
                # For File Not Found Exception
                if errno.ENOENT == e[0]:
                    raise OSError(_('File not found. Ensure zip file contains json files contained within a "backup" folder.'))
                raise e
            except Exception as e:
                logger.exception(e)
                raise e
            finally:
                _restore_cleanup()

        # ITSI 2.2.0 did not backup SA-UserAccess data.
        # When restoring the system based on a 2.2.0 backup json, just set the ACL to True
        # All ACL policies will be set properly in 2.2.1 and beyhond.
        if not self.is_dry_run and self.br_version == '2.2.0':
            logger.info("Restoring from version 2.2.0 backup files, need to reset all the ACL to True")
            self.migration_object.create_acl_object()

    def execute(self):
        """
        Method that does the bulk of operation
        """
        try:
            if self.backup_data:
                # block backup operation if service template sync in progress
                if ServiceTemplateUtils(self.session_key, self.username).service_template_sync_job_in_progress_or_sync_now():
                    msg = _("Scheduled sync of service template is in progress, cannot create backup at this time. " \
                          "Try again a little later. To see the status of sync operations, check the service template lister page.")
                    logger.error(msg)
                    sys.exit(0)

                logger.info("Start taking backup")
                self.backup()
                logger.info("Successfully done with backup")
            else:
                logger.info("Start restore operation")
                self.restore()
        except Exception as e:
            logger.exception(e)
            raise

    def zip_directory(self, path, name_of_zip_file):
        """
        Method that zips the directory whose path is provided.
        Also deletes directories not required after zipfile is created

        :param path:path to directory to zip
        :param name_of_zip_file: name of the created zip file
        """
        # Structure of directory:
        # $splunkHome/var/files/<_key>/backup/*.json
        # path is the path = $splunkHome/var/files/<_key>/backup
        # name of zip file = _key
        # final .zip is placed at splunkHome/var/itsi/backups and is named _key.zip
        # directories to be deleted after zip is created and moved to location are backup and _key

        try:
            FileManager.zip_directory(path, name_of_zip_file)
            logger.info("Successfully zipped backup files directory: " + str(path))
            FileManager.delete_working_directory(path)
            if len(path.split(os.sep)) >= 2:
                key = path.split(os.sep)[-2]
                path_to_key_directory = os.path.join(self.BACKUP_PATH, key)
                logger.debug('path to key directory is: '+ path_to_key_directory +"name of zipfile is: "+name_of_zip_file)
                shutil.move(os.path.join(path_to_key_directory,name_of_zip_file)+'.zip', os.path.join(self.BACKUP_PATH, name_of_zip_file)+'.zip')
                logger.info("Successfully moved zip file from:" + os.path.join(path_to_key_directory, name_of_zip_file) +"to: "+ os.path.join(self.BACKUP_PATH, name_of_zip_file))
                FileManager.delete_working_directory(path_to_key_directory)
        except OSError as ose:
            logger.exception(ose)
        except Exception as exc:
            logger.exception(exc)
            raise

    def unzip_backup(self, path_to_zip_file, extract_to_path):
        """
        Method unzips the backup .zip file
        :param path_to_zip_file:full path of zip file
        :param extract_to_path:path to extract zip file
        """
        try:
            logger.info("Unzip backup file")
            unzipped_directory_path = path_to_zip_file.split('.')[0]
            FileManager.unzip_backup(path_to_zip_file, extract_to_path)
            logger.info(
                'check if exists dir:' + str(unzipped_directory_path) + ':' + str(FileManager.is_exists((unzipped_directory_path))) + ':' + str(
                    FileManager.is_directory(unzipped_directory_path)))
            while FileManager.is_exists(unzipped_directory_path) == False:
                logger.info('waiting for unzip')
                time.sleep(1)
        except Exception as exc:
            logger.exception(exc)
            raise

class RuleFile(object):

    OBJECTS_WHITE_LIST = ['service', 'entity', 'home_view', 'kpi_template', 'deep_dive', 'kpi_threshold_template',
                          'correlation_search', 'glass_table']
    OBJECT_TYPE_KEY = 'object_type'
    TITLE_LIST_KEY = 'title_list'
    KEY_LIST_KEY = 'key_list'

    REPLACEMENT_RULES_KEY = 'replacement_rules'
    REPLACEMENT_KEY_LIST = ['title', '_key']
    REPLACEMENT_SCHEMA_TYPE_REPLACE = 'replace'
    REPLACEMENT_SCHEMA_TYPE_PREFIX = 'prefix'
    REPLACEMENT_SCHEMA_TYPE_POSTFIX = 'postfix'
    REPLACEMENT_SCHEMA_TYPE_LIST = [REPLACEMENT_SCHEMA_TYPE_REPLACE, REPLACEMENT_SCHEMA_TYPE_PREFIX,
                                    REPLACEMENT_SCHEMA_TYPE_POSTFIX]
    REPLACEMENT_SCHEMA_KEY = 'replacement_key'
    REPLACEMENT_SCHEMA_TYPE = 'replacement_type'
    REPLACEMENT_SCHEMA_REPLACEMENT_KEY = 'replacement_string'
    REPLACEMENT_SCHEMA_PATTERN_KEY = 'replacement_pattern'
    REPLACEMENT_SCHEMA_KEYS = [
        REPLACEMENT_SCHEMA_KEY, REPLACEMENT_SCHEMA_TYPE, REPLACEMENT_SCHEMA_REPLACEMENT_KEY,
        REPLACEMENT_SCHEMA_PATTERN_KEY
    ]
    REPLACEMENT_SCHEMA_REQUIRED_KEYS = [
        REPLACEMENT_SCHEMA_TYPE, REPLACEMENT_SCHEMA_KEY,
        REPLACEMENT_SCHEMA_REPLACEMENT_KEY
    ]

    def __init__(self, rule_file_path, is_validate=True):
        """
        Rule file path

        @type rule_file_path: basestring
        @param rule_file_path: rule file path
        """
        self.rule_file_path = rule_file_path
        # Initialized once rule spec is validated, initialize after rule spec is set
        self.rule_specs = None
        self.objects_rules = None

        if is_validate and not self._validate_rule_file():
            logger.error("Rules file is invalid")
            raise ValueError(_('Invalid rule file, please provide a valid rule file'))

        if not is_validate:
            self.rule_specs = FileManager.read_data(self.rule_file_path, 'r')

        # Objects_rules
        self.objects_rules = self.parse_rules()

    def _validate_rule_file(self):
        """
        Validate rule file and its contains

        @rtype: bool
        @return: return True or False
        """
        if self.rule_file_path is None or not FileManager.is_file(self.rule_file_path):
            logger.error('Provide file=%s is not a valid file', self.rule_file_path)
            return False
        else:
            data = FileManager.read_data(self.rule_file_path, 'r')
            is_validated = self._validate_rules(data)
            if is_validated:
                self.rule_specs = data
            return is_validated

    def _validate_rules(self, data_list):
        """
        Validate if file has right schema or not

        @type data_list: list
        @param data_list: data list

        @rtype: bool
        @return: True or False
        """
        # Validate keys
        for data in data_list:
            # check required key
            if self.OBJECT_TYPE_KEY not in data:
                logger.error('One or more required keys=%s is not defined in the file data=%s, required key are=%s',
                             self.OBJECT_TYPE_KEY, data, self.OBJECT_TYPE_KEY)
                return False
            else:
                lower_case = data.get(self.OBJECT_TYPE_KEY)
                if lower_case is not None:
                    lower_case = lower_case.strip().lower()
                if lower_case not in self.OBJECTS_WHITE_LIST:
                    logger.error('%s does not have valid value. Possible values are=%s', self.OBJECT_TYPE_KEY,
                                 self.OBJECTS_WHITE_LIST)
                    return False
            # Check for conditional key
            is_available = False
            available_key = None
            for key in [self.TITLE_LIST_KEY, self.KEY_LIST_KEY]:
                if key in data:
                    is_available = True
                    available_key = key
                    break

            if not is_available:
                logger.error('At least one of key from set=%s has to be present in the file data=%s',
                             (self.KEY_LIST_KEY, self.TITLE_LIST_KEY), data)
                return False
            else:
                # Check for value
                logger.debug('Validating key=%s value', available_key)
                if not self._is_valid_list_or_regex(data.get(available_key)):
                    logger.error("Data entry=%s of stanza=%s has invalid regex/string", data.get(available_key), data)
                    return False

            # Check for replacement data
            if self.REPLACEMENT_RULES_KEY in data:
                replacement_data_list = data.get(self.REPLACEMENT_RULES_KEY)
                if not self._validate_replacement_rules(replacement_data_list):
                    return False
        return True

    def _validate_replacement_rules(self, replacement_data_list):
        """
        Validate replacement rules validation
        @type replacement_data_list: list
        @param replacement_data_list: list of replacement rules

        @rtype: bool
        @return: True/False
        """
        for replacement_data in replacement_data_list:
            keys = replacement_data.keys()
            if len(list(set(keys).difference(self.REPLACEMENT_SCHEMA_KEYS))) != 0:
                logger.error("Invalid keys in replacement stanza=%s, valid keys are=%s",
                             replacement_data, self.REPLACEMENT_SCHEMA_KEYS)
                return False
            # Check two key are must present
            if len(set(self.REPLACEMENT_SCHEMA_REQUIRED_KEYS).difference(keys)) != 0:
                logger.error("Required keys=%s are not present in replacement stanza=%s",
                             self.REPLACEMENT_SCHEMA_REQUIRED_KEYS, replacement_data)
                return False

            key = self.REPLACEMENT_SCHEMA_TYPE
            if replacement_data.get(key) not in self.REPLACEMENT_SCHEMA_TYPE_LIST:
                logger.error("%s does not have valid value=%s of key=%s. Valid values are %s", replacement_data,
                             replacement_data.get(key), key, self.REPLACEMENT_SCHEMA_TYPE_LIST)
                return False
            if replacement_data.get(key) == self.REPLACEMENT_SCHEMA_TYPE_REPLACE:
                if self.REPLACEMENT_SCHEMA_PATTERN_KEY not in replacement_data:
                    logger.error("%s key does not exist in replacement data=%s. %s must be required for %s operation.",
                                 self.REPLACEMENT_SCHEMA_PATTERN_KEY, replacement_data,
                                 self.REPLACEMENT_SCHEMA_PATTERN_KEY, replacement_data.get(key))
                    return False
                elif not self._is_valid_regex(replacement_data.get(key)):
                    logger.error("%s key does not have valid regex of replacement data=%s. %s must have valid regex.",
                                 replacement_data.get(key), replacement_data,
                                 self.REPLACEMENT_SCHEMA_PATTERN_KEY)
                    return False
        return True

    def _is_valid_list_or_regex(self, value):
        """
        Check if given value either str/regex or list

        @type: basestring or list
        @param value: list or string

        @rtype: bool
        @return: return True or False
        """
        if isinstance(value, basestring):
            value = [value]
        if isinstance(value, list):
            return self._is_valid_regex_list(value)
        logger.error('%s is neither string nor list', value)
        return False

    def _is_valid_regex_list(self, data_list):
        """
        Check if list attribute is valid regex
        @type data_list: list
        @param data_list: list of data to be verify

        @rtype: bool
        @return: False even on value in the list is not valid regex otherwise True
        """
        # for regex in the list as well
        is_valid = True
        for val in data_list:
            if not self._is_valid_regex(val):
                is_valid = False
        return is_valid

    def _is_valid_regex(self, value):
        """
        Check if given value either regex or not

        @type: basestring
        @param value: string

        @rtype: bool
        @return: return True or False
        """
        try:
            re.compile(value)
            return True
        except re.error as exc:
            logger.exception('% is not a valid regex, error=%s', value, exc)
            logger.exception(exc)
            return False
        logger.error('%s is not neither regex', value)
        return False

    def parse_rules(self):
        """
        Parse rule specs and normalized it

        @rtype: list
        @return: List of combined rules for each object type
        """
        object_list = {}
        for rule_spec in self.rule_specs:
            if rule_spec.get('object_type') not in object_list:

                object_list[rule_spec.get('object_type')] = [rule_spec]
            else:
                object_list[rule_spec.get('object_type')].append(rule_spec)
        return object_list

    @staticmethod
    def _convert_to_list(data):
        """
        Check if data is list otherwise return back to list after str type cast

        @type data: basestring, number or list
        @param data: data to convert to list

        @rtype: list
        @return: list
        """
        if isinstance(data, list):
            return data
        else:
            return [str(data)]

    def apply_rules(self, data_list):
        """
        Pass list of data to apply rules defined in the rule spec file and return data which is filtered or replaced
        based upon defined rules

        @type data_list: list
        @param data_list: list of data to update it

        @rtype: list
        @return: list of filter data
        """
        filter_data = []
        for data in data_list:
            if data.get('object_type') in self.objects_rules:
                logger.debug('Found rule for given object type=%s', data.get('object_type'))
                updated_data = self._check_and_apply_rule(data)
                if updated_data:
                    filter_data.append(updated_data)
        return filter_data

    def _check_and_apply_rule(self, data):
        """
        Check if rule match and apply replacement rules

        @type data: dict
        @param data: data

        @rtype: dict
        @return: Updated or same dict
        """
        # Check for title or key
        is_matched = False
        object_type = data.get('object_type')
        object_rules = self.objects_rules.get(object_type)
        # Check title
        for object_rule in object_rules:
            # Check for title
            for tregx in self._convert_to_list(object_rule.get(self.TITLE_LIST_KEY)):
                if re.search(tregx, data.get('title', ''), flags=re.IGNORECASE):
                    is_matched = True
            # Check for _key
            for kregx in self._convert_to_list(object_rule.get(self.KEY_LIST_KEY)):
                if re.search(kregx, data.get('_key', ''), flags=re.IGNORECASE):
                    is_matched = True
            logger.debug("Is matched=%s rule=%s for title=%s, _key=%s", is_matched, object_rule, data.get('title'),
                         data.get('_key'))
            if is_matched and self.REPLACEMENT_RULES_KEY in object_rule:
                logger.info("Rules matched for %s, applying replacement rules now", data.get('title'))
                # Apply replace first then prefix or post fix
                get_order = lambda item: 0 if item.get(self.REPLACEMENT_SCHEMA_TYPE) == \
                                              self.REPLACEMENT_SCHEMA_TYPE_REPLACE else 1
                # Replacement
                for rule in sorted(object_rule.get(self.REPLACEMENT_RULES_KEY), key=get_order):
                    data = self._replace_rule(data, rule)
        return data if is_matched else None

    def _replace_rule(self, data, replacement_rule):
        """
        Apply replacement rule

        @type data: dict
        @param data: data to update

        @type replacement_rule: dict
        @param replacement_rule: replacement rule

        @rtype: dict
        @return: updated dict
        """
        replacement_key = replacement_rule.get(self.REPLACEMENT_SCHEMA_KEY)
        logger.debug("Applying replacement rule %s for %s", replacement_rule, data.get('title'))
        if replacement_rule.get(self.REPLACEMENT_SCHEMA_TYPE) == self.REPLACEMENT_SCHEMA_TYPE_PREFIX:
            if replacement_key in data:
                data[replacement_key] = replacement_rule.get(self.REPLACEMENT_SCHEMA_REPLACEMENT_KEY) +\
                                        data.get(replacement_key)
        elif replacement_rule.get(self.REPLACEMENT_SCHEMA_TYPE) == self.REPLACEMENT_SCHEMA_TYPE_POSTFIX:
            if replacement_key in data:
                data[replacement_key] = data.get(replacement_key) +\
                                        replacement_rule.get(self.REPLACEMENT_SCHEMA_REPLACEMENT_KEY)
        elif replacement_rule.get(self.REPLACEMENT_SCHEMA_TYPE) == self.REPLACEMENT_SCHEMA_TYPE_REPLACE:
            if replacement_key in data:
                pattern = replacement_rule.get(self.REPLACEMENT_SCHEMA_PATTERN_KEY)
                if pattern:
                    replace_string = replacement_rule.get(self.REPLACEMENT_SCHEMA_REPLACEMENT_KEY)
                    data[replacement_key] = re.sub(pattern, replace_string, data.get(replacement_key, ''),
                                                   flags=re.IGNORECASE)
        else:
            logger.warning("Invaid replacement type found=%s, valid keys are=%s", replacement_key,
                        self.REPLACEMENT_SCHEMA_TYPE_LIST)
        return data


class MigrateSchema(object):
    """
        Class is used to migrate old schema using handler which are defined for migration
    """
    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize session key

        @type session_key: basestring
        @param session_key: session key

        @param owner: basestring
        @param owner: owner

        @param app: basestring
        @param app: app name

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

    def _is_2_0_x_version(self, schema_version):
        """
        Check if verion is between 2.0.0 to 2.1.0
        @type schema_version: basestring
        @param schema_version: schema version

        @rtype: bool
        @return: true or false
        """
        return VersionCheck.compare(schema_version, '2.1.0') < 0 and VersionCheck.compare(schema_version, '2.0.0') >= 0

    def _is_2_1_x_version(self, schema_version):
        """
        Check if verion is between 2.1.0 to 2.2.0
        @type schema_version: basestring
        @param schema_version: schema version

        @rtype: bool
        @return: true or false
        """
        return VersionCheck.compare(schema_version, '2.2.0') < 0 and VersionCheck.compare(schema_version, '2.1.0') >= 0

    def _is_2_2_x_version(self, schema_version):
        """
        Check if verion is between 2.2.0 or above
        @type schema_version: basestring
        @param schema_version: schema version

        @rtype: bool
        @return: true or false
        """
        return VersionCheck.compare(schema_version, '2.3.0') < 0 and VersionCheck.compare(schema_version, '2.2.0') >= 0

    def _is_2_3_x_version(self, schema_version):
        """
        Check if verion is between 2.3.0 or above
        @type schema_version: basestring
        @param schema_version: schema version
        @rtype: bool
        @return: true or false
        """
        return VersionCheck.compare(schema_version, '2.4.0') < 0 and VersionCheck.compare(schema_version, '2.3.0') >= 0

    def migrate_schema(self, schema_version, object_type, data_list):
        """
        Migrate 2.0, 2.1, 2.2 or 2.3 version
        @type schema_version: basestring
        @param schema_version: schema to update

        @type object_type: basestring
        @param object_type: object type

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        if self._is_2_0_x_version(schema_version):
            data_list = self.migrate_2_0_x_schema(object_type, data_list)
            # update schema to 2.1.0
            schema_version = '2.1.0'
        if self._is_2_1_x_version(schema_version):
            data_list = self.migrate_2_1_x_schema(object_type, data_list)
            # update schema to 2.2.0
            schema_version = '2.2.0'
        if self._is_2_2_x_version(schema_version):
            data_list = self.migrate_2_2_x_schema(object_type, data_list)
            # update schema to 2.3.0
            schema_version = '2.3.0'
        if self._is_2_3_x_version(schema_version):
            data_list = self.migrate_2_3_x_schema(object_type, data_list)
            # update schema to 2.4.0
            schema_version = '2.4.0'

        data_list = self.migrate_itsi_migration(object_type, schema_version, data_list)
        return data_list

    def migrate_itsi_migration(self, object_type, schema_version, data_list):
        """
        If the migration is done via restoring, need to update the itsi_migration record
        with the new version information, so that the migration won't kick off the next
        time when user restart Splunk/ITSI
        @type object_type: basestring
        @param object_type: object type

        @type schema_version: basestring
        @param schema_version: version of the backup json file

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        if object_type == "migration":
            try:
                new_version = ITOAInterfaceUtils.get_app_version(self.session_key, 'SA-ITOA', 'nobody')
                data_list[0]["itsi_latest_version"] = new_version
                data_list[0]["itsi_old_version"] = schema_version
            except Exception as exc:
                logger.exception(exc)
        return data_list

    def migrate_2_0_x_schema(self, object_type, data_list):
        """
        @type object_type: basestring
        @param object_type: object type

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        if object_type != 'home_view':
            return data_list

        home_view_object = itsi_migration.UpdateServiceAnalyzer(self.session_key, self.owner, self.app)
        return home_view_object.update_home_view_objects(data_list)

    def migrate_2_1_x_schema(self, object_type, data_list):
        """
        Update schema from 2_1_x to 2.2.0 (current)

        @type object_type: basestring
        @param object_type: object type

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        # Migrate all the ACL stuff first
        self.create_acl_object()

        # Title update may apply for all
        if object_type in ['service', 'entity', 'kpi_threshold_template', 'kpi', 'kpi_template']:
            title_validation_mi_object = itsi_migration.TitleValidationHandler(self.session_key, self.owner, self.app)
            title_validation_mi_object.update_title(object_type, data_list)

        if object_type == 'correlation_search':
            cs_mi_object = itsi_migration.CorrelationSearchMigration(self.session_key, self.owner, self.app)
            return cs_mi_object.upgrade_correlation_searches_schema(data_list)
        elif object_type == 'service':
            service_mi_object = itsi_migration.ServiceMigrationChangeHandler(self.session_key, self.owner, self.app)
            for service in data_list:
                service_mi_object.update_service_kpis(service)
                service_mi_object.clear_kpi_thresholds_template_id(service)
            return data_list
        elif object_type == 'kpi_template':
            kpi_template_mi_object = itsi_migration.KPITemplateMigrationChangeHandler(self.session_key,
                                                                                      self.owner,
                                                                                      self.app)
            updated = []
            for template in data_list:
                if kpi_template_mi_object.update_template_search_type(template):
                    updated.append(template)
            return updated
        elif object_type == 'kpi_threshold_template':
            kpi_threshold_template_mi_object = itsi_migration.KPIThresholdTemplateMigrationChangeHandler(self.session_key, self.owner, self.app)
            updated = []
            for template in data_list:
                if kpi_threshold_template_mi_object.kpi_threshold_template_schema_update(template):
                    updated.append(template)
            return updated
        elif object_type == 'entity':
            for entity in data_list:
                # Clear out services field for all entities
                # On save, service membership change handler will update to membership with new schema for all entities
                entity['services'] = []
            return data_list
        else:
            # For all other cases
            return data_list

    def migrate_2_2_x_schema(self, object_type, data_list):
        """
        Update schema from 2_2_x to 2.3.0 (future)
        @type object_type: basestring
        @param object_type: object type

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        updated = []
        if object_type == 'correlation_search':
            delete_ad_search_object = itsi_migration.DeleteOldAdSearch(self.session_key, self.owner, self.app)
            delete_ad_search_object.delete_old_ad_search()
            for search in data_list:
                if search.get('name') != 'ITSI anomaly detection correlation search':
                    updated.append(search)
            return updated
        elif object_type == 'service':
            service_mi_object = itsi_migration.ServiceMigrationChangeHandler_from_2_2_0(
                self.session_key, self.owner, self.app)
            service_mi_object.obtain_services_perform_migration(data_list)

            base_search_mi_object = MigrateModuleKPIsToSharedBaseSearch(
                self.session_key, logger, False, self.owner, self.app)
            kpis_from_templates = base_search_mi_object.get_kpi_templates_kpis_by_id()
            base_searches_by_kpi = base_search_mi_object.get_base_searches_for_kpis_by_id(kpis_from_templates)

            role_migration_object = AddItsiRoleEntityRuleToServices(self.session_key, logger, False, self.owner, self.app)

            datamodel_settings_object = UpdateChangedDatamodelKPIs_2_2_0_to_2_3_0(self.session_key, logger, False, self.owner, self.app)
            migration_mapping = datamodel_settings_object.get_datamodel_migration_mapping()
            datamodel_settings_object.validate_migration_mapping(migration_mapping)

            for data_item in data_list:
                datamodel_migration_status = datamodel_settings_object.update_datamodel_settings(data_item,
                                                                                                 migration_mapping)
                base_search_migration_status = base_search_mi_object.update_kpis_for_service(data_item,
                                                                                             kpis_from_templates,
                                                                                             base_searches_by_kpi)
                role_migration_status = role_migration_object.add_service_entity_rules(data_item)
                logger.debug("Module datamodel migration status: %s", json.dumps(datamodel_migration_status))
                logger.debug("Module base search migration status: %s", json.dumps(base_search_migration_status))
                logger.debug("Module role migration status: %s", role_migration_status)
            return data_list
        elif object_type == 'glass_table':
            try:
                gt_migration_object = itsi_migration.MigrateToCommonGlassTable(self.session_key, self.owner, self.app)
                for gt in data_list:
                    gt_migration_object.convert_single_gt(gt)
            except Exception as exc:
                logger.exception(exc)
                return updated
            return data_list
        elif object_type == 'deep_dive':
            deep_dive_migrator = itsi_migration.DeepDiveMigrator(self.session_key, logger)
            for dd in data_list:
                deep_dive_migrator._update_exclude_fields(dd)
            return data_list
        else:
            return data_list

    def migrate_2_3_x_schema(self, object_type, data_list):
        """
        Update schema from 2_3_x to 2.4.0 (future)
        @type object_type: basestring
        @param object_type: object type

        @type data_list: list
        @param data_list: data to update

        @rtype: list
        @return: return updated list
        """
        if object_type == 'deep_dive':
            deep_dive_migrator = itsi_migration.DeepDiveMigrator(self.session_key, logger)
            for dd in data_list:
                deep_dive_migrator._update_threshold_settings(dd)
                deep_dive_migrator._update_entity_overlay_settings(dd)
            return data_list
        else:
            return data_list

    # We need to create ACL stanza for new imported objects
    def create_acl_object(self):
        """
        Create ACL object for new imported objects
        @return:
        """
        acl_handler = itsi_migration.ACLHandler(self.session_key, self.owner, self.app)
        acl_handler.add_acl()
