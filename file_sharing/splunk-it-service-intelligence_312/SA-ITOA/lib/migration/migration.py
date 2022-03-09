# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import glob
import os
from collections import deque
from abc import ABCMeta, abstractmethod

from ITOA.setup_logging import setup_logging
from ITOA.version_check import VersionCheck
from ITOA.itoa_common import FileManager
from object_interface.migration_config import get_registered_migration_handler
from . import utils
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n


logger = setup_logging("itsi_migration.log", "itsi.migration")

CHUNK_SIZE = 250

class MigrationFunctionAbstract(object):
    '''
        Base class for app migration handling
    '''
    __metaclass__ = ABCMeta

    def __init__(self, session_key):
        self.mi_method = MigrationBaseMethod(session_key)

    def rollback(self):
        '''
        Rollback function, which is called if execute operation fails
        This function must return status of operation
            True - if operation is successful
            False - if operation is failed
        :return boolean: status if operation is a success or failure
        '''
        return True

    def prepare(self):
        '''
        Prepare function which is called before execute operation, if it fails then execute function won't get call
        This function must return status of operation
            True - if operation is successful
            False - if operation is failed
        :return boolean: status if operation is successful or fail
        '''
        return True

    @abstractmethod
    def execute(self):
        '''
        This function must return status of operation
            True - if operation is successful
            False - if operation is failed
        :return boolean: status if operation is successful or fail
        '''
        pass

    def get_object_iterator(self, object_type, limit=CHUNK_SIZE, **kwargs):
        """
            Migration Base Class method to get records.
            @type session_key: basestring
            @param session_key: splunk session key
            @type object_type: basestring
            @param object_type: ITSI object types
            @type limit: int
            @param limit: get bulk batch size, default to 100
            @return: iterator, matched records from kvstore
        """
        return self.mi_method.migration_get(object_type, limit, **kwargs)

    def save_object(self, object_type, data_list):
        """
            Migration Base Class method to save records.
            @type session_key: basestring
            @param session_key: splunk session key
            @type object_type: basestring
            @param object_type: ITSI object types
            @type data_list: list
            @param data_list: list of json objects to be saved
            @return: boolean
        """
        return self.mi_method.migration_save(object_type, data_list)


class MigrationBaseMethod(object):
    """
        Base class which contains general migration methods
    """

    def __init__(self, session_key, dupname_tag=None):
        self.session_key = session_key
        self.dupname_tag = dupname_tag
        self.handler_manifest = get_registered_migration_handler()
        self.migration_helper_directory = make_splunkhome_path(['var', 'itsi', 'migration_helper'])
        if not FileManager.is_exists(self.migration_helper_directory):
            FileManager.create_directory(self.migration_helper_directory)

    def _get_handler_for_object_type(self, object_type):
        """
            A method to obtain the class handler based on the object type.
            All object classes are defined in the migration_manifest file.
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: the appropriate class handler.
        """
        handler = None
        manifest_handler = self.handler_manifest.get(object_type, None)
        if manifest_handler:
            handler = manifest_handler.get("base", None)
        if not handler:
            message = _("No valid handler found for object_type: {0}, grab a noop handler.").format(object_type)
            logger.debug(message)
            handler = self.handler_manifest.get("noop").get("base")
        return handler(self.session_key, self.migration_helper_directory, logger)

    def migration_get(self, object_type, limit=100, **kwargs):
        """
            A wrap method to get an iterator based on the object type
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: an object iterator.
        """
        handler = self._get_handler_for_object_type(object_type)
        return handler.migration_get(object_type, limit, **kwargs)

    def migration_save(self, object_type, data_list):
        """
            A wrap method to save incoming object data to local storage
            @type object_type: basestring
            @param object_type: ITSI object types
            @type data_list: list
            @param data_list: Actual data objects
            @return: boolean
        """
        handler = self._get_handler_for_object_type(object_type)
        return handler.migration_save(object_type, data_list)

    def migration_delete_kvstore(self, object_type):
        """
            A wrap method to delete content from the kvstore for the object
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        handler = self._get_handler_for_object_type(object_type)
        return handler.migration_delete_kvstore(object_type)

    def migration_save_single_object_to_kvstore(self, object_type, validation=True, dupname_tag=None):
        """
            A wrap method to save content to the kvstore for a single object.
            The coming data are coming from the local storage.
            @type object_type: basestring
            @param object_type: ITSI object types
            @type validation: boolean
            @param validation: require validation when saving to kvstore
            @type dupname_tag: basestring
            @param dupname_tag: a special tag to the duplicated titles.
            @return: boolean
        """
        handler = self._get_handler_for_object_type(object_type)
        return handler.migration_save_single_object_to_kvstore(object_type, validation, dupname_tag)

    def migration_bulk_save_to_kvstore(self, validation=True, dupname_tag=None):
        """
            A public method to save content to the kvstore for all objects.
            The coming data are coming from the local storage.
            @type object_type: basestring
            @param object_type: ITSI object types
            @type validation: boolean
            @param validation: require validation when saving to kvstore
            @type dupname_tag: basestring
            @param dupname_tag: a special tag to the duplicated titles.
            @return: boolean
        """
        object_type_list = []
        status = True
        try:
            target_directory = os.path.join(os.path.sep, self.migration_helper_directory, "*")
            for file_name in glob.glob(target_directory):
                mi_object =os.path.split(file_name)[-1].split('___')[0]
                if mi_object not in object_type_list:
                    object_type_list.append(mi_object)
            sorted_object_type_list = sorted(object_type_list, key=lambda x: utils._get_object_order(x))
            logger.info("Restoring order as the following: %s" % str(sorted_object_type_list))

            for object_type in sorted_object_type_list:
                logger.info("Saving content of object_type: %s into kvstore" % object_type)
                handler = self._get_handler_for_object_type(object_type)
                handler.migration_save_single_object_to_kvstore(object_type, validation, dupname_tag)
        except Exception, e:
            logger.exception(e)
            status = False

        self.cleanup_local_storage()
        return status

    def cleanup_local_storage(self):
        """
            A utility function to remove the local storage
        """
        try:
            if FileManager.is_exists(self.migration_helper_directory):
                FileManager.delete_working_directory(self.migration_helper_directory)
        except Exception:
            logger.error("Error in deleting %s !" % self.migration_helper_directory)

class MigrationBase(object):
    '''
        Base class which has some basic required function
    '''
    def __init__(self, from_version, to_version, ignore_build_number=True):
        '''
        Initialize
        :param from_version: from version we need to migration
        :param to_version: to version number perform migration
        :param ignore_build_number: if we need to ignore build number and version suffix after (major, minor, update)
            version
        :return: nothing
        '''
        if not self._validate_version(from_version):
            raise ValueError(_("Invalid version:{0}.").format(from_version))
        if not self._validate_version(to_version):
            raise ValueError(_("Invalid version:{0}.").format(to_version))
        self.to_version = to_version
        self.from_version = from_version
        self.ignore_build_number = ignore_build_number
        # TODO implement functionality ignore_build_number is set to true

    def _validate_version(self, version):
        return VersionCheck.validate_version(version)

    def _is_migration_required(self):
        comp = VersionCheck.compare(self.to_version, self.from_version)
        if comp == 0 or comp == -1:
            return False
        elif comp == 1:
            logger.info("Migration is required")
            return True
        else:
            logger.error("Version compare did not return expected value")
            return False

class Migration(MigrationBase):
    '''
        Migration call to perform any migration operation
    '''
    def __init__(self, from_version, to_version, ignore_build_number=True):
        '''
            Initialize the call
        :param from_version: from version we need to migration
        :param to_version: to version number perform migration
        :param ignore_build_number: if we need to ignore build number and version suffix after (major, minor, update)
            version
        :return: nothing
        '''
        super(Migration, self).__init__(from_version, to_version, ignore_build_number)
        self.is_execution_successful = False
        self.migration_functions = []

    def add(self, migration_function):
        '''
            Add migration function into the list. It throws exception if migration_function is not proper instance
        :param migration_function: migration function
        :return: boolean flag to show if migration is successful
        '''
        if not isinstance(migration_function, MigrationFunctionAbstract):
            logger.error("Migration function:%s is not instance of MigrationFunctionAbstract", migration_function)
            raise ValueError(_("Migration function: {} is not instance of MigrationFunctionAbstract.").format(migration_function))
        self.migration_functions.append(migration_function)

    def run(self):
        if not self._is_migration_required():
            logger.info("Migration is not required from:%s to:%s", self.from_version, self.to_version)

        rollback_queue = deque()
        rollback_required = False
        try:
            for command in self.migration_functions:
                prepare_step = command.prepare()
                # Call other steps only if prepare step is successful
                if prepare_step:
                    rollback_queue.appendleft(command)
                    if not command.execute():
                        logger.error("Failed to execute function:%s", command)
                        rollback_required = True
                        break
                    else:
                        logger.info("Successful executed operation:%s", command)
                else:
                    logger.error("prepare function of %s is failed, so skipping execute function", command)
        except Exception as e:
            logger.exception(e)
            rollback_required = True

        if rollback_required:
            try:
                for command in rollback_queue:
                    if not command.rollback():
                        logger.error("Rollback failed for %s", command)
                    else:
                        logger.info("Rollback successful for %s", command)
            except Exception:
                logger.exception("Rollback failed")
        else:
            self.is_execution_successful = True
