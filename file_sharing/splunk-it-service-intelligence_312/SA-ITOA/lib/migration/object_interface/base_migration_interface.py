# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import os
import glob
from abc import ABCMeta, abstractmethod
from ITOA import itoa_common as utils

CHUNK_SIZE = 250


class BaseMigrationInterface(object):
    """
        Base class for all migration object interfaces
    """
    __metaclass__ = ABCMeta

    def __init__(self, session_key, path, logger):
        """
            Base object interface class for migration purpose.
            This class defines all the base methods to interact with different objects.
            The detail implemenation of each method is done in the child class.
            @type session_key: basestring
            @param session_key: Splunk session key
            @type path: basestring
            @param path: the migration local storage location
            @type logger: log object
            @param logger: logger object

        """
        self.session_key = session_key
        self.logger = logger
        self.migration_helper_directory = path

    @abstractmethod
    def migration_get(self, object_type, limit=100):
        """
            Migration Base Class method to get records.
            Get records from either location storage or kvstore.
            Detail implementation is defined in each of the object class.
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        pass

    @abstractmethod
    def migration_save_single_object_to_kvstore(self, object_type, validation=True, dupname_tag=None):
        """
            A base method to save content to the kvstore for a single object.
            The coming data are coming from the local storage.
            @type object_type: basestring
            @param object_type: ITSI object types
            @type validation: boolean
            @param validation: require validation when saving to kvstore
            @type dupname_tag: basestring
            @param dupname_tag: a special tag to the duplicated titles.
            @return: boolean
        """
        pass

    def _clean_file(self, object_type):
        """
            A utility method to clean all the file from the local storage that
            are related to a particular object.
            @type object_type: basestring
            @param object_type: ITSI object types
        """
        target_file_list = []
        if utils.FileManager.is_exists(self.migration_helper_directory):
            target_file_list = self._get_object_file_list(object_type)
        for target_file in target_file_list:
            utils.FileManager.delete_file(target_file)

    def _iterator_from_filesystem(self, target_file_list):
        """
            A base method to obtain records from local storage.
            @type target_file_list: list
            @param target_file_list: list of files in the local storage for this object

        """
        if not target_file_list:
            raise Exception
        for target_file in target_file_list:
            if target_file and utils.FileManager.is_file(target_file):
                object_list = utils.FileManager.read_data(target_file)
                for single_object in object_list:
                    yield single_object

    def _get_object_file_list(self, object_type):
        object_type_modifier = "*" + object_type + "___*"
        target_file = os.path.join(os.path.sep, self.migration_helper_directory, object_type_modifier)
        target_file_list = glob.glob(target_file)
        self.logger.info("obtain the local storage target file list: %s" % target_file_list)
        return target_file_list

    def migration_delete_kvstore(self, object_type):
        """
            A base method to delete content from the kvstore for the object
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        pass

    def migration_save(self, object_type, data_list):
        """
            Migration Base Class method to save records.
            Always save to the local storage, not into the KVStore!!!
            @type object_type: basestring
            @param object_type: ITSI object types
            @type data_list: list
            @param data_list: list of json objects to be saved
            @return: boolean
        """
        status = True
        file_rolling_number = 0
        done = False
        self.logger.info("performing migration_save on object: %s" % object_type)
        try:
            if not utils.is_valid_list(data_list):
                raise TypeError(_('Invalid input data, expect list but receiving %s') % type(data_list))
            object_type_modifier = object_type + ".json"
            base_filename = os.path.join(os.path.sep, self.migration_helper_directory, object_type_modifier)
            data_list_size = len(data_list)

            #remove the previous copy
            self._clean_file(object_type)

            remaining = data_list_size
            starting = 0

            while not done:
                rolling_file_name = utils.FileManager.get_rolling_file_name(base_filename, file_rolling_number)

                if CHUNK_SIZE >= remaining:
                    utils.FileManager.write_to_file(rolling_file_name, data_list[starting:])
                    done = True
                else:
                    utils.FileManager.write_to_file(rolling_file_name, data_list[starting:CHUNK_SIZE+starting])
                    starting += CHUNK_SIZE
                    remaining -= CHUNK_SIZE

                file_rolling_number += 1
        except Exception, e:
            self.logger.exception("Something wrong when writing migration content to local storage")
            status = False

        return status
