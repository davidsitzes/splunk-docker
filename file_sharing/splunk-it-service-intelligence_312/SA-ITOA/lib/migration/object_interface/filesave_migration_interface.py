# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import glob
import json
from splunk.appserver.mrsparkle.lib import i18n
from ITOA import itoa_common as utils
from SA_ITOA_app_common.apifilesave.filesave import ApifilesaveService

from .base_migration_interface import BaseMigrationInterface

class FilesaveMigrationInterface(BaseMigrationInterface):
    """
        Interface to access Notable Event Objects
    """

    def _iterator_from_kvstore(self, object_type):
        """
            Helper method to obtain content from kvstore.
            This method is specific to glass_table_images objects.
            @type mi_obj: object type
            @param mi_obj: actual object based on the object_type
            @type limit: int
            @param limit: batch limit to pull from kvstore
        """
        results = []
        api_filesave_service = ApifilesaveService(app_name='SA-ITOA',
                                                  session_id=self.session_key,
                                                  user_name='nobody',
                                                  collection_name='SA-ITOA_files')
        data = api_filesave_service.get_all()
        try:
            results = json.loads(data)
        except:
            message = _("Failed to convert object content to json format")
            self.logger.error(message)
            raise Exception(message)

        for result in results:
            yield result

    def migration_get(self, object_type, limit=100):
        """
            Method to retrieve object content either from local storage or kvstore
            If this is the first version migration, there is no content from the local
            storage, an attempt will be made to retrieve content from kvstore.
            Any subsequent GET will be from the local storage.
            @type object_type: basestring
            @param object_type: object_type
            @type limit: int
            @param limit: get bulk batch size, default to 100
            @return: iterator, an iterator contains retrieved json objects
        """
        target_file_list = []
        self.logger.info("migration helper directory: %s, processing object_type: %s" %
                    (self.migration_helper_directory, object_type))

        if utils.FileManager.is_exists(self.migration_helper_directory):
            target_file_list = self._get_object_file_list(object_type)
            self.logger.info("Retrieving content from local storage: %s" % target_file_list)

        if target_file_list:
            self.logger.info("Trying to obtain data from the local file system...")
            data = self._iterator_from_filesystem(target_file_list)
        else:
            self.logger.info("Trying to obtain data from kvstore...")
            data = self._iterator_from_kvstore(object_type)

        return data

    def migration_save_single_object_to_kvstore(self, object_type, validation=True, dupname_tag=None):
        """
            Actual method to save content to the kvstore for a single object.
            The coming data are coming from the local storage.
            @type object_type: basestring
            @param object_type: ITSI object types
            @type validation: boolean
            @param validation: require validation when saving to kvstore
            @type dupname_tag: basestring
            @param dupname_tag: a special tag to the duplicated titles.
            @return: boolean
        """
        self.logger.info("single object save, object: %s" % object_type)
        api_filesave_service = ApifilesaveService(app_name='SA-ITOA',
                                                  session_id=self.session_key,
                                                  user_name='nobody',
                                                  collection_name='SA-ITOA_files')

        target_file_list = self._get_object_file_list(object_type)
        for target_file in target_file_list:
            self.logger.info("retrieving info from: %s" % target_file)
            data = utils.FileManager.read_data(target_file)
            for image in data:
                try:
                    api_filesave_service.create(image)
                except Exception:
                    self.logger.info("Image with key %s already found in collection" % image['_key'])
                    continue
            self.logger.info("Successfully added %s glass table images" % str(len(data)))

    def migration_delete_kvstore(self, object_type):
        """
            Actual method to delete content from the kvstore for the object.
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        self.logger.info("deleting existing object_type content: %s", object_type)
        api_filesave_service = ApifilesaveService(app_name='SA-ITOA',
                                                  session_id=self.session_key,
                                                  user_name='nobody',
                                                  collection_name='SA-ITOA_files')
        api_filesave_service.delete_all()
