# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import glob
from ITOA.itoa_factory import instantiate_object
from ITOA import itoa_common as utils
from ITOA.storage import itoa_storage
from .base_migration_interface import BaseMigrationInterface

class ITOAMigrationInterface(BaseMigrationInterface):
    """
        Migration class to handle ITOA objects
    """
    def _iterator_from_kvstore(self, object_type, limit, get_raw=False):
        """
            Helper method to obtain content from kvstore.
            This method is specific to ITOA objects.
            @type object_type: basestring
            @param object_type: type of the object
            @type limit: int
            @param limit: batch limit to pull from kvstore
            @type get_raw: boolean
            @param get_raw: get raw contents instead of processed contents
        """
        try:
            skip = 0
            mi_obj = None
            if get_raw:
                mi_obj = itoa_storage.ITOAStorage()
                mi_obj.wait_for_storage_init(self.session_key)
            else:
                mi_obj = instantiate_object(self.session_key,
                                            "nobody",
                                            object_type,
                                            logger=self.logger)

            while True:
                results = None
                if get_raw:
                    results = mi_obj.get_all(self.session_key, 'nobody', object_type, sort_key='_key', sort_dir=1,
                                             skip=skip, limit=limit)
                else:
                    results = mi_obj.get_bulk("nobody",
                                              sort_key="_key",
                                              sort_dir=1,
                                              skip=skip,
                                              limit=limit,
                                              req_source="MigrationBaseMethod")
                self.logger.info("get_bulk from kvstore, size of the results: %s" % len(results))
                if not results or len(results) == 0:
                    break
                skip += limit
                for result in results:
                    yield result
        except Exception:
            self.logger.error("Failed to save object content for object type: %s! Exception to follow")
            raise

    def migration_get(self, object_type, limit=100, **kwargs):
        """
            Method to retrieve object content either from local storage or kvstore
            If this is the first version migration, there is no content from the local
            storage, an attempt will be made to retrieve content from kvstore.
            Any subsequent GET will be from the local storage.
            @type object_type: basestring
            @param object_type: object_type
            @type limit: int
            @param limit: get bulk batch size, default to 100
            @type kwargs: dict
            @param kwargs:
                get_raw: get raw contents  from kv store instead of processed contents
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
            data = self._iterator_from_kvstore(object_type, limit, get_raw=kwargs.get('get_raw', False))

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
        target_file_list = self._get_object_file_list(object_type)
        for target_file in target_file_list:
            data = utils.FileManager.read_data(target_file)
            if len(data) > 0:
                mi_obj = instantiate_object(self.session_key,
                                            "nobody",
                                            object_type,
                                            logger=self.logger)
                if validation:
                    # for base_service_template, need to skip the st update
                    if object_type in ['base_service_template']:
                        mi_obj.skip_service_template_update = True

                    utils.save_batch(mi_obj,
                                     "nobody",
                                     data,
                                     no_batch=False,
                                     dupname_tag=dupname_tag)
                else:
                    mi_obj.batch_save_backend("nobody", data)
                self.logger.info("%s %s saved to kvstore successfully", len(data), object_type)
            else:
                self.logger.info("no objects of type %s to be saved", object_type)

    def migration_delete_kvstore(self, object_type):
        """
            Actual method to delete content from the kvstore for the object.
            This method applies to all ITOA objects
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        self.logger.info('deleting existing object_type: %s', object_type)
        mi_obj = instantiate_object(self.session_key,
                                    "nobody",
                                    object_type,
                                    logger=self.logger)
        mi_obj.delete_bulk("nobody")
