# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import glob
import json
from splunk.util import normalizeBoolean
from splunk import ResourceNotFound
from ITOA import itoa_common as utils
from SA_ITOA_app_common.apifilesave.filesave import ApifilesaveService
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch

from .base_migration_interface import BaseMigrationInterface

class CorrelationSearchMigrationInterface(BaseMigrationInterface):
    """
        Interface to access correlation search
    """

    def _iterator_from_kvstore(self, object_type):
        """
            Helper method to obtain content from kvstore.
            This method is specific to glass_table_images objects.
            @type object_type:  basestring
            @param object_type: object type
        """
        results = []
        search_interface = ItsiCorrelationSearch(self.session_key)
        saved_searches = search_interface.get_bulk(None)
        
        try:
            results = json.loads(saved_searches)
        except:
            self.logger.debug("Failed to load saved searches from kvstore, maybe already in json format")
            if isinstance(saved_searches, list):
                results = saved_searches
            pass

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
        search_names = []
        searches_to_create = []
        correlation_search = ItsiCorrelationSearch(self.session_key, is_validate_service_ids=False)
        target_file_list = self._get_object_file_list(object_type)

        for target_file in target_file_list:
            data = utils.FileManager.read_data(target_file)
            for cs in data:
                name = cs.get('name')
                if not normalizeBoolean(cs.get("eai:acl", {}).get("removable", True)):
                    # Searches that we cannot or should not delete for whatever reason
                    self.logger.info('Skipping restore of unremovable search="%s"', name)
                    continue
                if name in search_names:
                    new_name = name + ' - Copy'
                    self.logger.warning('Duplicate entry found for correlation search=%s, hence append - Copy in the name,'
                                   ' new name=%s', name, new_name)
                    cs['name'] = new_name
                    name = new_name

                search_names.append(name)
                searches_to_create.append(cs)

                try:
                    self.logger.debug('Trying to delete old search=%s if exist on the instance', name)
                    correlation_search.delete(name)
                    self.logger.debug('Successfully deleted existing search=%s', name)
                except ResourceNotFound as e:
                    # This search never existed on this box. no worries.
                    # Do not log this exception as this may confuse users, instead log it into debug
                    # just for debugging purpose.
                    self.logger.debug(e)
                    pass

        created = correlation_search.create_bulk(searches_to_create)
        self.logger.info('Created searches: %s', created)
        return created

    def migration_delete_kvstore(self, object_type):
        """
            Actual method to delete content from the kvstore for the object.
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        self.logger.info('deleting existing object_type: %s', object_type)
        correlation_search = ItsiCorrelationSearch(self.session_key, is_validate_service_ids=False)
        data = self._iterator_from_kvstore(object_type)
        for cs in data:
            try:
                name = cs.get('name')
                correlation_search.delete(name)
            except ResourceNotFound as e:
                # This search never existed on this box. no worries.
                # Do not log this exception as this may confuse users, instead log it into debug
                # just for debugging purpose.
                self.logger.debug(e)
                pass
