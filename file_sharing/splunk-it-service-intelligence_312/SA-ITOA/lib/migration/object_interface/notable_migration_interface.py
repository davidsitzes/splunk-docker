# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import time
from splunk.appserver.mrsparkle.lib import i18n
from splunk.rest import simpleRequest
from ITOA import itoa_common as utils
from .base_migration_interface import BaseMigrationInterface

class NotableMigrationInterface(BaseMigrationInterface):
    """
        Interface to access Notable Event Objects
    """

    def _iterator_from_kvstore(self, object_type):
        """
            Helper method to obtain content from kvstore.
            @type object_type: basestring
            @param object_type: type of the object
            @type limit: int
            @param limit: batch limit to pull from kvstore
        """
        results = []
        location = self._get_notable_collection_data_uri(object_type)
        rsp, content = simpleRequest(location, sessionKey=self.session_key)
        if rsp.status != 200:
            self.logger.error("Failed to get object content, response=%s, content=%s", rsp, content)
            raise Exception(_("Failed to get object content"))
        try:
            results = json.loads(content)
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

    def  _get_notable_collection_data_uri(self, object_type):
        """Get the uri to the collection data when object type is Notable Type
        @type object_type: basestring
        @param object_type: object type

        @rtype: basestring/NoneType
        @return: uri if object type is Notable Type; None if unsupported object
        type.
        """
        if object_type == "notable_event_comment":
            collection = "itsi_notable_event_comment"
        elif object_type == "notable_event_tag":
            collection = "itsi_notable_event_tag"
        elif object_type == "external_ticket":
            collection = "itsi_notable_event_ticketing"
        elif object_type == "notable_event_group":
            collection = "itsi_notable_event_group"
        elif object_type == "notable_aggregation_policy":
            collection = "itsi_notable_event_aggregation_policy"
        elif object_type == "notable_event_state":
            collection = "itsi_notable_event_state"
        elif object_type == "notable_event_seed_group":
            collection = "itsi_correlation_engine_group_template"
        else:
            raise Exception(_("Failed to get notable event collection from object type: %s.") % object_type)
        uri = "/servicesNS/nobody/SA-ITOA/storage/collections/data/%s" % collection
        return uri

    def migration_update_mod_time(self, object_type, data_list):
        """
        Utility method to update the mod_time during restore.
        For aggregation policy, need to keep the mod time up-to-date 
        after the restore.
        @type object_type: basestring
        @param object_type: ITSI object types
        @type data_list: list of dict.
        @param data_list: list of json dict. from the backup cache
        @return: None 
        """
        if object_type != 'notable_aggregation_policy':
            return

        # in-memory update the mod_time to the current time
        for data in data_list:
            if isinstance(data, dict):
                data['mod_time'] = time.time()

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
            self.logger.info("retrieving info from: %s" % target_file)
            data = utils.FileManager.read_data(target_file)
            if not data:
                continue
            location = self._get_notable_collection_data_uri(object_type)
            if not location.endswith('/'):
                location += '/'
            location += 'batch_save'
            self.migration_update_mod_time(object_type, data)
            response, content = simpleRequest(
                location,
                method='POST',
                jsonargs=json.dumps(data),
                sessionKey=self.session_key,
                raiseAllErrors=False
            )
            if response.status not in (200, 201):
                self.logger.error('Failed to bulk update notable type')
            else:
                self.logger.info('Updated notable type....')

    def migration_delete_kvstore(self, object_type):
        """
            Actual method to delete content from the kvstore for the object.
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        location = self._get_notable_collection_data_uri(object_type)
        self.logger.info('deleting existing object_type content: %s URI: %s', object_type, location)
        filter_data = {}
        filter_data['object_type'] = object_type
        response, content = simpleRequest(
            location,
            method="DELETE",
            sessionKey=self.session_key,
            getargs=filter_data,
            raiseAllErrors=False
        )
        return
