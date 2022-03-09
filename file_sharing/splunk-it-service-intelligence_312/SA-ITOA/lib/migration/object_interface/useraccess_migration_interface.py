# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import glob
import json
import sys
from splunk.appserver.mrsparkle.lib import i18n
from splunk.rest import simpleRequest
from splunk.clilib.bundle_paths import make_splunkhome_path
from ITOA import itoa_common as utils
from .base_migration_interface import BaseMigrationInterface

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccessStore, UserAccess

class UserAccessMigrationInterface(BaseMigrationInterface):
    """
        Interface to access UserAccess Objects
    """

    def _iterator_from_kvstore(self, object_type):
        """
            Helper method to obtain content from kvstore.
            This method is specific to ITOA objects.
            @type object_type: basestring
            @param object_type: type of the object
            @type limit: int
            @param limit: batch limit to pull from kvstore
        """
        results = []
        location = '/servicesNS/nobody/SA-UserAccess/storage/collections/data/{0}'.format(object_type)
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
            if object_type == 'app_acl':
                for single_record in data:
                    object_id = single_record.get('obj_id')
                    object_app = single_record.get('obj_app')
                    object_storename = single_record.get('obj_storename')
                    obj_type = single_record.get('obj_type')
                    object_acl = single_record.get('obj_acl')
                    if object_acl:
                        object_owner = object_acl.get('obj_owner')
                        if 'obj_owner' in object_acl:
                            object_acl.pop('obj_owner')
                        success, content = UserAccess.update_perms(object_id, 
                            object_acl, object_app, obj_type, object_storename,
                            self.session_key, self.logger, object_owner, merge=True)
                    else:
                        success = False
                        content = "object_acl does not exist in the acl blob."
                    
                    if not success:
                        # If any of the single record update is failed, bail out the restoring
                        raise Exception(content)

            elif object_type == 'app_capabilities':
                store = UserAccessStore.getInstance(app_name='SA-UserAccess', ns='nobody')
                if data:
                    store.bulk_update(object_type, data, self.session_key, self.logger)

    def migration_delete_kvstore(self, object_type):
        """
            Actual method to delete content from the kvstore for the object.
            This method applies to all ITOA objects
            @type object_type: basestring
            @param object_type: ITSI object types
            @return: boolean
        """
        location = '/servicesNS/nobody/SA-UserAccess/storage/collections/data/{0}'.format(object_type)
        self.logger.info('deleting existing object_type content: %s URI: %s', object_type, location)
        filter_data = {}
        response, content = simpleRequest(
            location,
            method="DELETE",
            sessionKey=self.session_key,
            getargs=filter_data,
            raiseAllErrors=False
        )
        return
