# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import statestore
from time import sleep

from splunk.appserver.mrsparkle.lib import i18n
from splunk.auth import getCurrentUser

from ITOA.setup_logging import setup_logging
logger = setup_logging("itsi.log", "itoa.storage")

LOG_CHANGE_TRACKING = "[change_tracking]"

class ITOAStorage(object):
    """
    Defines a storage interface for each of the handlers.
    The different storage options will eventually be registered through a lookup file
    or state store, or some other persistent thingy
    """
    def __init__(self, **kwargs):
        """
        All simple initialization, for adding the storage options, read a file in the storage directory
        Registers the different options, and sets the default backend
        """
        self.backend = None
        self.app = self.get_app_name()
        self.itoa_storage_options = {}
        self.register_storage_option('statestore', statestore.StateStore(**kwargs))
        # Set the default primary option
        self.set_storage_backend('statestore')
        self.should_init = True

    def wait_for_storage_init(self, session_key):
        """
        KV store can take long to get initialized on splunkd restart,
        use this method to wait until it is inited

        @param session_key: Session key to splunkd to use to check KV store init
        @return: True if KV store is inited, else False
        """
        timeout_seconds = 300 # 5 Mins
        retry_seconds = 5
        while not self.is_available(session_key):
            logger.debug('KV store is not initialized, retrying after 5 seconds')
            sleep(retry_seconds)
            timeout_seconds -= retry_seconds
            if timeout_seconds == 0:
                logger.error("KV store does not seem to have been initialized"
                    " for the last 5 minutes. Stopping retry.")
                return False
        logger.info('KV store has been initialized.')
        return True

    def get_app_name(self):
        """
        Gets the name of the app
        We used to be clever, and get it from the filesystem
        ...But clever was wrong
        """
        return "SA-ITOA"

    def register_storage_option(self, option, optioninstance):
        """
        Method for allowing custom storage options to be registered,
        should a customer or external party decide that this is desirable
        @param option: The new or existing option that they want
        @type option: string

        @param optioninstance: The interface to the option they want, duck typing used
        @type option: Anything as long as it supports the interface
        """
        self.itoa_storage_options[option] = optioninstance

    def getStorageOptions(self):
        """
        Returns an array of the different options available for storing data
        @param self: The reference to self
        @type self: itoa_storage instance

        @return: An array of keys for supported backend storage options
        @rtype: list
        """
        return self.itoa_storage_options.keys()

    def get_backend(self, session_key, option=None):
        """
        Gets the backend store and throws an exception if it doesnt exist
        @param option: An optional parameter that specifies which backend interface
        to use.  If blank, uses the current defined backend
        @type option: string

        @return: The backend interface
        @rtype: duck typed.
        """
        if option is None:
            option = self.backend
        elif option != self.backend:
            self.should_init = True
        backend = self.itoa_storage_options.get(option,None)
        if backend is None:
            raise Exception(_("Backend not registered or undefined"))
        if self.should_init == True:
            backend.lazy_init(session_key) #The backend should provide an initialize method
            self.backend = option
            self.should_init = False
        return backend

    def set_storage_backend(self, option):
        """ 
        Sets the option that should be used to store all of this crap
        @param session_key: The splunkd session key
        @type session_key: string

        @param option: The string index of the currently existing option to use
        @type string: string
        """
        self.backend = option

    def is_available(self, session_key):
        """
        Tries to hit a non-existent collection endpoint.
        If the KV store is ready to serve requests, it will return a 500; if it's not up yet, it will
        return a 503.

        Will throw exception if the current backend is not KV store

        @returns true if response is not 503 else false
        @rtype bool
        """
        if self.backend != 'statestore':
            raise Exception(_("`is_available` method can only be run on the KV store backend."))
        backend = self.get_backend(session_key)
        retval = backend.is_available(session_key)
        logger.debug("Querying if KV store is available: %s", retval)
        return retval

    def check_payload_size(self, session_key, data_list, throw_on_violation=True):
        """
        Method to verify payload size isnt larger than limit of size in backend

        @type: basestring
        @param session_key: splunkd session key

        @type: list
        @param data_list: JSON list payload to verify

        @type: boolean
        @param throw_on_violation: True if violation should trigger exception, else returns bool indicating
            if violation detected

        @rtype: boolean
        @return: True if no violation detected, False if violation detected
        """
        return self.get_backend(session_key).check_payload_size(data_list, session_key=session_key, throw_on_violation=throw_on_violation)

###############################################################################
#Generic Crud methods
###############################################################################
    def create(self, session_key, owner, objecttype, data, current_user_name=None):
        """
        A generic creation method, used by all of the other components
        to create a particular entity or service based on the json passed in
        @param session_key: The splunkd session key
        @type session_key: string

        @return a json structure containing an id field and an id
        @retval dict
        """
        backend = self.get_backend(session_key)
        #The backend will create an id for us to use
        #The we cannot assign it here, it must be on the lower levels
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        logger.info("%s user=%s method=create objecttype=%s attempt",
                LOG_CHANGE_TRACKING, user_name, objecttype)
        self.entity_clarification(objecttype,data)
        retval = backend.create(session_key,owner,objecttype,data)
        logger.info("%s user=%s method=create objecttype=%s key=%s",
                LOG_CHANGE_TRACKING, user_name, objecttype, retval.get("_key"))
        return retval

    def edit(self,session_key,owner,objecttype,identifier,data,current_user_name=None):
        """
        A generic edit method, used by all of the other components to
        create a particular service or entity based on the json passed in
        @param session_key: The splunkd session key
        @type session_key: string

        @return a json structure containing an id field and an id
        @retval dict
        """
        backend = self.get_backend(session_key)
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        logger.info("%s user=%s method=edit objecttype=%s key=%s",
                LOG_CHANGE_TRACKING, user_name, objecttype, identifier)
        self.entity_clarification(objecttype,data)
        retval = backend.edit(session_key,owner,objecttype,identifier,data)
        return retval

    def get(self, session_key, owner, objecttype, identifier, current_user_name=None):
        """
        A generic get method to retrieve the item specified by
        its identifier.  This is only used to retrieve by identifier

        @param session_key: The splunkd session key
        @type session_key: string

        @return a json-like dict structure containing the fields of the requested item
        @retval dict
        """
        backend = self.get_backend(session_key)
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        logger.info("%s user=%s method=get objecttype=%s key=%s",
                LOG_CHANGE_TRACKING, user_name, objecttype, identifier)
        return backend.get(session_key, owner, objecttype, identifier)

    def delete(self, session_key, owner, objecttype, identifier, current_user_name=None):
        """
        A generic delete method used to delete
        @param session_key: The splunkd session key
        @type session_key: string
        """
        backend = self.get_backend(session_key)
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        logger.info("%s user=%s method=delete objecttype=%s key=%s",
            LOG_CHANGE_TRACKING, user_name, objecttype, identifier)
        backend.delete(session_key,owner,objecttype,identifier)

    def get_all(self, session_key, owner, objecttype, sort_key=None, sort_dir=None,
            filter_data={}, fields=None, skip=None, limit=None, current_user_name=None):
        """
        Get all of a particular thing, returned as a list of json structures
        @param session_key: The splunkd session key
        @type session_key: string

        @return: a dict suitable for json conversion of the object types
        @rtype: list
        """
        backend = self.get_backend(session_key)
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        logger.info("%s user=%s method=get_all objecttype=%s filter=%s",
                LOG_CHANGE_TRACKING, user_name, objecttype, filter_data)
        return backend.get_all(session_key, owner, objecttype, sort_key=sort_key,
                sort_dir=sort_dir, filter_data=filter_data, fields=fields, skip=skip, limit=limit)

    def delete_all(self, session_key, owner, objecttype, filter_data, current_user_name=None):
        """
        Delete all of a particular thing, no return value
        @param session_key: The splunkd session key
        @param owner: The owner of the particular thing
        @param objecttype:    The type of object to delete
        @param filterdata: Particular filtering parameters - very much required because
            I don't want to allow people to delete the entire database just yet
        """
        backend = self.get_backend(session_key)
        user_name = current_user_name
        if user_name is None:
            user_name = getCurrentUser()['name']
        if filter_data is None or len(filter_data) == 0:
            filter_data = {"object_type":objecttype}
        logger.info("%s user=%s method=delete_all objecttype=%s filter=%s",
                LOG_CHANGE_TRACKING, user_name, objecttype, filter_data)
        backend.delete_all(session_key,owner,objecttype,filter_data)
        return

    def batch_save(self, session_key, owner, data_list):
        """
        WARNING: object type must be set before call this function

        Save multiple objects in single save

        @type session_key: basestring
        @param session_key: session_key

        @type owner: string
        @param owner: user who is performing this operation

        @type data_list: list of dictionary
        @param data_list: objects to upsert

        @rtype: list of strings
        @return: ids of objects upserted on success, throws exceptions on errors
        """
        backend = self.get_backend(session_key)
        results = backend.batch_save(session_key, owner, data_list)
        return results

###############################################################################
# Specific retrieval methods
###############################################################################
    def entity_clarification(self,objecttype,data):
        """
        Define an _type field for entities for use in rules vs non-rules
        Sigh .... We should get rid of this at some point
        """
        if objecttype != 'entity':
            return
        if data.has_key('_type'):
            return
        #At this point we need to make up the key to clarify what type of entity it is
        if data.has_key('identifier'):
            data['_type'] = 'entity'
        else:
            data['_type'] = 'rule'

#######################################################################################
# CSV Loading Methods
#######################################################################################


    def get_all_aliases(self,session_key,owner):
        """
        Returns all of the entity aliases and all of the stuff they own.
        We needed to add a filter parameter as well.
        """
        backend = self.get_backend(session_key)
        currentUser = getCurrentUser()
        logger.info("%s user=%s method=get_all_aliases", LOG_CHANGE_TRACKING, currentUser['name'])
        alias_dict = {}
        aliases = backend.get_all(session_key,owner, 'entity',
                fields=['identifier.fields','informational.fields'])
        for field in ['identifier','informational']:
            alias_set = set()
            # Add all of the aliases to the alias set
            for alias in aliases:
                if field not in alias:
                    continue
                if "fields" not in alias[field]:
                    continue
                alias_set.update(alias[field]['fields'])
            alias_dict[field] = list(alias_set)
        return alias_dict

    def get_count(self,session_key,owner,object_type,filter_data=None):
        """
        Gets the count for the specified object type.  Right now its a little hackey
        """
        backend = self.get_backend(session_key)
        currentUser = getCurrentUser()
        logger.info("%s user=%s method=get_count", LOG_CHANGE_TRACKING, currentUser['name'])

        keys = backend.get_all(session_key, owner, object_type, filter_data=filter_data, fields=['_key'])
        return {"count": len(keys)}