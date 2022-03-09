# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import time

from splunk.appserver.mrsparkle.lib import i18n
from splunk import ResourceNotFound
from ITOA.itoa_common import is_valid_dict, is_valid_list, is_valid_str, validate_json
from ITOA.storage import itoa_storage
from ITOA.setup_logging import setup_logging
from notable_event_utils import MethodType

logger = setup_logging('itsi_event_management.log', 'itsi.event_management')


class EventManagementException(Exception):
    pass


def time_function_call(fx):
    """
    This decorator will provide a log message measuring how long a function call took.

    Arguments:
    fx -- The function to measure
    """

    def wrapper(*args, **kwargs):

        logger.debug("Started operation=%s", fx.__name__)

        t = time.time()

        r = fx(*args, **kwargs)

        logger.info('[Change Tracking] Successfully called operation="%s"', fx.__name__)

        diff = time.time() - t

        diff_string = str(round(diff, 2)) + " seconds"

        logger.info('[Performance Tracking] Completed Notable Event operation="%s", duration="%s"', fx.__name__,
                    diff_string)

        return r

    return wrapper


class BaseEventManagement(object):
    """
    A generic class which has CURD operation and bulk curd operation to perform for any object level
    """

    # Key which hold id
    id_key = '_key'

    def __init__(self, session_key, collection, object_type, user='nobody', current_user_name=None):
        """
        Initialize objects

        @type session_key: basestring
        @param session_key: session_key

        @type collection: basestring
        @param collection: collection name

        @type user: basestring
        @param user: user name

        @type object_type: basestring
        @param object_type: object type

        @rtype: object
        @return: instance of the class
        """
        if not is_valid_str(session_key):
            message = _("Invalid session key")
            logger.error(message)
            raise ValueError(message)
        else:
            self.session_key = session_key

        self.owner = user
        self.current_user_name = current_user_name

        if not is_valid_str(collection):
            logger.error("Invalid collection name=%s", collection)
            raise ValueError(_('Invalid collection name'))
        else:
            self.collection = collection

        self.object_type = object_type

        self.object_type_key = 'object_type'

        self.storage_interface = itoa_storage.ITOAStorage(collection=self.collection)

    def pre_processing(self, data_list, method):
        """
        This is being used by inherit class which can be used
        to validate schema or inject some default values like time
        etc
        @type data_list: list
        @param data_list: data list

        @type method: basestring
        @param method: method name

        @return: None
        """
        pass

    def get_filter_data(self, object_ids):
        """
        return filter base upon _key

        @type: object_ids: list
        @param object_ids: object list

        @rtype: basestring
        @return: return filter string
        """
        if is_valid_list(object_ids):
            return {'$or': [{self.id_key: object_id} for object_id in object_ids]}
        else:
            raise TypeError(_('%s is not list') % object_ids)

    def merge_filter_data(self, filter_data, new_data):
        """
        Merge filter passed in request and filter created later

        Update filter_data in place

        @type filter_data: dict
        @param filter_data: filter data

        @type new_data: dict
        @param new_data: newly create filter
        @return:
        """
        if not is_valid_dict(new_data) or not is_valid_dict(filter_data):
            raise TypeError(_('Invalid filter data to merge'))

        for key, value in new_data.iteritems():
            if key in filter_data:
                filter_data[key].extend(value)
            else:
                filter_data[key] = value

        return validate_json('[event_management_interface]', filter_data)

    def get_user(self, **kwargs):
        """
        Return user
        @param kwargs: dict which hold some configuration

        @rtype: basestring
        @return: return user
        """
        return self.owner if self.owner else kwargs.get('owner')

    def fetch_filter_data(self, **kwargs):
        """
        Check filter data in kwargs and return dict form of it

        @type kwargs: dict
        @param kwargs: kwargs

        @rtype: dict
        @return: return filter data
        """
        filter_data = {}
        if kwargs.get('filter_data') and kwargs.get('filter') in kwargs:
            f_data_1 = kwargs.get('filter_data')
            f_data_2 = kwargs.get('filter')
            if f_data_1:
                f_data_1 = validate_json('[event_management_interface]', f_data_1)
            if f_data_2:
                f_data_2 = validate_json('[event_management_interface]', f_data_2)
            if f_data_1 is not None and filter_data is not None:
                filter_data = self.merge_data(f_data_1, f_data_2)
            else:
                filter_data = f_data_1 or f_data_2
        else:
            filter_data = kwargs.get('filter') or kwargs.get('filter_data')

        if filter_data:
            filter_data = validate_json('[event_management_interface]', filter_data)
        return filter_data or {}

    def inject_object_type(self, data_list):
        """
        Insert object type if it is not set

        @type data_list: list
        @param data_list: data list

        @return: in place update
        """
        # make sure object type is set
        for data in data_list:
            if 'object_type' not in data:
                data['object_type'] = self.object_type
            elif data.get('object_type') != self.object_type:
                data['object_type'] = self.object_type

    @time_function_call
    def create(self, data, **kwargs):
        """
        Create notable event

        @type data - dict
        @param data - notable event schema to create

        @rtype dict
        @return create object _key or raise an exception
        """
        if is_valid_dict(data):
            self.inject_object_type([data])
            self.pre_processing([data], MethodType.CREATE)
            result = self.storage_interface.create(self.session_key, self.get_user(**kwargs), self.object_type, data)
            logger.debug("Create %s object id=%s", self.object_type, result.get(self.id_key))
            return result
        else:
            message = _("Data is not a valid dictionary, data type=%s.") % type(data)
            logger.error(message)
            raise TypeError(message)

    def create_for_group(self, data, **kwargs):
        """
        Create stuff for events in a Group.
        """
        raise NotImplementedError(_('Derived class must implement this method'))

    @time_function_call
    def create_bulk(self, data_list, **kwargs):
        """
        Create more than one notable events

        @type data_list: list
        @param data_list: data list

        @rtype: list
        @return: list of created
        """
        try:
            validate_json('[Notable Event Curd]', data_list)
        except Exception as e:
            logger.exception(e)
            message = _('Invalid json list to do bulk create')
            logger.error(message)
            raise TypeError(message)

        # make sure object type is set
        self.inject_object_type(data_list)
        self.pre_processing(data_list, MethodType.CREATE_BULK)

        results = self.storage_interface.batch_save(self.session_key, self.get_user(**kwargs), data_list)
        return results

    @time_function_call
    def get(self, object_id, **kwargs):
        """
        Get notable event object

        @type object_id: basestring
        @param object_id: notable event key

        @rtype: dict
        @return: return notable event schema
        """
        if is_valid_str(object_id):
            result = self.storage_interface.get(self.session_key, self.get_user(**kwargs), self.object_type, object_id)
            return result
        else:
            message = _('Invalid key to get object, value=%s.') % object_id
            logger.error(message)
            raise TypeError(message)

    @time_function_call
    def get_bulk(self, object_ids, **kwargs):
        """
        Get one or more than one notable events

        @type object_ids: list
        @param object_ids: list of objects to get
        Note: if object list is empty or not defined then get all objects

        @type kwargs: dict
        @param kwargs: extra arguments to fetch notable events

        @rtype: list
        @return: list of notable events
        """
        filter_data = self.fetch_filter_data(**kwargs)

        if is_valid_list(object_ids) and len(object_ids) != 0:
            self.merge_filter_data(filter_data, self.get_filter_data(object_ids))

        logger.debug('Updated filter data=%s', filter_data)

        limit = kwargs.get('count')
        skip = kwargs.get('offset')
        if limit is None and skip is None:
            # If count and offset are undefined, try limit and skip
            limit = kwargs.get('limit')
            skip = kwargs.get('skip')

        results = self.storage_interface.get_all(self.session_key, self.get_user(**kwargs), self.object_type,
                                                 sort_key=kwargs.get('sort_key'), filter_data=filter_data,
                                                 sort_dir=kwargs.get('sort_dir'), fields=kwargs.get('fields'),
                                                 skip=skip, limit=limit
                                                 )
        logger.debug("Return %s notable events", len(results))
        return results

    def get_and_merge_data_list(self, object_ids, data_list, is_partial_update=True, **kwargs):
        """
        Useful function to do partial update. Its merge data from backend with request data

        @type object_ids: list
        @param object_ids: list of objects to fetch from backend

        @type data_list: list
        @param data_list: data list which is passed in the request

        @type is_partial_update: bool
        @param is_partial_update: set to true it is partial update

        @param **kwargs: Key word arguments to provide additional args to those who override this method

        @rtype: list
        @return: Merged data
        """
        results = self.get_bulk(object_ids)
        if results is None or len(results) == 0:
            logger.error('Failed to get objects=%s from kv store', object_ids)
            raise EventManagementException('Failed to get objects=%s from kv store'%(str(object_ids)))
        mapped_objects = {}
        for data in data_list:
            if data.get(self.id_key) not in mapped_objects:
                mapped_objects[data.get(self.id_key)] = {'data': data, 'fdata': None}
        for result in results:
            if result.get(self.id_key) in mapped_objects:
                mapped_objects[result.get(self.id_key)]['fdata'] = result
        for value in mapped_objects.itervalues():
            self.merge_data(value['fdata'], value['data'], is_partial_update)
        return data_list

    def get_and_merge_data(self, object_id, data, is_partial_update=True, **kwargs):
        """
        Similar function but it deals with one object instead of list
        Note: this is inplace update to data dict

        @type object_id: basestring
        @param object_id: object id

        @type data: dict
        @param data: data is passed in the request

        @type is_partial_update: bool
        @param is_partial_update: set to true it is partial update

        @param **kwargs: Key word arguments to provide additional args to those who override this method

        @rtype: dict
        @return: Merge data
        """
        result = self.get(object_id)
        if result is None:
            logger.error("Failed to get object id=%s from kv store", object_id)
            raise EventManagementException("Failed to get object id=%s from kv store"%object_id)
        return self.merge_data(result, data, is_partial_update)

    def merge_data(self, fetched_data, data, is_partial_update=True):
        """
        Helper function to merge request data with backend data
        Note: this is inplace update to data dict

        @type fetched_data: dict
        @param fetched_data: Fetch data from backend

        @param data: dict
        @param data: request data

        @type is_partial_update: bool
        @param is_partial_update: set to true it is partial update

        @rtype: dict
        @return: return updated data (inplace update to data)
        """
        if data is None or fetched_data is None:
            logger.error("data or fetched data is None")
            raise EventManagementException('data or fetched data is None')

        for key, value in fetched_data.iteritems():
            if is_partial_update and key not in data:
                data[key] = value

        return data

    @time_function_call
    def update(self, object_id, data, is_partial_update=False, **kwargs):
        """
        Update one notable event

        @type object_id: basestring
        @param object_id: object id

        @type data: dict
        @param data: data

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: Extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        if is_valid_str(object_id):
            self.get_and_merge_data(object_id, data, is_partial_update, **kwargs)

            self.inject_object_type([data])
            self.pre_processing([data], MethodType.UPDATE)

            result = self.storage_interface.edit(self.session_key, self.get_user(**kwargs), self.object_type,
                                                 object_id, data)
            return result
        else:
            message = _('Object id is not valid string, value=%s') % object_id
            logger.error(message)
            raise TypeError(message)

    @time_function_call
    def update_bulk(self, object_ids, data_list, is_partial_update=False, **kwargs):
        """
        Perform update for one or more notable events

        @type object_ids: list
        @param object_ids: notable events

        @type data_list: list
        @param data_list: notable events

        @type is_partial_update: bool
        @param is_partial_update: flag for partial update

        @type kwargs: dict
        @param kwargs: Extra params to perform

        @rtype: list
        @return: update notable event schema
        """
        if is_valid_list(object_ids):
            self.get_and_merge_data_list(object_ids, data_list, is_partial_update, **kwargs)
            self.inject_object_type(data_list)
            self.pre_processing(data_list, MethodType.UPDATE_BULK)
            results = self.storage_interface.batch_save(self.session_key, self.get_user(**kwargs), data_list)
            return results
        else:
            message = _('Object ids is not valid list, value=%s.') % object_ids
            logger.error(message)
            raise TypeError(message)

    @time_function_call
    def delete(self, object_id, **kwargs):
        """
        Delete notable event from KV store

        @type object_id: basestring
        @param object_id: object id

        @type kwargs: dict
        @param kwargs: extra params

        @return: None
        """
        if is_valid_str(object_id):
            self.pre_processing([{self.id_key: object_id}], MethodType.DELETE)
            logger.debug('Deleting %s:%s event', self.id_key, object_id)
            return self.storage_interface.delete(self.session_key, self.get_user(**kwargs), self.object_type, object_id)
        else:
            message = _('Id can not be empty or invalid id=%s.') % object_id
            logger.error(message)
            raise TypeError(message)

    @time_function_call
    def delete_bulk(self, object_ids, **kwargs):
        """
        Delete bulk

        @type object_ids: list
        @param object_ids: object list to delete

        @type kwargs: dict
        @param kwargs: extra params to delete
        @return:
        """
        filter_data = self.fetch_filter_data(**kwargs)

        if is_valid_list(object_ids) and len(object_ids) != 0:
            self.merge_filter_data(filter_data, self.get_filter_data(object_ids))

        if filter_data:
            filter_data = validate_json('[event_management_interface]', filter_data)

        if isinstance(object_ids, list):
            self.pre_processing([{self.id_key: eid for eid in object_ids}], MethodType.DELETE_BULK)
        logger.debug('Deleting events ids=%s, other arguments=%s', object_ids, filter_data)

        return self.storage_interface.delete_all(self.session_key, self.get_user(**kwargs), self.object_type,
                                                 filter_data)

