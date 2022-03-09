# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time
from abc import ABCMeta, abstractmethod

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.event_management.notable_event_comment import NotableEventComment
from ITOA.event_management.notable_event_tag import NotableEventTag
from ITOA.event_management.notable_event_utils import filter_index_fields_and_get_event_id_for_notable_event,\
    SearchUtils, Audit, NotableEventException, NotableEventConfiguration, MethodType
from ITOA.itoa_common import is_valid_dict, is_valid_list, is_valid_str, validate_json, get_current_utc_epoch
from ITOA.storage import itoa_storage
from ITOA.setup_logging import setup_logging
from base_event_management import time_function_call, BaseEventManagement, EventManagementException
from push_event_manager import PushEventManager


class NotableEvent(BaseEventManagement):
    __metaclass__ = ABCMeta

    def __init__(self, session_key,
                 index_name,
                 current_user_name=None,
                 audit_token_name='Notable Index Audit Token',
                 tag_collection='itsi_notable_event_tag',
                 comment_collection='itsi_notable_event_comment',
                 state_collection='itsi_notable_event_state',
                 logger=None,
                 **kwargs):
        """
        Initialize objects

        @type session_key: basestring
        @param session_key: session_key

        @type audit_token_name: basestring
        @param audit_token_name: Http listener token name to audit any create, update, delete

        # Tag and collection is required to delete tags and comments
        @type tag_collection: basestring
        @param tag_collection: Tag collection name

        @type comment_collection: basestring
        @param comment_collection: comment collection

        @type kwargs: dict
        @param kwargs: Additional settings like token name, audit index etc

        @rtype: object
        @return: instance of the class
        """
        if logger:
            self.logger = logger
        else:
            self.logger = setup_logging('itsi_event_management.log', 'itsi.notable_event')

        if not (is_valid_str(session_key) and is_valid_str(index_name)):
            self.logger.error("Invalid session key or index name")
            raise NotableEventException('Invalid session key or index name')
        else:
            self.session_key = session_key

        self.mod_time_key = 'mod_time'
        self.create_time_key = 'create_time'
        default_token_name='Auto Generated Event Management Token'
        token_name = kwargs.get('token_name', default_token_name)

        # Extra arguments
        self.kwargs = kwargs
        self.id_key = 'event_id'

        self.audit = Audit(self.session_key, audit_token_name=audit_token_name,
                           audit_host=kwargs.get('audit_host'),
                           audit_source=kwargs.get('audit_source', 'Notable Event Audit'),
                           audit_sourcetype=kwargs.get('audit_sourcetype', 'stash'))
        self.push_manager = PushEventManager(self.session_key, token_name)
        self.search_utils = SearchUtils(self.session_key, self.logger, index_name,
                                        user=kwargs.get('user', 'nobody'),
                                        namespace=kwargs.get('namespace', 'itsi'))
        self.tag_object = NotableEventTag(session_key, collection=tag_collection)
        self.comment_object = NotableEventComment(session_key, collection=comment_collection)
        self.storage_interface = itoa_storage.ITOAStorage(collection=state_collection)
        self.object_type = 'notable_event_state'
        self.owner = kwargs.get('user', 'nobody')
        self.current_user_name = current_user_name
        self.fields_to_track = ['status', 'severity', 'owner']
        self.notable_event_configuration = NotableEventConfiguration(session_key, self.logger)

    def pre_processing(self, data_list, method):
        """
        Add mod_time and create_time to the notable event states

        @type data_list: list
        @param data_list: list of data to validate and add time, user info etc

        @type method: basestring
        @param method: method type

        @rtype: list
        @return: It updates list in place and also return it back as well
        """
        if not isinstance(data_list, list):
            error_msg = _('data_list: {0} is not valid list, data_list type is {1}.').format(data_list, type(data_list))
            self.logger.error(error_msg)
            raise TypeError(error_msg)

        for data in data_list:
            # Make sure data is valid dict
            if not isinstance(data, dict):
                error_msg = _('data: {0} is not valid dictionary, data type is {1}.').format(data, type(data))
                self.logger.error(error_msg)
                raise TypeError(error_msg)

            # Ensure '_key' is set to id_key for kv store request
            if self.id_key in data:
                data['_key'] = data.get(self.id_key)

            time_value = time.time()
            if method in (MethodType.CREATE, MethodType.CREATE_BULK):
                # Add create time
                data[self.create_time_key] = time_value
            if method not in (MethodType.DELETE, MethodType.DELETE_BULK, MethodType.GET, MethodType.GET_BULK):
                # Need to set mod time for create and update
                data[self.mod_time_key] = time_value

        return data_list

    @abstractmethod
    def validate_schema(self, data):
        """
        Validate schema prior to perform an operation

        @type data: dict
        @param data: schema to validate

        @rtype: bool
        @return: True - if validation pass otherwise False
        """
        raise NotImplementedError(_('Not implemented'))

    def validate_schema_list(self, data_list):
        """
        Validate schema list

        @type data_list: list
        @param data_list: list of document/schema

        @rtype: bool
        @return: True/False
        """
        ret = True
        if is_valid_list(data_list):
            for data in data_list:
                ret = ret and self.validate_schema(data)
        else:
            self.logger.error('Can not validate schema because of invalid list')
        return ret

    def add_time(self, data):
        """
        Add create time and mod time to data

        @type data: dict
        @param data: data to add create time and mod time

        @rtype: dict
        @return: updated data or raise exception
        """
        if not is_valid_dict(data):
            self.logger.error('Failed to add create time because of invalid format of data')
            raise NotableEventException('Failed to add create time because of invalid format of data')

        # add mod time
        data = self.upsert_mod_time(data)

        return data

    def upsert_mod_time(self, data):
        """
        Add or update mod time

        @type data: dict
        @param data: data to add create time and mod time

        @rtype: dict
        @return: updated data or raise exception
        """
        if not is_valid_dict(data):
            self.logger.error('Failed to add %s time', self.mod_time_key)
            raise NotableEventException('Failed to add required %s key' % self.mod_time_key)

        data[self.mod_time_key] = str(get_current_utc_epoch())
        return data

    def _upsert_old_values(self, fetched_data, data):
        """
        Add old values to data to set up values for activity tracking

        @type fetched_data: dict
        @param fetched_data: old data values to graft onto data

        @type data: dict
        @param data: data to add old value tracking to

        @rtype: dict
        @return: data, updated in place with old value tracking
        """
        # graft fetched data onto object to update so that activity tracking can use it
        for key in fetched_data.keys():
            if key != self.id_key and key != '_key':
                data['__old__' + key] = fetched_data.get(key)

    def _upsert_id_key(self, data, object_id):
        """
        Add object_id to data

        @type data: dict
        @param data: data to add id key to

        @type object_id: basestring
        @param object_id: id key to add

        @rtype: dict
        @return: updated data or raise exception
        """
        if not is_valid_dict(data):
            error_msg = _('Failed to add key {0} to data: {1}.').format(object_id, data)
            self.logger.error(error_msg)
            raise NotableEventException(error_msg)

        # ensure object_id is included in data so that event_id matches _key in kv store
        data[self.id_key] = object_id

        return data

    @time_function_call
    def create(self, data, **kwargs):
        """
        Create notable event

        @type data - dict
        @param data - notable event schema to create

        @rtype dict
        @return create object _key or raise an exception
        """
        if not is_valid_dict(data):
            message = _("Data is not a valid dictionary, data type=%s") % type(data)
            self.logger.error(message)
            raise NotableEventException(message)

        self.add_time(data)
        updated = filter_index_fields_and_get_event_id_for_notable_event(data, self.logger,
            is_none_allowed=True, event_identifier_fields_string=data.get('event_identifier_fields'),
            is_token_replacement=True
        )

        try:
            self.validate_schema(updated)
        except Exception:
            self.logger.error('Validation failed and invalid data to create notable event, data="%s"', data)
            raise

        # create event id and filter some index fields
        self.push_manager.push_event(updated,  host=updated.get('host'), time=updated.get('_time'),
             source=updated.get('source'), sourcetype=updated.get('sourcetype'))
        self.logger.debug("Created event id=%s", updated.get(self.id_key))
        return updated.get(self.id_key)

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
            validate_json('[Notable Event CRUD]', data_list)
        except Exception:
            self.logger.exception('Invalid json list to do bulk create')
            raise

        results = []

        # prepare bulk data
        for data in data_list:
            self.add_time(data)
            # Create event id, mod time and filter some index fields
            updated = filter_index_fields_and_get_event_id_for_notable_event(
                    data,
                    self.logger,
                    is_none_allowed=True,
                    event_identifier_fields_string=data.get('event_identifier_fields'),
                    is_token_replacement=True
            )
            try:
                self.validate_schema(updated)
            except Exception:
                self.logger.error('Invalid data={0}'.format(updated))
                raise
            results.append(updated.get(self.id_key))
            self.push_manager.push_event(updated, host=updated.get('host'), time=updated.get('_time'),
                    source=updated.get('source'), sourcetype=updated.get('sourcetype'))
        # audit is not applicable for events that do not exist yet.
        return results

    @time_function_call
    def get(self, object_id, **kwargs):
        """
        Get notable event object

        @type object_id: basestring
        @param object_id: notable event key

        @type kwargs: optional key value params `earliest_time` and
            `latest_time`
        @param  kwargs: additional parameters which can optimize search time
            if you know what the bucket is, this is awesome.

        @rtype: dict
        @return: return notable event schema
        """
        if not is_valid_str(object_id):
            message = _('Invalid key to get object, value=%s.') % object_id
            self.logger.error(message)
            raise TypeError(message)

        result = self.search_utils.get_events([object_id], earliest_time=kwargs.get('earliest_time'),
           latest_time=kwargs.get('latest_time'))
        result = result[0]

        # get and merge results from kv store
        kv_result = self._check_state_exists(object_id)
        if kv_result is not None:
            self._force_merge_data(kv_result, result)

        return result

    @time_function_call
    def get_bulk(self, object_ids, **kwargs):
        """
        Get one or more than one notable events

        @type object_ids: list
        @param object_ids: list of objects to get

        @type kwargs: dict
        @param kwargs: extra arguments to fetch notable events

        @rtype: list
        @return: list of notable events
        """
        if not is_valid_list(object_ids):
            message = _('Object ids is not valid list, value=%s.') % object_ids
            self.logger.error(message)
            raise TypeError(message)

        results = self.search_utils.get_events(object_ids, earliest_time=kwargs.get('earliest_time'),
                                               latest_time=kwargs.get('latest_time'))
        # sort results to speed up iteration
        results = sorted(results, key=lambda result: result.get(self.id_key))

        # get and merge results from kv store
        # TODO: pass sort by event_id as part of get request
        kv_results = self._get_state_bulk(object_ids)
        if len(kv_results) > 0:
            # sort kv_results to speed up iteration
            kv_results = sorted(kv_results, key=lambda result: result.get(self.id_key))
            results_iter = 0
            for kv_result in kv_results:
                # find raw index result in sorted results, starting at results_iter
                if results_iter < len(results):
                    for i in range(results_iter, len(results)):
                        result = results[i]
                        if result.get(self.id_key) == kv_result.get(self.id_key):
                            # merge kv values onto index result
                            self._force_merge_data(kv_result, result)
                            results_iter += 1
                            break

        self.logger.debug("Return %s notable events", len(results))
        return results

    def _force_merge_data(self, fetched_data, data):
        """
        Helper function to merge request data with backend data
        Note: this is inplace update to data dict

        @type fetched_data: dict
        @param fetched_data: Fetch data from backend

        @param data: dict
        @param data: request data

        @rtype: dict
        @return: return updated data (inplace update to data)
        """
        if data is None or fetched_data is None:
            error_msg = _('data or fetched data is None.')
            self.logger.error(error_msg)
            raise EventManagementException(error_msg)

        for key, value in fetched_data.iteritems():
            data[key] = value

        return data

    def _get_activity(self, updated_data, activity_type=None):
        """
        Return activity which is happening during update

        @type updated_data: dict
        @param updated_data: data to get activity

        @type activity_type: basestring
        @param activity_type: type of activity

        @rtype: basestring
        @return: activity log statement
        """
        activity_tracking = ''
        keys_to_delete = []
        fields_to_update = [] # keep track of fields that already exist in entry

        if activity_type == 'acknowledge':
            return '{0} acknowledged notable event'.format(updated_data.get('owner'))

        # handle fields that already exist in entry - show update from old value to new value
        for key in updated_data.keys():
            if key.startswith('__old__'):
                keys_to_delete.append(key)
                actual_key = key[len('__old__'):]
                if actual_key not in updated_data or actual_key not in self.fields_to_track:
                    continue
                fields_to_update.append(actual_key)
                old_value = updated_data.get(key)
                new_value = updated_data.get(actual_key)
                # look up label for available fields
                if actual_key == 'status':
                    old_value = '{0} ({1})'.format(self.notable_event_configuration.status_contents.get(old_value, {}).get('label'), old_value)
                    new_value = '{0} ({1})'.format(self.notable_event_configuration.status_contents.get(new_value, {}).get('label'), new_value)
                elif actual_key == 'severity':
                    old_value = '{0} ({1})'.format(self.notable_event_configuration.severity_contents.get(old_value, {}).get('label'), old_value)
                    new_value = '{0} ({1})'.format(self.notable_event_configuration.severity_contents.get(new_value, {}).get('label'), new_value)
                activity_tracking += '{0} changed from {0}="{1}" to {0}="{2}". '.format(actual_key, old_value, new_value)

        # delete old entry in the dict
        for key in keys_to_delete:
            del updated_data[key]

        # handle fields that don't exist yet - show update to new value
        for field in updated_data.keys():
            if field not in fields_to_update and field in self.fields_to_track:
                value = updated_data.get(field)
                if field == 'status':
                    value = '{0} ({1})'.format(self.notable_event_configuration.status_contents.get(value, {}).get('label'), value)
                elif field == 'severity':
                    value = '{0} ({1})'.format(self.notable_event_configuration.severity_contents.get(value, {}).get('label'), value)
                activity_tracking += 'updated {0}="{1}". '.format(field, value)

        return activity_tracking

    def _create_state(self, data, **kwargs):
        """
        Create state for one notable event

        @type data - dict
        @param data - notable event schema to create

        @rtype dict
        @return created object _key or raise an exception
        """
        if not isinstance(data, dict):
            error_msg = _('data: {0} is not valid dictionary, data type is {1}.').format(data, type(data))
            self.logger.error(error_msg)
            raise TypeError(error_msg)

        activity = self._get_activity(data, kwargs.pop('action_type', None))
        ret = super(NotableEvent, self).create(data, **kwargs)
        # Create is kind of update here because event had already created with some initial state
        # now we are tracking its state by creating record in KV
        self.audit.send_activity_to_audit({self.id_key: data.get('_key')}, activity, 'Notable Event Update')
        return ret

    def _get_state(self, object_id, **kwargs):
        """
        Get state for one notable event

        @type object_id: basestring
        @param object_id: object id

        @rtype: dict
        @return: notable event state
        """
        return super(NotableEvent, self).get(object_id, **kwargs)

    def _update_state(self, object_id, data, is_partial_update=False, **kwargs):
        """
        Update state for one notable event

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
        activity = self._get_activity(data, kwargs.pop('action_type', None))
        ret = super(NotableEvent, self).update(object_id, data, is_partial_update, **kwargs)
        self.audit.send_activity_to_audit({self.id_key: data.get('_key')}, activity, 'Notable Event Update')

        return ret

    def _delete_state(self, object_id, **kwargs):
        """
        Delete state for one notable event

        @type object_id: basestring
        @param object_id: object id

        @type kwargs: dict
        @param kwargs: extra params

        @return:
        """
        return super(NotableEvent, self).delete(object_id, **kwargs)

    def _create_state_bulk(self, data_list, **kwargs):
        """
        Create state for one or more notable events

        @type data_list: list
        @param data_list: data list

        @rtype: list
        @return: list of created state object _keys
        """
        if not isinstance(data_list, list):
            error_msg = _('data_list: {0} is not valid list, data_list type is {1}.').format(data_list, type(data_list))
            self.logger.error(error_msg)
            raise TypeError(error_msg)

        action_type = kwargs.pop('action_type', None)
        activities_data = []
        activities = []
        for data in data_list:
            activities_data.append({self.id_key: data.get(self.id_key)})
            activities.append(self._get_activity(data, action_type))
        ret = super(NotableEvent, self).create_bulk(data_list, **kwargs)
        # Create is kind of update here because events had already created with some initial state
        # now we are tracking their state by creating record in KV
        self.audit.send_activity_to_audit_bulk(activities_data, activities, 'Notable Event Bulk Update')

        return ret

    def _get_state_bulk(self, object_ids, **kwargs):
        """
        Get state for one or more notable events

        @type object_ids: list
        @param object_ids: list of objects to get
        Note: if object list is empty or not defined then get all objects

        @type kwargs: dict
        @param kwargs: extra arguments to fetch notable events

        @rtype: list
        @return: list of states of notable events
        """
        return super(NotableEvent, self).get_bulk(object_ids, **kwargs)

    def _update_state_bulk(self, data_list, is_partial_update=True, **kwargs):
        """
        Perform update for one or more notable events

        @type object_ids: list
        @param object_ids: notable event IDs

        @type data_list: list
        @param data_list: notable events

        @type is_partial_update: bool
        @param is_partial_update: flag for partial update

        @type kwargs: dict
        @param kwargs: Extra params to perform

        @rtype: list
        @return: updated notable event IDs
        """
        if not isinstance(data_list, list):
            error_msg = _('data_list: {0} is not valid list, data_list type is {1}.').format(data_list, type(data_list))
            self.logger.error(error_msg)
            raise TypeError(error_msg)
        if len(data_list) == 0:
            return []

        action_type = kwargs.pop('action_type', None)

        ids = []
        ids_data = []
        activities = []
        for data in data_list:
            ids.append(data.get(self.id_key))
            ids_data.append({self.id_key: data.get(self.id_key)})
            activities.append(self._get_activity(data, action_type))
        ret = super(NotableEvent, self).update_bulk(ids, data_list, is_partial_update, **kwargs)
        self.audit.send_activity_to_audit_bulk(ids_data, activities, 'Notable Event Bulk Update')

        return ret

    def _delete_state_bulk(self, object_ids, **kwargs):
        """
        Delete bulk

        @type object_ids: list
        @param object_ids: object ID list to delete

        @type kwargs: dict
        @param kwargs: extra params to delete

        @return:
        """
        return super(NotableEvent, self).delete_bulk(object_ids, **kwargs)

    def _check_state_exists(self, object_id):
        """
        Check KV store to see if entry exists for given event ID

        @type object_id: basestring
        @param object_id: object id

        @rtype: dict|None
        @return: entry if it exists in KV store, None otherwise
        """
        try:
            # see if entry for event exists
            return self._get_state(object_id)
        except Exception:
            return

    def get_and_merge_data_list(self, object_ids, data_list, is_partial_update=True, **kwargs):
        """
        Similar function to do partial update. It merges data from backend with request data

        @type object_ids: list
        @param object_ids: list of objects to fetch from backend

        @type data_list: list
        @param data_list: data list with his passed in the request

        @type is_partial_update: bool
        @param is_partial_update: set to true if it is partial update

        @param **kwargs: Key word arguments to provide additional args to those who override this method
            Generally expected kwargs are:
                fetched_data: already fetched kv store entry for given object_id

        @rtype: list
        @return: Merged data
        """
        # if data hasn't been fetched yet, fetch it from KV store
        fetched_data = kwargs.get('fetched_data', self._get_state_bulk(object_ids))
        if fetched_data is None or len(fetched_data) == 0:
            error_msg = _('Failed to get state for events: {0} from kv store.').format(str(object_ids))
            self.logger.error(error_msg)
            raise EventManagementException(error_msg)

        mapped_objects = {}
        for data in data_list:
            mapped_objects[data.get(self.id_key)] = {'data': data,'fdata': None}
        # fill in fetched data values
        for state_object in fetched_data:
            if state_object.get(self.id_key) in mapped_objects:
                mapped_objects[state_object.get(self.id_key)]['fdata'] = state_object
        # merge fetched data with data to udpate
        for value in mapped_objects.itervalues():
            self.merge_data(value.get('fdata'), value.get('data'), is_partial_update)

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
        @param is_partial_update: set to true if it is partial update

        @param **kwargs: Key word arguments to provide additional args to those who override this method
            Generally expected kwargs are:
                fetched_data: already fetched kv store entry for given object_id

        @rtype: dict
        @return: Merge data
        """
        # if data hasn't been fetched yet, fetch it from KV store
        fetched_data = kwargs.get('fetched_data', self._check_state_exists(object_id))
        if fetched_data is None:
            error_msg = _('Failed to get state for event: {0} from kv store.').format(object_id)
            self.logger.error(error_msg)
            raise EventManagementException(error_msg)

        return self.merge_data(fetched_data, data, is_partial_update)

    @time_function_call
    def update(self, object_id, data, is_partial_update=True, **kwargs):
        """
        Update one notable event's state

        @type object_id: basestring
        @param object_id: object id

        @type data: dict
        @param data: data

        @type kwargs: dict
        @param kwargs: Extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        if not is_valid_str(object_id):
            error_msg = _('Object_id: {0} is not valid str, object_id type is {1}.').format(object_id, type(object_id))
            self.logger.error(error_msg)
            raise TypeError(error_msg)

        data_to_update = {}
        self._upsert_id_key(data_to_update, object_id)
        # grab valid fields from data
        for field in self.fields_to_track:
            if field in data:
                data_to_update[field] = data.get(field)

        # fetch event state, if it exists
        fetched_event_state = self._check_state_exists(object_id)
        # create entry for event if it doesn't exist yet and return
        if fetched_event_state is None:
            return self._create_state(data_to_update, **kwargs)

        # update existing entry for event
        self._upsert_old_values(fetched_event_state, data_to_update)

        return self._update_state(object_id, data_to_update, is_partial_update, fetched_data=fetched_event_state, **kwargs)

    @time_function_call
    def update_bulk(self, object_ids, data_list, is_partial_update=True, **kwargs):
        """
        Perform update for one or more notable events

        Note: is_partial_update is not being used here because it is always do partial update

        @type object_ids: list
        @param object_ids: notable events

        @type data_list: list
        @param data_list: notable events

        @type is_partial_update: bool
        @param is_partial_update: flag for partial update

        @type kwargs: dict
        @param kwargs: Extra params to perform

        @rtype: list
        @return: updated notable event IDs
        """
        if not is_valid_list(object_ids):
            errorMsg = _('Object_ids: {0} is not valid list, object_ids type is {1}.').format(object_ids, type(object_ids))
            self.logger.error(errorMsg)
            raise TypeError(errorMsg)
        if not is_valid_list(data_list):
            errorMsg = _('Data_list: {0} is not valid list, data_list type is {1}.').format(data_list, type(data_list))
            self.logger.error(errorMsg)
            raise TypeError(errorMsg)
        if len(data_list) != len(object_ids):
            errorMsg = _('Object_ids: {0} to update don\'t match up with data_list: {1}.').format(object_ids, data_list)
            self.logger.error(errorMsg)
            raise TypeError(errorMsg)
        if len(data_list) == 0 or len(object_ids) == 0:
            return []

        # if action_type is not in kwargs, it is acknowledge action for "All events in the group"
        # no other elegant way of passing action_type flag to _create_state_bulk
        # action_type in data is removed before _create_state_bulk is called because it is not one of the fields to track
        if 'action_type' not in kwargs:
            kwargs['action_type'] = data_list[0].get('action_type', None)

        # create map of ID to associated data
        mapped_objects = {}
        for event_id in object_ids:
            data = [data for data in data_list if data.get(self.id_key) == event_id]
            if len(data) > 0:
                data = data[0]
                data_to_update = {}
                self._upsert_id_key(data_to_update, event_id)
                # grab valid fields from data
                for field in self.fields_to_track:
                    if field in data:
                        data_to_update[field] = data.get(field)
                mapped_objects[event_id] = data_to_update

        # fetch existing state object entries
        existing_state_objects = self._get_state_bulk(object_ids)

        # determine if state objects need to be updated or created based on existence in KV store
        objects_to_create = []
        objects_to_update = []
        for object_id, mapped_object in mapped_objects.iteritems():
            existing_state_object = [existing_state_object for existing_state_object in existing_state_objects if existing_state_object.get(self.id_key) == object_id]
            if len(existing_state_object) == 0:
                # object doesn't exist so it needs to be created
                objects_to_create.append(mapped_object)
            else:
                # object exists so it can be updated
                existing_state_object = existing_state_object[0]
                self._upsert_old_values(existing_state_object, mapped_object)
                objects_to_update.append(mapped_object)

        # bulk create non-existent entries
        create_ret = []
        create_err = None
        # create entries, best-effort
        if len(objects_to_create) > 0:
            try:
                create_ret = self._create_state_bulk(objects_to_create, **kwargs)
            except Exception as e:
                create_err = e

        # bulk update existing entries
        update_ret = []
        update_err = None
        # update entries, best-effort
        if len(objects_to_update) > 0:
            try:
                update_ret = self._update_state_bulk(objects_to_update, is_partial_update, fetched_data=existing_state_objects, **kwargs)
            except Exception as e:
                update_err = e

        # handle errors
        if create_err is not None or update_err is not None:
            msg = _('Notable event bulk update failed.')
            if create_err is not None:
                msg += ' {0}'.format(str(create_err))
            if update_err is not None:
                msg += ' {0}'.format(str(update_err))
            self.logger.error(msg)
            raise NotableEventException(msg)

        # join returned values (IDs) from create and update
        return create_ret + update_ret

    def update_group_events(self, group_id, fields_to_update, event_filter, **kwargs):
        """
        This function is being used when user want to perform action on group events with specific state to new state
        Primary uses for this is rules engine

        @type group_id: basestring
        @param group_id: group id

        @type fields_to_update: dict
        @param fields_to_update: key, value of fields to update

        @type event_filter: basestring
        @param event_filter: event filter which needs to be apply

        @return: list of ids of updated notable events
        """
        if not isinstance(group_id, basestring) or not isinstance(event_filter,
                basestring) or not isinstance(fields_to_update, dict):
            msg = _('Invalid group_id="{}" or fields_to_update="{}" or filter="{}".').format(
                    group_id, str(fields_to_update), event_filter)
            self.logger.error(msg)
            raise TypeError(msg)

        events = self.search_utils.update_group_events(group_id, fields_to_update, event_filter,
            latest_time=kwargs.get('latest_time'), earliest_time=kwargs.get('earliest_time'))

        activity = 'changed events which match filter=`%s` to `%s`'%(event_filter, str(fields_to_update))

        mapped_data_to_update = {}
        for event_id in events:
            mapped_data_to_update[event_id] = {self.id_key: event_id}
            for field_key, field_value in fields_to_update.iteritems():
                mapped_data_to_update[event_id][field_key] = field_value

        ret = self.update_bulk(mapped_data_to_update.keys(), mapped_data_to_update.values())
        self.audit.send_activity_to_audit({'event_id': group_id, 'is_group': True}, activity, 'Notable Event Bulk Update for Group')

        return ret
