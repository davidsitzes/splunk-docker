# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
 This module is used to do single or bulk create/update/delete/get on correlation searches. Correlation searches is
 nothing other than saved searches which has some alert enable to generate notable events
"""
import abc
import json

from splunk.appserver.mrsparkle.lib import i18n
from notable_event_utils import MethodType
from ITOA.event_management.base_event_management import BaseEventManagement, time_function_call
from ITOA.saved_search_utility import SavedSearch
from ITOA.setup_logging import setup_logging
from ITOA.itoa_exceptions import ItoaAccessDeniedError
from itsi.objects.itsi_service import ItsiService
import splunk.entity

class CorrelationSearchException(Exception):
    pass


class CorrelationSearch(BaseEventManagement):
    """
    Main class to create/update/delete correlation search

    Correlation search support all saved search properties.
    """
    __metaclass__ = abc.ABCMeta

    id_key = 'sid' # Set this id to perform update

    def __init__(self, session_key, current_user_name=None, user='nobody', app='itsi', logger=None):
        """
        Initialize objects

        @type session_key: basestring
        @param session_key: session_key


        @type user: basestring
        @param user: user name

        @type app: app context
        @param app: app name

        @type logger: logger object
        @param logger: logger name

        @rtype: object
        @return: instance of the class
        """

        if not session_key:
            raise TypeError(_('Invalid session key'))

        self.session_key = session_key
        if logger:
            self.logger = logger
        else:
            self.logger = setup_logging('itsi_event_management.log',
                                        'itsi.event_management.correlation_search')
        self.app = app
        self.owner = user
        self.current_user_name = current_user_name
        self.name_key = 'name'
        self.search_key = 'search'
        self.name_key = 'name'

        # Saved Search Entity can have very large schema like 400 field set
        # Include all first level field, however you need to define all prefix for all fields which
        #  goes more than one level
        self.field_suffix = ['action.itsi_event_generator',
                             'action.email',
                             'action.script',
                             'action.rss',
                             'alert',
                             'dispatch']

        self.object_type = "correlation_search"

    def validation(self, search_schema_list, method):
        """
        Validate required keys like name and search

        @type search_schema_list: list
        @param search_schema_list: list of search schema

        @type method: basestring
        @param method: method type

        @rtype: bool
        @return: True|False of validation
        """
        if not isinstance(search_schema_list, list):
            raise TypeError(_('Could not validate searches because provide data is not a valid list'))
        if not self.extra_validation(search_schema_list, method):
            message = _('Addition validation has failed')
            self.logger.error(message)
            raise CorrelationSearchException(message)
        for data in search_schema_list:
            if not data:
                msg = _('Search data is not defined, type={0}.').format(type(data))
                self.logger.error(msg)
                raise TypeError(msg)
            if not self._validate_key(data, self.name_key):
                msg = _('Search name={0} is not defined.').format(data.get(self.name_key))
                self.logger.error(msg)
                raise ValueError(msg)

            if not self._validate_key(data, self.search_key):
                msg = _('Search string is not defined, value={0}.').format(data.get(self.search_key))
                self.logger.error(msg)
                raise ValueError(msg)
        return True

    @abc.abstractmethod
    def extra_validation(self, search_schema_list, method):
        """
        This is function is inherit class what to do some thing special before saved search is being
        create or update. For example in ITSI check for service id

        @type search_schema_list: list
        @param search_schema_list: list of search schema

        @type method: basestring
        @param method: method type

        @rtype: bool
        @return: True|False of validation
        """
        return True

    @abc.abstractmethod
    def get_search_string(self, search_filter=None):
        """
        This function is being used to pass search string to get search related to only correlation search
        action.itsi_event_generator=1 is return all search which has itsi_event_generator enabled

        @rtype: basestring
        @return: search string
        """
        raise NotImplementedError(_('Not implemented'))

    @staticmethod
    def _validate_key(data, key):
        """
        Check if particular key exist and it has a valid value

        @type data: dict
        @param data: Dict against we validate key and its value

        @type key: basestring
        @param key: key to compare

        @return:
        """
        return isinstance(data, dict) and key in data and data.get(key) is not None and data.get(key) != ''

    def is_match_suffix(self, key):
        """
        Check if key starts with one or more self.field_suffix

        @type key: basestring
        @param key: key

        @rtype: bool
        @return: True|False
        """
        for suffix in self.field_suffix:
            if key.startswith(suffix):
                return True
        return False

    def filter_entity_fields(self, entity):
        """
        Filter fields set to return based upon setting defined self.field_suffix

        @type: splunk.entity object
        @param entity: Entity object

        @rtype: dict
        @return: return only fields defined in self.field_suffix and all first level fields
        """
        if not isinstance(entity, splunk.entity.Entity):
            raise TypeError(_('object is not valid splunk entity object'))
        data = {}
        for key, value in entity.iteritems():
            if key.find('.') > 0 and self.is_match_suffix(key):
                data[key] = value
            elif key.find('.') == -1:
                data[key] = value
            else:
                pass
        # Add name
        data[self.name_key] = entity.name
        # Add sid
        data[self.id_key] = entity.name
        return data

    def get(self, object_id, **kwargs):
        """
        Get single correlation search

        @type object_id: basestring
        @param object_id: saved search name

        @type kwargs: dict
        @param kwargs: extra arguments (Not Used

        @rtype: dict
        @return: Search search properties
        """
        if not object_id:
            msg = _('Search name is not valid, type={0}.').format(type(object_id))
            self.logger.error(msg)
            raise CorrelationSearchException(msg)
        entity = SavedSearch.get_search(self.session_key, object_id, self.app, self.owner)
        return self.filter_entity_fields(entity)

    def get_bulk(self, object_ids, **kwargs):
        """
        Get more than one correlation search

        @type object_ids: list
        @param object_ids: object list
            Pass None to get all correlation search

        @type kwargs: dict
        @param kwargs: extra parameters

        @rtype: list
        @return: list of correlation search
        """
        if not object_ids:
            search_string = self.get_search_string(
                search_filter=kwargs.get('filter'))
            if kwargs.get('search'):
                search_string += ' AND ' + kwargs.pop('search')

            entities = SavedSearch.get_all_searches(self.session_key, self.app, self.owner,
                                                    search=search_string,
                                                    count=kwargs.pop('count', -1), offset=kwargs.pop('offset', 0),
                                                    sort_key=kwargs.pop('sort_key', 'name'),
                                                    sort_dir=kwargs.pop('sort_dir', 'asc'))
        elif isinstance(object_ids, list):
            search_list = []
            for sid in object_ids:
                search_list.append('name="{0}"'.format(sid))
            entities = SavedSearch.get_all_searches(self.session_key, self.app, self.owner,
                                                    search=' OR '.join(search_list),
                                                    count=kwargs.pop('count', -1), offset=kwargs.pop('offset', 0),
                                                    sort_key=kwargs.pop('sort_key', 'name'),
                                                    sort_dir=kwargs.pop('sort_dir', 'asc'))
        else:
            msg = _('Invalid object list, type is {0}.').format(type(object_ids))
            self.logger.error(msg)
            raise CorrelationSearchException(msg)

        data = [self.filter_entity_fields(entity) for entity in entities]
        self.inject_object_type(data)
        return data

    def _create_search(self, data, raise_if_exist=False):
        """
        Supporting function to create search

        @type data: dict
        @param data: saved search schema in dict format

        @type raise_if_exist: bool
        @param raise_if_exist: Raise exception if search already exist

        @rtype: basestring
        @return: search name
        """
        name = data.pop(self.name_key, None)
        if not name:
            msg = _('Search name={0} is not specified.').format(name)
            self.logger.error(msg)
            raise TypeError(msg)
        is_saved = SavedSearch.update_search(self.session_key, name, self.app, self.owner, raise_if_exist=raise_if_exist, **data)
        if not is_saved:
            msg = _('Failed to save search {0}.').format(name)
            self.logger.error(msg)
            raise CorrelationSearchException(msg)
        else:
            return name

    def _create_or_update(self, data_list, method, raise_if_exist=False, is_validate=True):
        """
        Supporting function to create/update correlation search

        @type data_list: list
        @param data_list: list of saved search schema to save

        @type method: basestring
        @param method: method type

        @type raise_if_exist: bool
        @param raise_if_exist: Raise exception if search already exist

        @rtype: list
        @return: list of saved search name
        """
        if not isinstance(data_list, list):
            msg = _('Invalid data list, type={0}.').format(type(data_list))
            self.logger.error(msg)
            raise TypeError(msg)

        saved_search_names = []
        for data in data_list:
            if not is_validate:
                saved_search_names.append(self._create_search(data, raise_if_exist))
            elif is_validate and self.validation([data], method=method):
                saved_search_names.append(self._create_search(data, raise_if_exist))
            else:
                msg = _('Validation failed, for data="{0}".').format(data)
                self.logger.error(msg)
                raise CorrelationSearchException(msg)
        return saved_search_names

    @time_function_call
    def create(self, data, **kwargs):
        """
        Create saved search

        @type data: dict
        @param data: data

        @type kwargs: dict
        @param kwargs: saved search settings

        @rtype: basestring
        @return: name of saved search
        """
        raise_if_exist = kwargs.get('raise_if_exist', True) if isinstance(kwargs, dict) else True
        saved_search_names = self._create_or_update([data], MethodType.CREATE, raise_if_exist=raise_if_exist)
        return saved_search_names[0] if saved_search_names else None

    @time_function_call
    def create_bulk(self, data_list, **kwargs):
        """
        Create searches in bulk

        @type data_list: list
        @param data_list: list of savedsearch entries

        @type kwargs: dict
        @param kwargs: extra parameter (this is not being used here)

        @type: list
        @return: list of successfully saved search
        """
        return self._create_or_update(data_list, MethodType.CREATE_BULK, raise_if_exist=True)

    @time_function_call
    def update(self, object_id, data, enforce_rbac=True, is_partial_update=False, **kwargs):
        """
        Update saved search
        Note: We can't support partial update. Schema must have search and name

        @type object_id: basestring
        @param object_id: saved search sid. If name is specified in the data then object id is not being used here

        @type data: dict
        @param data: saved search to update

        @type enforce_rbac: boolean
        @param enforce_rbac: True enforces rbac on update i.e. if user does not have read access to at least 1 services, update will fail
                             False does not enforce RBAC. It is used in methods like update_service_or_kpi_in_correlation_search where
                             the correlation_search needs to be updated without rbac check when for eg a service is deleted

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update (this is not being used here)

        @type kwargs: dict (this is not being used here)
        @param kwargs: Extra parameters (this is not being used here)

        @rtype: dict
        @return: return dict which holds updated keys
        """
        # Make sure data contain name, use sid if it does not
        if isinstance(data, dict) and data.get(self.name_key):
            data[self.name_key] = object_id

        if enforce_rbac:
            if not self._can_user_update(self.current_user_name, data['name']):
                raise ItoaAccessDeniedError(
                    _('Access denied. You do not have permission to update this object.'),
                    self.logger)
        saved_search_names = self._create_or_update([data], MethodType.UPDATE)
        return saved_search_names[0] if saved_search_names else None

    @time_function_call
    def update_bulk(self, object_ids, data_list, is_partial_update=False, **kwargs):
        """
        Perform update for one or more correlation search
        Note: We can't support partial update. Schema must have search and name

        @type object_ids: list
        @param object_ids: notable events (this is not being used here)

        @type data_list: list
        @param data_list: list of saved search schema to update

        @type is_partial_update: bool
        @param is_partial_update: flag for partial update (this is not being used here)

        @type kwargs: dict
        @param kwargs: Extra params to perform (this is not being used here)

        @rtype: list
        @return: update notable event schema
        """
        return self._create_or_update(data_list, MethodType.UPDATE_BULK)

    def _delete_searches(self, search_list):
        """
        Delete provide saved searches

        @param search_list: list
        @param search_list: list of saved search names to delete

        @return: None or raise Exception
        """
        if not isinstance(search_list, list):
            msg = _('Invalid search list. Provided type={0}.').format(search_list)
            self.logger.error(msg)
            raise CorrelationSearchException(msg)
        for search in search_list:
            if not search:
                continue
            SavedSearch.delete_search(self.session_key, search, self.app, self.owner)

    @time_function_call
    def delete(self, object_id, **kwargs):
        """
        Function to delete correlation searches

        @type object_id: basestring
        @param object_id: search name

        @type kwargs: dict
        @param kwargs: extra params (this is not be being used here)

        @return: None
        """
        if not object_id:
            message = _('Invalid search name. Search name can not be empty.')
            self.logger.error(message)
            raise CorrelationSearchException(message)
        self._delete_searches([object_id])

    @time_function_call
    def delete_bulk(self, object_ids, **kwargs):
        """
        Delete correlation searches in bulk

        @type object_ids: list
        @param object_ids: list of correlation searches to delete

        @type kwargs: dict
        @param kwargs: extra params to delete, checks the filter params

        @return: None
        """
        if object_ids and len(object_ids) != 0:
            self._delete_searches(object_ids)

        elif kwargs.get('filter'):
            object_ids = []
            delete_filter = json.loads(kwargs.get('filter'))
            conditional = delete_filter.keys()[0]
            for cs in delete_filter[conditional]:
                object_ids.append(cs['name'])
            self._delete_searches(object_ids)

    def _can_user_update(self, current_user, name):
        """
        Determines if a user can update a given correlation search

        @type current_user: basestring
        @param current_user: current user

        @type name: string
        @param: name: name/id of the correlation search

        @return: Boolean
        """
        # Get the saved correlation search from mongo
        persistent_correlation_search = self.get(name)

        def _construct_filter_for_service_ids(service_ids_string):
            """
            Contructs kvstore filter from the service_ids_string

            @type service_ids_string: basestring
            @param service_ids_string: comma separated string of service_ids

            @return: dict
            """
            if len(service_ids_string) == 0:
                return {}
            service_ids_list = service_ids_string.split(',')
            if len(service_ids_list) >= 1 and len(service_ids_list[0]) > 0:
                get_bulk_filter = {'$or': []}
                for service_id in service_ids_list:
                    get_bulk_filter['$or'].append({'_key': service_id})
                return get_bulk_filter
            else:
                return {}

        # Retrieve service_ids from the persistent correlation search
        service_ids = persistent_correlation_search.get('action.itsi_event_generator.param.service_ids', None)
        if not service_ids:
            return True
        get_bulk_filter = _construct_filter_for_service_ids(service_ids)
        # Do bulk get on the Service collection with the filter of service_ids

        # If for some weird reason the current user is not a valid string, reset this to nobody to behave like enforce_rbac=off
        if not current_user:
            current_user = 'nobody'
        service_object_handle = ItsiService(self.session_key, current_user)
        fetched_services = service_object_handle.get_bulk('nobody',
                                                        filter_data=get_bulk_filter if len(get_bulk_filter) > 0 and isinstance(get_bulk_filter, dict) else None,
                                                        fields=['_key', 'title'],
                                                        req_source='CorrelationSearch Update')

        # If len(fetched_services) < len(persistent_services) => this user does not have access to at least one service
        persistent_services = list(set(service_ids.split(',')))
        persistent_services_length = len(persistent_services) if len(persistent_services) >=1 and len(persistent_services[0]) > 0 else 0
        if isinstance(fetched_services, list) and len(fetched_services) < persistent_services_length:
            return False
        else:
            return True
