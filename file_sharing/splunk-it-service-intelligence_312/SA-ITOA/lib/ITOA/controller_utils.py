#
# -*- coding: utf-8 -*-
# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
#

"""
DO NOT IMPORT THIS MODULE UNLESS YOU ARE GUARANTEED AN ACTIVE CHERRYPY SESSION

Web Controller Utilities

This module is usable only when an active CherryPy session is available to
be consumed.

It is unsuitable for consumption in Modular Inputs, Splunkd REST endpoints or
anything else outside of the appserver/controllers framework
"""

import cherrypy
import json

from numbers import Number
from copy import deepcopy

from splunk.appserver.mrsparkle.lib import i18n
from splunk.auth import getCurrentUser
from splunk.util import normalizeBoolean

import itoa_common as utils
from itoa_factory import instantiate_object
from itoa_object import CRUDMethodTypes
from itoa_exceptions import ItoaValidationError
from itoa_base_controller import ITOABaseController
from itoa_config import get_collection_name_for_itoa_object
from storage import itoa_storage, statestore
from ITOA.setup_logging import setup_logging
from itsi.event_management.event_management_services import EventManagementService
from event_management.event_management_object_manifest import object_manifest as event_management_object_manifest


logger = setup_logging("itsi.log", "itsi.controller_utils")

class ITOAError(cherrypy.HTTPError):
    """
    Set the status and msg on the response
    I.e.
    raise ITOAEntityError(status=500, message=_("Your call is very important to us ..."))
    """
    def get_error_page(self, *args, **kwargs):
        kwargs['noexname'] = 'true'
        return super(ITOAError, self).get_error_page(*args, **kwargs)

def get_session_key():
    '''
    fetches session_key from an active cherrypy session if available

    @rtype: basestring
    @return sessionkey: splunkd session key
    '''
    return cherrypy.session["sessionKey"] if hasattr(cherrypy, 'session') else None

def get_current_username():
    '''
    Get current username
    @return username: current user logged into the system
    @return type: str
    @raise AttributeError: if user is not logged into system
    '''
    current_user = getCurrentUser()
    return current_user.get('name', 'unknown') if utils.is_valid_dict(current_user) else 'unknown'

def log_message(logger, prefix, msg, level='DEBUG'):
    '''
    utility method to log a message if the class was initialized with a proper logger object
    @param logger: logger object
    @param type: logger

    @param prefix: message prefix; ususally the method name that wishes to log the message
    @param type: str

    @param msg: message to log
    @param type: str

    @param level: Expected level of logging; splunk supported (INFO, WARN, DEBUG, ERROR)
        defaults to DEBUG
    '''
    if logger is None:
        return

    level = level.strip().upper()
    if level not in ['INFO', 'WARN', 'DEBUG', 'ERROR']:
        return
    if not isinstance(msg, basestring):
        try:
            msg = str(msg)
        except Exception, exc:
            logger.exception(exc)
            return

    if prefix is None or len(prefix.strip()) == 0:
        # get caller's name - which ought to be our prefix...
        from inspect import currentframe, getouterframes
        curframe = currentframe()
        calframe = getouterframes(curframe, 2)
        prefix = calframe[1][3]

    if level == 'INFO':
        logger.info('%s %s', prefix, msg)
    elif level == 'WARN':
        logger.warning('%s %s', prefix, msg)
    elif level == 'ERROR':
        logger.error('%s %s', prefix, msg)
    else:
        logger.debug('%s %s', prefix, msg)
    return


class ObjectOperation(ITOABaseController):
    """
    An instance of this class can be used to perform CRUD operations on ITOA
    Objects from a REST request context.
    """
    IMMUTABLE_OBJECT_ERROR_MESSAGE = _('This object is provided as a template and cannot be edited. Clone the object to customize the settings.')

    def __init__(self, logger, session_key, current_user):
        self.logger = logger
        self.session_key = session_key
        self.current_user = current_user

    def instantiate_object(self, object_type):
        return instantiate_object(self.session_key, self.current_user, object_type, logger=self.logger)

    def create(self, log_prefix, owner, object_type, kwargs, raw=False):
        """
        Generic create, creates an interface to the lower storage levels and
        passes the data in through there
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; like "service", "entity", "kpi" or "saved_page"
        @param kwargs: The original kwargs passed from cherrypy - here we get the identifier and the data

        @return: json with identifier
        @rval: json string
        """
        results = None
        if object_type == 'kpi':
            data = utils.validate_json(log_prefix, kwargs.get('data'))
            # Invoke KPI upsert methods
            service_object = self.instantiate_object('service')
            results = service_object.bulk_change_kpis(
                owner,
                data.get('kpis_to_change'),
                is_create=data.get('is_create', False)
            )
        else:
            obj = self.instantiate_object(object_type)
            results = obj.create(owner, kwargs.get('data'))
        if raw:
            return results
        else:
            return self.render_json(results)

    def edit(self, log_prefix, owner, object_type, object_id, kwargs, raw=False):
        """
        Generic edit for an existing object
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_name: The name of the object; currently "servie", "entity", "kpi or "saved_page"
        @param id_: The id of the object being edited
        @param object_type: The type of the object; like "service", "entity", "kpi or "saved_page"
        @param object_id: The id of the object being edited
        @param kwargs: The original kwargs passed from cherrypy - here we get the identifier and the data

        @return: json with identifier
        @rval: json string
        """
        obj = self.instantiate_object(object_type)
        if kwargs.get('data').get('_immutable') == 1:
            raise ItoaValidationError(self.IMMUTABLE_OBJECT_ERROR_MESSAGE, self.logger)

        results = obj.update(
            owner,
            object_id,
            kwargs.get('data'),
            is_partial_data=kwargs.get('is_partial_data', False)
        )

        if raw:
            return results
        else:
            return self.render_json(results)

    def get(self, log_prefix, owner, object_type, object_id, kwargs, raw=False):
        """
        Generic get for an existing object
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; like "service", "entity", "kpi or "saved_page"
        @param kwargs: The original kwargs passed from cherrypy - here we get the identifier and the data
        @pararm id_ The identifier of object to retrieve

        @return: json of the object requested
        @rval: json string
        """
        obj = self.instantiate_object(object_type)
        if object_type in ['notable_event_aggregation_policy', 'correlation_search']:
            results = obj.get(object_id)
        else:
            results = obj.get(owner, object_id, 'REST')


        if raw:
            return results
        else:
            return self.render_json(results)

    def delete(self, log_prefix, owner, object_type, object_id, kwargs):
        """
        Generic delete for an existing object
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; like "service", "entity", "kpi or "saved_page"
        @param id_: The identifier for the object to delete
        @param kwargs: The original kwargs passed from cherrypy

        @return: status json and identifier
        @rval: None (a successful delete just returns 200)
        """
        if not utils.is_valid_str(object_id):
            message = _("Missing identifier")
            self.logger.error(log_prefix + message)
            raise ITOAError(status="400", message=message)
        obj = self.instantiate_object(object_type)
        result = obj.get(owner, object_id, 'REST')
        # if Force-Delete is not true in header and object is _immutable raise exception
        if kwargs is not None and kwargs.get('X-Force-Delete') != 'true' and \
            result is not None and result.get('_immutable') == 1:
            raise ItoaValidationError(self.IMMUTABLE_OBJECT_ERROR_MESSAGE, self.logger)
        obj.delete(owner, object_id, 'REST')

    def get_bulk(self, log_prefix, owner, object_type, kwargs, raw=False):
        self.logger.debug("GET objects=%s with owner=%s, kwargs=%s", object_type, owner, kwargs)

        if object_type == 'kpi':
            # Invoke KPI CRUD methods
            service_object = self.instantiate_object('service')
            results = service_object.bulk_get_kpis(owner, kwargs.get('kpis_to_get'))
            if raw:
                return results
            else:
                return self.render_json(results)

        # For all other object types, proceed ...
        sort_key = kwargs.get('sort_key')
        sort_dir = kwargs.get('sort_dir')
        limit = kwargs.get('count')
        skip = kwargs.get('offset')
        if limit is None and skip is None:
            # If count and offset are undefined, try limit and skip
            limit = kwargs.get('limit')
            skip = kwargs.get('skip')
        fields = kwargs.get('fields')
        filter_data = kwargs.get('filter')
        self.logger.debug("filter_data=%s", filter_data)

        try:
            if isinstance(filter_data, basestring):
                filter_data = json.loads(filter_data)
        except ValueError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "ValueError not parse filterdata=%s", filter_data)
            filter_data = None
        except TypeError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "TypeError not parse filterdata=%s", filter_data)
            filter_data = None

        # in finality, always ensure filter_data is a dict type
        filter_data = None if not isinstance(filter_data, dict) else filter_data

        try:
            if isinstance(fields, basestring):
                fields = fields.split(',')
        except ValueError, e:
            self.logger.exception(e)
            self.logger.error(log_prefix + "ValueError not parse fields=%s", fields)
            fields = None
        except TypeError, e:
            self.logger.exception(e)
            self.logger.error(log_prefix + "TypeError not parse fields=%s", fields)
            fields = None

        # in finality, always ensure fields is a list
        fields = None if not isinstance(fields, list) else fields

        self.logger.debug("Parsed parameters sort_key=%s, sort_dir=%s, filter_data=%s",
                          sort_key,
                          sort_dir,
                          filter_data)

        obj = self.instantiate_object(object_type)
        results = obj.get_bulk(
            owner,
            sort_key=sort_key,
            sort_dir=sort_dir,
            filter_data=filter_data,
            fields=fields,
            limit=limit,
            skip=skip,
            req_source='REST'
            )
        if raw:
            return results
        else:
            return self.render_json(results)

    def refresh(self, log_prefix, owner, object_type, options, raw=False):
        self.logger.debug("Refreshing objects=%s owner=%s, options=%s", object_type, owner, options)

        obj = self.instantiate_object(object_type)
        results = obj.refresh(owner, options)
        if raw:
            return results
        else:
            return self.render_json(results)

    def delete_bulk(self, log_prefix, owner, object_type, kwargs):
        '''
        Perform a bulk delete operation on the different object types
        Some special logic applies to kpis

        @param log_prefix: Logger prefix
        @type log_prefix: string

        @param owner: The method caller
        @type owner: The method owner

        @param object_type: The ITOA object type
        @type object_type: string

        @param kwargs: Optional arguments
        @type kwargs: dict
        '''
        self.logger.debug("DELETE objects=%s owner=%s, kwargs=%s", object_type, owner, kwargs)

        if object_type == 'kpi':
            # Invoke KPI CRUD methods
            obj = self.instantiate_object('service')
            obj.bulk_delete_kpis(owner, kwargs.get('kpis_to_delete'))

        # For all other object types, proceed ...
        filter_data = kwargs.get('filter')
        self.logger.debug("filter_data=%s", filter_data)
        try:
            if filter_data is not None:
                filter_data = json.loads(filter_data)

                # If X-Force-Delete header is not true, process filter_data to delete only mutable objects
                # kwargs has 'X-Force-Delete' from the headers extracted by endpoint handlers
                if kwargs.get('X-Force-Delete') != 'true':
                    # Append mutability check to filter
                    filter_data.update({'_immutable': {'$ne': 1}})

                    # Privatizable objects with RBAC checks need mutability checks in filter_string too
                    if filter_data.get('filter_string') is not None and isinstance(filter_data['filter_string'], dict):
                        filter_data['filter_string'].update({'_immutable': {'$ne': 1}})
            else:
                # If filter_data is None and X-Force-Delete Header is not true, delete only mutable objects
                if kwargs.get('X-Force-Delete') != 'true':
                    filter_data = {'_immutable': {'$ne': 1}}
        except ValueError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "ValueError not parse filterdata=%s", filter_data)
            filter_data = None
        except TypeError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "TypeError not parse filterdata=%s", filter_data)
            filter_data = None

        obj = self.instantiate_object(object_type)
        obj.delete_bulk(owner, filter_data, req_source='REST')

    def bulk_edit(self, log_prefix, owner, object_type, kwargs, raw=False):
        """
        Update interface to save changes in underlying storage interface for bulk of objects
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; like "service", "entity", "kpi" or "saved_page"
        @param kwargs: The original kwargs passed from cherrypy - here we get the identifier and the data

        @return: json with identifier
        @rval: json string
        """
        results = None
        obj = self.instantiate_object(object_type)
        is_partial_data = normalizeBoolean(kwargs.get('is_partial_data', False))
        results = obj.save_batch(
            owner,
            kwargs.get('data'),
            validate_names=True,
            method=CRUDMethodTypes.METHOD_UPDATE,
            is_partial_data=is_partial_data
        )
        if raw:
            return results
        else:
            return self.render_json(results)

    def templatize(self, owner, object_type, object_id):
        """
        Templatize an object id

        @type owner: basestring
        @param owner: namespace of this request. `nobody` vs an actual user

        @type object_type: basestring
        @param object_type: type of object. `service` or `kpi_base_search` etc.

        @type object_id: basestring
        @param object_id: identifier of the object that needs to be templatized

        @rtype: dict
        @return: templatized object
        """
        obj = self.instantiate_object(object_type)
        template = obj.templatize(owner, object_id, req_source='REST')

        return template


class Request(object):
    """
    An object of this class represents an incoming REST Request
    """
    OPERATION_READ = 'read'
    OPERATION_WRITE = 'write'
    OPERATION_DELETE = 'delete'
    EVENT_MANAGEMENT_SERVICE_OBJECTS = ['notable_event_aggregation_policy',
                                        'correlation_search']

    def get_method(self):
        """
        Returns the cherryPy request method if a session is available.
        """
        return cherrypy.request.method

    def get_operation(self, method=None):
        '''
        A method that infers the desired operation from cherrypy.request.method
        @type operation_type: str
        @return operation_type: 'read'/'write'/'delete'

        @raise AttributeError: if cherrypy isn't setup
        @raise Exception: if method isnt supported
        '''
        operation = None
        method = self.get_method() if not method else method
        if method == 'GET':
            operation = 'read'
        elif method == 'POST' or method == 'PUT':
            operation = 'write'
        elif method == 'DELETE':
            operation = 'delete'
        else:
            message = _('Unsupported operation - {0}.').format(method)
            raise Exception(message)
        return operation

    def validate(self, params, operation, logger):
        '''validate incoming request. Ensure that params consists of some
        mandatory keys & operation is valid
        @return nothing
        @raise ITOAError Response Code: 400
        '''
        log_prefix = '[Request.validate] '
        expected = ['object']
        message = _('Bad Request: Missing one/all of the keys=`%s`. Received=%s.') % (expected, params)
        for i in expected:
            if params is not None and i not in params:
                log_message(logger, log_prefix, message, level='ERROR')
                raise ITOAError(status=400, message=message)
        if not operation:
            message = _('Unsupported. Received: No operation.')
            log_message(logger, log_prefix, message, level='ERROR')
            raise ITOAError(status=400, message=message)
        log_message(logger, log_prefix, 'Valid request', 'DEBUG')

    def __init__(self, params, method, logger, session_key, current_user):
        '''
        @param params: incoming query params also includes data
        @param method: incoming request's HTTP method
        @param logger: caller's logger
        @param session_key: valid splunkd session key
        @param current_user: Current user in which to contextualize operations
        '''
        self._operation = self.get_operation(method)
        self.logger = logger
        self.current_user = current_user
        self.validate(params, self._operation, logger)
        self.session_key = session_key

        self._method = method
        # request data is all in query params
        self._qp = QueryParam(params, logger)

        if self._qp.get_object_type() in self.EVENT_MANAGEMENT_SERVICE_OBJECTS:
            self.op = EventManagementService(self.session_key)
        else:
            self.op = ObjectOperation(logger, session_key, current_user)

        if self._qp.get_object_type() == 'correlation_search':
            self.object_key = 'name'
            self.query_op = 'OR'
        else:
            self.object_key = '_key'
            self.query_op = '$or'

    def __str__(self):
        '''
        return a JSON'ified string else a dict
        '''
        try:
            return json.dumps(self.get_dict())
        except Exception:
            self.logger.exception('JSON error')
            return str(self.get_dict()) # we'll return what we have as string

    def get_query_param(self):
        """
        External callers could get query param set on request using this method

        @rtype: object
        @return: the query param configured on the request
        """
        return self._qp

    def get_object_type(self):
        """
        Get the object type from the request
        """
        return self._qp.get_object_type()

    def get_object_owner(self):
        """
        Get the owner from the request
        """
        return self._qp.get_owner()

    def get_dict(self):
        """
        Get the different query parameters and meta information surrounding the request
        """
        return {
            'query_params': self._qp.get_dict(),
            'method': self._method,
            'operation': self._operation
            }

    def is_write(self):
        '''is operation a write?
        '''
        return True if self._operation == 'write' else False

    def get_data(self):
        '''wrapper to return the data
        '''
        return self._qp.get_data()

    def get_data_as_list(self):
        '''wrapper to return data as a list
        '''
        data = self._qp.get_data()
        if isinstance(data, basestring):
            try:
                data = json.loads(data)
            except Exception:
                message = _('Bad Request: Unable to jsonify data, %s.') % data
                logger.exception(message)
                raise ITOAError(status=400, message=message)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            return data
        else:
            message = _('Expecting data to be a dict/list. Bad format %s.') % data
            raise ITOAError(status=400, message=message)

    def is_create(self):
        '''
        is the request indicating a desire to create?
        All of the following must be True:
        1. operation must be `write`
        2. ensure data does not exist in Statestore
        '''
        log_prefix = '[Request][is_create] '

        # if request is not a `write` operation, its definitely not a `create`
        # operation
        if not self.is_write():
            return False

        # if request has no object ids, its definitely a `create` operation.
        if not self.get_object_ids():
            return True

        data = self.get_data_as_list()
        self.logger.info('%s data: %s', log_prefix, str(data))
        for i in data:
            id_ = (self._qp.get_id()
                   if self._qp.has_id()
                   else i.get(self.object_key))
            object_type = self._qp.get_object_type()
            if object_type in self.EVENT_MANAGEMENT_SERVICE_OBJECTS:
                r = self.op.get(
                    self._qp.get_owner(),
                    object_type,
                    id_,
                    self._qp.get_all_params())
            else:
                r = self.op.get(
                    log_prefix,
                    self._qp.get_owner(),
                    object_type,
                    id_,
                    self._qp.get_all_params(),
                    raw=True)
            self.logger.info('%s read data: %s', log_prefix, str(r))
            if r:
                # object already exists... req is trying to update
                return False
        return True

    def is_asking_for_shared(self):
        '''Is request querying for shared objects?
        Return True if so, False otherwise
        '''
        owners = self.get_owners_in_query()
        if 'nobody' in owners:
            return True
        return False

    def is_asking_for_private(self):
        '''Is request querying for private objects?
        Return True if so, False otherwise
        '''
        owners = self.get_owners_in_query()
        if self.current_user in owners:
            return True
        return False

    def is_asking_for_all(self):
        '''Is request querying for both `shared` and `private` objects?
        Return True if so, False otherwise
        '''
        return self.is_asking_for_shared() and self.is_asking_for_private()

    def is_bulk(self):
        '''
        does request indicate a bulk operation?
        i.e. `bulk read`, `bulk write`, `bulk delete`

        Query Params are always present for Bulk Delete and Bulk Read.
        * Delete selected objects
            filter: {"shared":true,"filter_string":{"$or":[
                {"_key":"2fcb25a0-8543-465b-899a-8faa511f0b2f"},
                {"_key":"7c126174-bec2-4f74-8a66-017c2bc80432"},
                {"_key":"d2707d34-6c46-4571-a3af-cf9a3b96af97"}
                ]}}

        * Delete all objects
            filter:{"title":{"$regex":""}}

        * Read all/ Bulk read/Lister Page
            count:20
            offset:0
            sort_key:title
            sort_dir:asc
            filter:{"shared":"true"}
            _:1454956547876

        @rtype: bool
        @return: True incoming params satisfy any of the conditions
            False if otherwise
        '''
        log_prefix = '[is_bulk] '

        if (self._qp.get_object_type() == 'correlation_search'
            and (not self._qp.has_id()
                 or type(self._qp.get_id()) == list)):

            log_message(self.logger, log_prefix,
                        '`{}` implies bulk request'.format(
                            self.get_dict()), 'DEBUG')
            return True

        if all([
                not self._qp.has_id(),
                any([
                    self._qp.has_valid_filter(),
                    self._qp.has_valid_count(),
                    self._qp.has_valid_offset(),
                    self._qp.has_valid_sort_key(),
                    self._qp.has_valid_sort_dir()
                    ])
             ]):
            log_message(self.logger, log_prefix, '`{}` implies bulk request'.format(
                self.get_dict()), 'DEBUG')
            return True
        log_message(self.logger, log_prefix, '`{}` does not imply bulk request'.format(
            self.get_dict()), 'DEBUG')
        return False

    def get_owners_in_query(self):
        '''
        if query params has any `_owner` based query,
            return a list of owners for whom a query string might have been
            constructed
                in the following query params we need a list of all `_owner` values
                {...
                    'filter': '{
                        "$or": [{"_owner": "nobody"}, {"_owner": "admin"}], "is_named": true
                        }',
                ...}
        else return []
        '''
        try:
            return self.owners_in_query
        except AttributeError:
            self.owners_in_query = []
            if self.has_owners_in_query():
                self.owners_in_query = self._qp.get_all_values_in_filter(key='_owner')
            return self.owners_in_query

    def get_object_ids(self):
        '''
        if request deals with *an* id, return it as a list,
        else, return a list of object ids for our filter.
        '''
        log_prefix = '[get_object_ids] '
        if self._qp.has_id():
            self.logger.info('%s id: %s', log_prefix, self._qp.get_id())
            if isinstance(self._qp.get_id(), list):
                return self._qp.get_id()
            return [self._qp.get_id()]
        object_ids = self._qp.get_all_values_in_filter(key=self.object_key)
        self.logger.info('%s ids: %s', log_prefix, object_ids)
        return object_ids

    def has_owners_in_query(self):
        '''check if our filter string has any _owner based query
        '''
        return self._qp.has_value_in_filter(key='_owner')

    def has_object_ids(self):
        '''
        check if we have an id or
        our filter string has any object ids as part of the query
        return True if it does. False if otherwise
        '''
        return any([
            self._qp.has_id(),
            self._qp.has_value_in_filter(key=self.object_key)])

    def has_regex(self):
        '''check if our filter string has any regexes as part of the query
        return True if it does. False if otherwise
        '''
        return self._qp.has_value_in_filter(key='$regex')

    def get_query(self):
        return self._qp.get_filter()

    def reset_query(self, key=None, val_type=list):
        '''reset the query in request
        @type key: str
        @param key: key to initialize the reset query to
        @type val_type: value to initialize with
        @return nothing
        '''
        if key:
            self._qp.reset_filter({key: val_type()})
        else:
            self._qp.reset_filter({self.query_op: val_type()})

    def update_owners_in_query(self, owners):
        '''given a list of owners, update the owner field in query
        @type owners: list
        @param owners: owners to update query with
        @return nothing
        '''
        if not isinstance(owners, list):
            owners = [owners]
        self._qp.update_filter(
            owners, generate=False, query_op=self.query_op,
            query_opkey='_owner')

    def update_keys_in_query(self, keys):
        '''given a list of keys, update the key field in query.
        @type keys: list
        @param keys: keys to update query with
        @return nothing
        '''
        if not isinstance(keys, list):
            keys = [keys]
        self._qp.update_filter(
            keys, generate=False, query_op=self.query_op, key=self.object_key)

    def update_object_id(self, id_):
        '''update requested object id with given
        @param id_: str to update id with
        '''
        self._qp.set_id(id_)


class QueryParam(object):
    '''
    A class to represent query params that an incoming request may have
    '''
    def __init__(self, kwargs, logger):
        '''
        @type kwargs: dict
        @param kwargs: incoming query params

        @type logger: logger
        @param logger: caller's logger
        '''
        self._all_params = kwargs if kwargs else {}
        try:
            self._filter = (json.loads(kwargs.get('filter'))
                            or json.loads(kwargs.get('filter_data')))
        except TypeError:  # received a dictionary
            self._filter = kwargs.get('filter') or kwargs.get('filter_data')
        except ValueError:  # empty string most likely
            self._filter = {}

        self.__ = kwargs.get('_')
        self._object_type = kwargs.get('object')
        self._owner = kwargs.get('owner')
        self._count = kwargs.get('count')
        self._offset = kwargs.get('offset')
        self._sort_key = kwargs.get('sort_key')
        self._sort_dir = kwargs.get('sort_dir')
        self._data = kwargs.get('data')
        self._id = kwargs.get('id_') or kwargs.get('ids')
        if type(self._id) in (str, unicode) and '[' in self._id:
            self._id = json.loads(self._id)
        self.logger = logger

    def __str__(self):
        try:
            return json.dumps(self.get_dict())
        except Exception:
            logger.exception('Controller Utils JSON Error')
            return self.get_dict()  # we'll return what we have

    def has_data(self):
        '''return True if queryparams has data
        '''
        return True if self._data else False

    def get_data(self):
        '''getter to return data from query params
        '''
        return self._data

    def has_id(self):
        '''return True if queryparams deals with *an* object
        '''
        return True if self._id else False

    def get_id(self):
        '''return object id
        '''
        return self._id

    def set_id(self, id_):
        '''set _id with given
        @param id_: str to update _id with
        '''
        self._id = id_

    def is_valid(self):
        '''Return True if object is a dict of non-zero length. False otherwise
        No individual member validations here...
        '''
        return True if (isinstance(self._all_params, dict)
                        and self._all_params) else False

    def get_dict(self):
        '''
        get a consumable dict of what exists
        '''
        return {'_': self.__,
                'object': self._object_type,
                'owner': self._owner,
                'count': self._count,
                'offset': self._offset,
                'sort_key': self._sort_key,
                'sort_dir': self._sort_dir,
                'filter': self._filter,
                'id_': self._id,
                'data': self._data}

    def get_all_params(self):
        '''Get all of the params
        '''
        return self._all_params

    def has_valid_object_type(self):
        '''Return True if object_type is a valid string, else False
        '''
        return True if (isinstance(self._object_type, basestring)
                        and self._object_type.strip()) else False

    def set_object_type(self, otype):
        self._object_type = otype

    def get_object_type(self):
        return self._object_type

    def has_valid_owner(self):
        '''Return True if owner is a valid str, else False
        '''
        return True if (isinstance(self._owner, basestring)
                        and self._owner.strip()) else False

    def set_owner(self, owner):
        self._owner = owner

    def get_owner(self):
        return self._owner

    def has_valid_filter(self):
        '''
        return True if filter is valid, False if otherwise
        '''
        return False if not isinstance(self._filter, dict) else True

    def reset_filter(self, new_filter={}):
        self._filter = new_filter

    def update_filter(self, values, generate=True, query_op='$or', key='_key'):
        '''
        Update existing `filter`. if `filter` has a `filter_string`, update it
        Else, update `filter`
        1. if generate is True, using `values`, generate a filter string
        2. if generate is False, use `values` and append to existing
        @param values: list; values to update filter with
        @param generate: bool; True implies generate new filter
        @param query_op: str; $or/$and and so on
        @param key: str; key to update filter
        '''
        # current query params lacks a filter..create one
        if not self._filter:
            self._filter = {query_op: []}

        if generate:
            to_change = {"{0}".format(query_op): [{key: i} for i in values]}
        else:
            # append to what we already have
            if self._filter.get('filter_string'):
                to_change = deepcopy(self._filter['filter_string'])
            else:
                to_change = deepcopy(self._filter)
            val = to_change.get(query_op)
            for i in values:
                val.append({key: i})

        if self._filter.get('filter_string'):
            self._filter['filter_string'] = to_change
        else:
            self._filter = to_change

    def get_filter(self, stringify=True):
        '''
        get the filter; defaults to string
        @type stringify: bool
        @param stringify: True implies, caller wants a stringified version;
            False implies otherwise
        '''
        if stringify is True:
            return json.dumps(self._filter)
        return self._filter

    def has_valid_count(self):
        '''Return True if count is a valid number
        '''
        return True if isinstance(self._count, Number) else False

    def get_count(self):
        return self._count

    def has_valid_offset(self):
        '''Return True if offset is a valid number
        '''
        return True if isinstance(self._offset, Number) else False

    def get_offset(self):
        return self._offset

    def has_valid_sort_key(self):
        '''Return True if sort_key is a valid non-zero length string
        '''
        return True if (isinstance(self._sort_key, basestring) and \
                self._sort_key) else False

    def get_sort_key(self):
        return self._sort_key

    def has_valid_sort_dir(self):
        return True if (isinstance(self._sort_dir, basestring) and \
                self._sort_dir) else False

    def get_sort_dir(self):
        return self._sort_dir

    def get_filter_string(self):
        return self._filter.get('filter_string') if self._filter else None

    def get_all_values_in_filter(self, key, filter_=None, values=None):
        '''return a list of values for given filter.
        implemented recursively here because values can be pretty much at any
        level in our filter. ex: "_key" or "_owner"
        @param key: `key` whose values we care about. Ex: _key, _owner etc...
        @param filter_: filter to work with. Pass nothing to work with
            initialized value
        @param values: pass nothing to it. used for recursive purposes.
        '''
        FILTER = 'filter_string'
        try:
            if self._recursing:
                pass
        except AttributeError:
            values = []
            self._recursing = True

        if values is None:
            values = []

        values_ = deepcopy(values)
        recurse = self.get_all_values_in_filter

        filter_ = self._filter if not filter_ else filter_
        if isinstance(filter_, basestring):
            try:
                filter_ = json.loads(filter_)
            except ValueError:
                return values_

        if not isinstance(filter_, dict) and not isinstance(filter_, list):
            return values_

        # always work with value of FILTER
        if FILTER in filter_:
            filter_ = filter_[FILTER]

        if not isinstance(filter_, dict):
            return values_

        if key in filter_:
            values_.append(filter_[key])

        for val in filter_.values():
            if isinstance(val, dict):
                val = [val]
            if isinstance(val, list):
                for attribute in val:
                    if isinstance(attribute, dict):
                        values_ += recurse(key, attribute, values=values_)
        values_ = list(set(values_))
        return values_

    def has_value_in_filter(self, key, filter_=None):
        '''check if our filter has anything to do with provided key
        return True if it does. False if otherwise
        '''
        FILTER = 'filter_string'
        recurse = self.has_value_in_filter
        has_value = False

        if not filter_ and not self._filter:
            return False

        filter_ = self._filter if not filter_ else filter_

        if isinstance(filter_, basestring):
            try:
                filter_ = json.loads(filter_)
            except ValueError:
                return has_value

        # always work with value of `filter_string`
        if FILTER in filter_:
            filter_ = filter_[FILTER]

        if not isinstance(filter_, dict):
            return False
        if key in filter_:
            return True

        for val in filter_.values():
            if isinstance(val, dict):
                val = [val]
            if isinstance(val, list):
                for i in val:
                    if isinstance(i, dict):
                        return recurse(key, i)
        return has_value


#################
# Decorators
#################

class NormalizeRESTRequestForSharedObjects(object):
    '''
    Decorator to normalize incoming endpoint request
    Applicable only when:
    - object is glass_table or deep_dive
    - incoming requests to a controller endpoint being decorated has the 'owner' field
    Decorator will change the 'owner' to what is specified in new_owner; defaults to 'nobody'
    '''
    def __init__(self, logger, new_owner='nobody'):
        '''
        The init method
        @param self: the self param
        @param type: object

        @param logger: caller's logger object
        @param type: logger object

        @param new_owner: string indicating new owner
        @param type: string
        '''
        self.new_owner = new_owner
        self.logger = logger
        self.shared_objects = utils.get_privatizeable_object_types()

    @staticmethod
    def is_true(var):
        '''
        utility method to check if value of var implies true
        @param var: the variable under question
        @param type: string, bool, number types
        @return False by default, True if it matches criteria
        '''
        is_true = False
        if isinstance(var, basestring):
            if var.strip().lower() == 'true' or var.strip().lower().startswith('yes'):
                is_true = True
        elif isinstance(var, bool):
            is_true = var
        elif isinstance(var, (int, float, complex, long)):
            if int(var) > 0:
                is_true = True
        return is_true

    def __call__(self, func):
        '''
        The call method which is invoked for actual decoration
        @param self: the self param
        @param type: object
        @param f: function object being decorated
        '''
        def wrapper(*args, **kwargs):
            '''
            actual decorator.
            Applicable only to object types deep_dive and glass_table
            @param args: arguments passed to the decorator
            @param kwargs: key value args passed to the decorator
                do stuff iff:
                - there is an 'owner' and 'object' in kwargs.
                - 'object' is either 'glass_table' or 'deep_dive'
                normalize 'owner' to 'nobody'
            '''
            log_prefix = '[NormalizeRESTRequestForSharedObjects.__call__.wrapper] '

            object_type = kwargs.get('object')
            owner = kwargs.get('owner')
            filter_data = kwargs.get('filter')
            method = cherrypy.request.method

            if filter_data:
                filter_data = json.loads(filter_data)

            if owner and object_type in self.shared_objects:
                log_message(self.logger, log_prefix, 'Beginning normalization of incoming request', 'INFO')
                log_message(self.logger, log_prefix, 'kwargs - {}'.format(json.dumps(kwargs)))
                
                # this is the most important change, contexts are always re-written.
                kwargs['owner'] = self.new_owner


                if method == 'GET' and filter_data:
                    is_shared = NormalizeRESTRequestForSharedObjects.is_true(filter_data.get('shared'))
                    if is_shared:
                        if owner == 'nobody':
                            log_message(self.logger, log_prefix, 'owned by "nobody" requested')
                            filter_data['_owner'] = 'nobody'
                        else:
                            log_message(self.logger, log_prefix, 'owned by "nobody" + owned by "{}" requested'.format(owner))
                            filter_data['$or'] = [{'_owner':'nobody'}, {'_owner':owner}]
                    else:
                        log_message(self.logger, log_prefix, 'owned by "{}" requested'.format(owner))
                        filter_data['_owner'] = owner
                    filter_data.pop('shared', None) # useless hereon - not sent when creating
                    kwargs['filter'] = json.dumps(filter_data)
                log_message(self.logger, log_prefix, 'Normalization of incoming request complete', 'INFO')
                log_message(self.logger, log_prefix, 'New kwargs - {}'.format(json.dumps(kwargs)))
            else:
                msg = _('Normalization not applicable for this req. Applicable to req with owner and for object_types \
                    {}. Received object_type "{}".').format(str(self.shared_objects), object_type)
                log_message(self.logger, log_prefix, msg)
            return func(*args, **kwargs)
        return wrapper

def handle_json_in(func):
    """
    Decorator to handle application/json content type

    no-op if content type is not application/json, else
    convert json to a dict and put that dict in the kwargs
    data argument.
    """
    def wrapper(*args, **kwargs):
        if 'application/json' in cherrypy.request.headers.get('Content-Type', ''):
            contentlength = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(contentlength))
            passed_json = json.loads(rawbody)
            if 'data' not in kwargs:
                kwargs.update({'data': passed_json})
            else:
                kwargs.update(passed_json)
        return func(*args, **kwargs)
    return wrapper

def handle_json_in_splunkd (f) :
    """
    Decorator to handle application/json content type for splunkd
    rest endpoints

    no-op if content type is not application/json, else
    convert json to a dict and put that dict in the kwargs
    data argument.
    """
    def wrapper (self, *args, **kwargs) :
        if 'content-type' in self.request['headers'] and \
                'application/json' in self.request['headers']['content-type']:
            parsed_json = json.loads (self.request['payload'])

            if isinstance (parsed_json, list) :
                self.args.update ( { 'data' : parsed_json } )
            else :
                self.args.update (parsed_json)

        return f (self, *args, **kwargs)
    return wrapper

def load_validate_json(json_data):
    '''
    Quick and dirty parsing/json validation,
    Here as a method because I was doing it everywhere

    @return: Parsed json dict/list (or unaltered dict if it was a dict originally)
    @rval: dict or list parsed json
    '''
    if json_data == None:
        message = _("Missing json_data")
        raise ITOAError(status="400", message=message)
    elif isinstance(json_data, dict):
        return json_data
    try:
        data = json.loads(json_data)
    except TypeError:
        message = _("Unable to parse expected json data {0}").format(json_data)
        logger.exception(message)
        raise ITOAError(status="400", message=message)
    return data

def get_storage_interface(object_type=None):
    """
    Method to obtain a storage interface object for a given object type to work on
    @param self: The self reference
    @param object_type: ITOA Object type
        (service/entity/kpi/glass_table etc...)
    @param type: string
    @return storage_interface: itoa_storage instance initialized to appropriate collection
    """
    collection = get_collection_name_for_itoa_object(object_type)
    init_params = {}
    if collection:
        init_params['collection'] = collection
    return itoa_storage.ITOAStorage(**init_params)

def check_object_update_allowed(session_key, logger):
    """
    Used by ITOA interface to check if update operation can proceed
    It throws a 400 exception if backup/restore jobs are in progress, else lets operation continue

    @type session_key: basestring
    @param session_key: Session key under which call is being served in ITOA interface

    @type: object
    @param logger: logger to use

    @rtype: None
    @return: Nothing, throws 405 if backup/restore jobs are in progress
    """
    backup_restore_instance = instantiate_object(session_key, 'nobody', 'backup_restore', logger)
    jobs_in_progress = backup_restore_instance.get_bulk('nobody',
                                                        filter_data={'status': 'In Progress'},
                                                        limit=1)

    if isinstance(jobs_in_progress, list) and len(jobs_in_progress) > 0:
        message = _('Backup/restore jobs are in progress. Configuration '
            'changes are not allowed while backup/restore jobs are in progress')
        logger.error(message)
        raise ITOAError(status=405, message=message)
