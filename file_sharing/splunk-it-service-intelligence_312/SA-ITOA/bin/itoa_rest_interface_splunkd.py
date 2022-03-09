# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json
import operator

from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ITOAError, ItoaValidationError
from ITOA.rest_interface_provider_base import SplunkdRestInterfaceBase

from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import (
    ItoaInterfaceProvider,
    get_supported_itoa_object_types,
    get_interactable_object_types,
    get_privatizeable_object_types
)
from itsi.access_control.splunkd_controller_rbac_utils import EnforceRBACSplunkd
from itsi.itsi_utils import CAPABILITY_MATRIX
from itsi.itsi_utils import ITOAInterfaceUtils

logger = setup_logging("itsi.log", "itsi.rest_handler_splunkd.itoa_interface")
logger.debug("Initialized ITOA REST splunkd handler interface log")

def NormalizeRESTRequestForSharedObjects(function):
    """
    Decorator for shared object types
    Applicable only to object types deep_dive and glass_table

    This decorator is custom built for ItoaRestInterfaceProviderSplunkd and makes assumptions about
    methods/attributes from the class

    @param args: arguments passed to the decorator
    @param kwargs: key value args passed to the decorator
        do stuff iff:
        - there is an 'owner' and 'object' in kwargs.
        - 'object' is either 'glass_table' or 'deep_dive'
        normalize 'owner' to 'nobody'
    """
    def wrapper(self, *args, **kwargs):
        def is_true(var):
            """
            utility method to check if value of var implies true

            @type: boolean
            @param var: the variable under question

            @type: variable
            @param type: string, bool, number types

            @rtype: boolean
            @return False by default, True if it matches criteria
            """
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

        log_prefix = '[NormalizeRESTRequestForSharedObjects.wrapper]'

        owner = args[0]
        object_type = args[1]
        filter_data = kwargs.get('filter')

        if filter_data:
            filter_data = json.loads(filter_data)

        new_owner = owner
        if owner is not None and object_type in get_privatizeable_object_types():
            new_owner = 'nobody'
            if self._rest_method == 'GET' and filter_data is not None:
                is_shared = is_true(filter_data.get('shared'))
                if is_shared:
                    if owner == 'nobody':
                        filter_data['_owner'] = 'nobody'
                    else:
                        filter_data['$or'] = [{'_owner': 'nobody'}, {'_owner': owner}]
                else:
                    filter_data['_owner'] = owner
                filter_data.pop('shared', None) # useless here on - not sent when creating
                kwargs['filter'] = json.dumps(filter_data)
        new_args = (new_owner,) + args[1:]

        return function(self, *new_args, **kwargs)
    return wrapper

class ItoaRestInterfaceProviderSplunkd(ItoaInterfaceProvider):
    """
    This wrapper class for the REST provider in ItoaInterfaceProvider which
    handles all access check decorators and passes on to provider to serve
    rest of the request
    """
    def __init__(self, session_key, current_user, rest_method):
        """
        The decorator invoked wrapper for the decorated function (REST handler)
        This wrapper does the access check on the REST request and throws an exception if access is denied

        @type: string
        @param session_key: the splunkd session key for the request

        @type: string
        @param current_user: current user invoking the request

        @type: string
        @param: type of REST method of this request, GET/PUT/POST/DELETE
        """
        self._setup(session_key, current_user, rest_method)

    def get_supported_object_types(self):
        """
        Method to get supported ITOA object for this interface

        @type: object
        @param self: the self reference

        @rtype: json
        @return: json of the supported objects list
        """
        return self.get_supported_object_types_json()

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def load_csv(self, owner, **kwargs):
        """
        Method to perform bulk import of CSV data

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the updated objects list
        """
        return self._bulk_csv_import(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd(is_bulk_op=True)
    def bulk_update(self, owner, object_type, **kwargs):
        """
        Method to perform bulk updates on objects

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: result of the update
        """
        return self._bulk_update(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd(is_bulk_op=True)
    def bulk_entities_update(self, owner, object_type, **kwargs):
        """
        Method to bulk update entity fields

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: result of the update
        """
        return self._bulk_entities_update(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def generate_entity_filter(self, owner, **kwargs):
        """
        Endpoint which can be used to generate  an entity filter that is
        consumable by KPI search strings. A nice thing about this endpoint is
        that it can be invoked within a Splunk search command using "| rest".
        The purpose of this endpoint is to generate entity filters on the fly
        at search time. This is acheived by invoking this endpoint from within a subsearch.
        For more, see ITOA-5990.

        @type owner: basestring
        @param owner: string indicating owner of this call.

        @type kwargs: dict
        @param kwargs: parameters; query params that are sent as part of request
            Mandatory keys:
                @type service_id: basestring
                @param service_id: identifier of the service that this KPI belongs to
            Other keys:
                @type entity_id_fields: basestring
                @param entity_id_fields: comma separated entity identifier fields as defined in KPI

                @type entity_alias_filtering_fields: basestring
                @param entity_alias_filtering_fields: comma separated entity alias fields for
                    filtering as defined in KPI

        @rtype: basestring
        @return entity filter
        """
        logger.debug('Input args=%s', json.dumps(kwargs))
        return self._generate_entity_filter(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_kpi_searches(self, owner, **kwargs):
        """
        Method to generate KPI searches

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the generated search
        """
        return self._get_kpi_searches(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='glass_table', logger=logger)
    def get_kpi_searches_gt(self, owner, **kwargs):
        """
        Method to generate KPI searches for data models in glass table ad hoc widgets

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the generated search
        """
        return self._get_kpi_searches(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_search_clause(self, owner, **kwargs):
        """
        Method to generate search clauses for KPI search construction

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the generated search clauses
        """
        return self._get_search_clause(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def preview_merge(self, owner, **kwargs):
        """
        Method to generate preview results of bulk CSV import

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the previewed objects
        """
        return self._preview_merge(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_alias_list(self, owner, **kwargs):
        """
        Method to get alias list

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the aliases
        """
        return self._get_alias_list(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_backfill_search(self, owner, **kwargs):
        """
        Method to generate backfill searches

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the generated searches
        """
        return self._get_backfill_search(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_entity_filter(self, owner, **kwargs):
        """
        Method to get entity filters

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the entity filters
        """
        if kwargs.get('is_get_count', False):
            return self._get_entity_filter_count(owner, **kwargs)
        else:
            return self._get_entity_filter(owner, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='rbac', logger=logger)
    def object_permissions(self, owner, object_type, **kwargs):
        """
        Method to get/set object permissions

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results
        """
        return self._perms(object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='rbac', logger=logger)
    def object_permissions_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Method to get/set object permissions on specific object

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of permissions processing
        """
        return self._perms_by_id(object_type, object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd(is_bulk_op=True)
    def bulk_crud(self, owner, object_type, **kwargs):
        """
        Routes CRUD operations on objects

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the REST method results
        """
        if self._rest_method == 'GET':
            return self._get_bulk(owner, object_type, **kwargs)
        elif self._rest_method in ['PUT', 'POST']:
            logger.debug("Calling create method")
            return self._create_or_update(owner, object_type, **kwargs)
        elif self._rest_method == 'DELETE':
            self._delete_bulk(owner, object_type, **kwargs)
        else:
            raise ITOAError(status="500", message=_("Unsupported HTTP method %s.") % self._rest_method)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd()
    def crud_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Routes CRUD operations per object

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the REST method
        """
        if self._rest_method == 'GET':
            return self._get_by_id(owner, object_type, object_id, **kwargs)
        elif self._rest_method in ['PUT', 'POST']:
            return self._update_by_id(owner, object_type, object_id, **kwargs)
        elif self._rest_method == 'DELETE':
            return self._delete_by_id(owner, object_type, object_id, **kwargs)
        else:
            raise ITOAError(status="500", message=_("Unsupported HTTP method %s.") % self._rest_method)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd(is_bulk_op=True)
    def refresh_objects(self, owner, object_type, **kwargs):
        """
        Refreshes objects in bulk

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of refresh
        """
        return self._refresh_object(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd()
    def refresh_object_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Refreshes specific objects

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the refresh
        """
        return self._object_refresh_by_id(owner, object_type, object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd()
    def link_template_to_service(self, owner, object_type, object_id, **kwargs):
        """
        Get service template id from service /
        Link a single service to a service template

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the refresh
        """
        return self._link_template_to_service(owner, object_type, object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd(is_bulk_op=True)
    def get_objects_count(self, owner, object_type, **kwargs):
        """
        Gets count of objects with filters applied

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._get_object_count(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd()
    def templatize_object_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Templatizes given object

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the templatized objects
        """
        return self._templatize_object_by_id(owner, object_type, object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects
    @EnforceRBACSplunkd()
    def get_neighbors(self, owner, object_type, **kwargs):
        """
        Get related entity relationships for a given entity within given levels

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the REST method
        """
        return self._get_neighbors(owner, object_type, **kwargs)

    def get_rest_request_info(self, args, kwargs):
        """
        Invoked by access check (CheckUserAccess decorator) in SA-UserAccess
        to get splunkd request specific information

        @type: object
        @param self: the self reference

        @type: tuple
        @param args: args of the decorated REST handler function being processed

        @type: dict
        @param kwargs: kwargs of the decorated REST handler function being processed

        @rtype: tuple
        @return: tuple containing (user, session_key, object_type, operation, owner) for this request
        """
        owner = args[0] if len(args) > 0 else None
        object_type = args[1] if len(args) > 1 else None

        session_key = self._session_key
        user = self._current_user
        method = self._rest_method

        if method == 'GET':
            operation = 'read'
        elif method in ['POST', 'PUT']:
            operation = 'write'
        elif method == 'DELETE':
            operation = 'delete'
        else:
            message = _('Unsupported operation - {0}').format(method)
            raise Exception(message)

        return user, session_key, object_type, operation, owner

class ItoaRestInterfaceSplunkd(PersistentServerConnectionApplication, SplunkdRestInterfaceBase):
    """
    Class implementation for REST handler providing services for ITOA interface endpoints.
    """

    # Names of APIs of the form:
    # /itoa_interface/load_csv/
    _simple_helper_api_names = [
        'load_csv',
        'generate_entity_filter',
        'get_kpi_searches',
        'get_kpi_searches_gt',
        'get_search_clause',
        'preview_merge',
        'get_alias_list',
        'get_backfill_search',
        'get_entity_filter'
    ]

    def __init__(self, command_line, command_arg):
        """
        Basic constructor

        @type: string
        @param command_line: command line invoked for handler

        @type: string
        @param command_arg: args for invoked command line for handler
        """
        super(ItoaRestInterfaceSplunkd, self).__init__()

    def handle(self, args):
        """
        Blanket handler for all REST calls on the interface routing the GET/POST/PUT/DELETE requests.
        Derived implementation from PersistentServerConnectionApplication.

        @type args: json
        @param args: a JSON string representing a dictionary of arguments to the REST call.

        @rtype: json
        @return: a valid REST response
        """
        return self._default_handle(args)


    def _dispatch_to_provider(self, args):
        """
        Parses the REST path on the interface to help route to respective handlers
        This handler's think layer parses the paths and routes actual handling for the call
        to ItoaRestInterfaceProviderSplunkd

        @type: dict
        @param args: the args routed for the REST method

        @rtype: dict
        @return: results of the REST method
        """
        if not isinstance(args, dict):
            message = _('Invalid REST args received by ITOA interface - {}').format(args)
            raise ItoaValidationError(message=message, logger=logger)

        session_key = args['session']['authtoken']
        current_user = args['session']['user']
        rest_method = args['method']

        rest_method_args = {}

        SplunkdRestInterfaceBase.extract_rest_args(args, 'query', rest_method_args)

        SplunkdRestInterfaceBase.extract_force_delete_header(args, rest_method_args)

        rest_method_args.update(SplunkdRestInterfaceBase.extract_data_payload(args))

        interface_provider = ItoaRestInterfaceProviderSplunkd(session_key, current_user, rest_method)

        rest_path = args['rest_path']
        if not isinstance(rest_path, basestring):
            message = _('Invalid REST path received by ITOA interface - {}').format(rest_path)
            raise ItoaValidationError(message=message, logger=logger)

        # Double check this is ITOA interface path
        path_parts = rest_path.strip().strip('/').split('/')
        if (not isinstance(path_parts, list)) or (len(path_parts) < 2) or (path_parts[0] != 'itoa_interface'):
            raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))
        path_parts.pop(0)

        # Version check the API. It should be in the second part of URL if specified. Samples:
        # /itoa_interface/vLatest/... where vLatest implies latest ITSI version
        # /itoa_interface/<Latest ITSI version>/...
        # Currently only latest version of ITSI is supported for all APIs
        if len(path_parts) < 1:
            raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))

        if path_parts[0] in ['vLatest', 'v' + ITOAInterfaceUtils.get_app_version(session_key, app='itsi')]:
            path_parts.pop(0)

        if len(path_parts) < 1:
            raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))

        first_path_part = path_parts[0]

        # First check for helper methods which would occur as the first term in the path

        if first_path_part == 'get_supported_object_types' and len(path_parts) == 1:
            return interface_provider.get_supported_object_types()

        owner = self.extract_request_owner(args, rest_method_args)

        if first_path_part in self._simple_helper_api_names:
            if len(path_parts) == 2 and first_path_part == 'get_entity_filter' and path_parts[1] == 'count':
                rest_method_args['is_get_count'] = True
            elif len(path_parts) != 1:
                raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))
            if callable(getattr(interface_provider, first_path_part, None)):
                return operator.methodcaller(first_path_part, owner, **rest_method_args)(interface_provider)

        # Handle if this is a permissions path
        if first_path_part in get_interactable_object_types():
            if len(path_parts) == 2 and path_parts[1] == 'perms':
                return interface_provider.object_permissions(owner, first_path_part, **rest_method_args)
            elif len(path_parts) == 3 and path_parts[2] == 'perms':
                return interface_provider.object_permissions_by_id(
                    owner,
                    first_path_part,
                    path_parts[1],
                    **rest_method_args
                )

        # If no takers so far, it must be an object CRUD path
        if first_path_part in get_supported_itoa_object_types():
            object_type = first_path_part
            if len(path_parts) == 1:
                return interface_provider.bulk_crud(owner, object_type, **rest_method_args)
            elif len(path_parts) == 2:
                if path_parts[1] == 'refresh':
                    return interface_provider.refresh_objects(owner, object_type, **rest_method_args)
                elif path_parts[1] == 'count':
                    return interface_provider.get_objects_count(owner, object_type, **rest_method_args)
                elif path_parts[1] == 'bulk_update':
                    return interface_provider.bulk_update(owner, object_type, **rest_method_args)
                elif path_parts[1] == 'bulk_entities_update':
                    return interface_provider.bulk_entities_update(owner, object_type, **rest_method_args)
                elif path_parts[1] == 'get_neighbors':
                    return interface_provider.get_neighbors(owner, object_type, **rest_method_args)
                else:
                    # Path is for object CRUD by id
                    object_id = path_parts[1]
                    return interface_provider.crud_by_id(owner, object_type, object_id, **rest_method_args)
            elif len(path_parts) == 3:
                if path_parts[2] == 'refresh':
                    return interface_provider.refresh_object_by_id(owner, object_type, path_parts[1], **rest_method_args)
                elif path_parts[2] == 'templatize':
                    return interface_provider.templatize_object_by_id(owner, object_type, path_parts[1], **rest_method_args)
                elif path_parts[2] == 'base_service_template':
                    return interface_provider.link_template_to_service(owner, object_type, path_parts[1], **rest_method_args)

        # No takers so far implies REST path is crazy, error out
        raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))
