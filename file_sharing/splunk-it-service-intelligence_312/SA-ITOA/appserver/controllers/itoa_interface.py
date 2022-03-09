# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Exposes Cherrypy/Splunkweb endpoints that do basic CRUD on most ITSI objects
"""

import sys
import json

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.auth import getCurrentUser

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import (
    NormalizeRESTRequestForSharedObjects,
    handle_json_in,
    ITOAError
)
from itsi.access_control.access_control_controller_utils import EnforceRBAC
from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import ItoaInterfaceProvider

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess, UserAccess

logger = setup_logging("itsi.log", "itsi.controllers.itoa_interface")
logger.debug("Initialized ITOA interface log")

# Multi-inheritance prevents the custom controller grafting from intermittently failing with multiple controllers in the app
class itoa_interface(ITOABaseController, controllers.BaseController, ItoaInterfaceProvider):
    """
    ITOAInterface does the CRUD for entities, interfaces with the backend
    and puts stuff in places
    """
    def _setup_provider(self):
        self._setup(cherrypy.session['sessionKey'], getCurrentUser()['name'], cherrypy.request.method)


###############################################################################
# Basic CRUD routing
###############################################################################
    @route('/:object/:action=perms')
    @expose_page(must_login=True, methods=['POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='rbac', logger=logger)
    def perms(self, object, action, **kwargs):
        """
        invoke this endpoint to update permissions on a bunch of object ids
        Only users with the appropriate capability will be able to do this.

        @type action: string
        @param action: route name registered with cherrypy

        @type kwargs: dictionary
        @params kwargs: object ids and permissions for these objects
            Mandatory keys: objects, acl
                     types: list, dict

        @rtype: json
        @returns json data on success
        @raises ITOAError on failure
        """
        if action != 'perms':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "perms".') % action)

        self._setup_provider()
        return self._perms(object, **kwargs)

    @route('/:object/:id_/:action=perms')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='rbac', logger=logger)
    def perms_by_id(self, object, id_, action, **kwargs):
        """
        invoke this endpoint to fetch/update permissions on objects.
        Only users with an `admin` role will be able to do stuff.

        @type action: string
        @param actin: route name registered with cherrypy

        @type kwargs: dictionary
        @param kwargs: permissions for an object or list of objects

        @returns json data on success
        @raises ITOAError on failure
        """
        if action != 'perms':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "perms".') % action)

        self._setup_provider()
        return self._perms_by_id(object, id_, **kwargs)

    @route('/:action=get_supported_object_types')
    @expose_page(must_login=True,methods=['GET'])
    def get_supported_object_types(self, action) :
        """
        An app or an SA might want to query the supported object types
        Return a list of supported object types
        No Access Control enforcement on this endpoint...
        @param self: The self reference
        @return: an array of supported object types
        """
        if action != 'get_supported_object_types':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_supported_object_types".') % action)

        self._setup_provider()
        return self.get_supported_object_types_json()

    @route('/:owner/:object')
    @expose_page(must_login=True,methods=['POST', 'PUT', 'GET','DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def crud(self, owner, object, **kwargs):
        """
        CRUD interface for IT context objects (routes without an ID)

        @param self: The self reference
        @param object: Target object type
        @param **kwargs: Key word arguments extracted from the POST body

        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        @rval: json string
        """
        self._setup_provider()
        method = cherrypy.request.method
        if method in ('POST', 'PUT'):
            return self._create_or_update(owner, object, **kwargs)
        elif method == 'GET':
            return self._get_bulk(owner, object, **kwargs)
        elif method == 'DELETE':
            # Extract force delete header
            kwargs.update({'X-Force-Delete': cherrypy.request.headers.get('X-Force-Delete', False)})
            self._delete_bulk(owner, object, **kwargs)
            cherrypy.response.status = 204
        else:
            raise ITOAError(status="501", message=_("Unsupported HTTP method"))

    @route('/:owner/:object/:action=refresh')
    @expose_page(must_login=True, methods=['POST', 'PUT'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def object_refresh(self, owner, object, action='refresh', **kwargs):
        """
        CRUD interface for IT context objects to refresh without causing
        related objects to refresh to the change - used by UI primarily

        @param self: The self reference
        @param owner: The owner context
        @param object: Target object type
        @param **kwargs: Key word arguments extracted from the POST body

        @return: None
        """
        if action != 'refresh':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "refresh".') % action)

        self._setup_provider()
        return self._refresh_object(owner, object, **kwargs)

    @route('/:owner/:object/:aggregation=count')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def object_count(self, owner, object, aggregation, **kwargs):
        """
        Get the object count
        """
        self._setup_provider()
        return self._get_object_count(owner, object, **kwargs)

    @route('/:owner/:object/:id_/:action=templatize')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def templatize_by_id(self, owner, object, id_, action, **kwargs):
        """
        Templatize given object id.
        We will get rid of values that make the given id unique
        and pass back to the UI, the templatized value.
        @param object: target object type
        @param id_: target object identifier
        @param **kwargs: key word arguments extracted for us by cherrypy as a
        dictionary

        @rtype: json
        @return templatized value
        """
        if action != 'templatize':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "templatize".') % action)

        self._setup_provider()
        return self._templatize_object_by_id(owner, object, id_, **kwargs)

    @route('/:owner/:object/:id_')
    @expose_page(must_login=True, methods=['GET', 'PUT', 'POST', 'DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def crud_by_id(self, owner, object, id_, **kwargs):
        """
        CRUD interface for IT context objects (routes with an ID)

        Entity specific create - Just defines an endpoint that calls the generic version
        @param self: The self reference
        @param object: Target object type
        @param id_: Target object identifier
        @param **kwargs: Key word arguments extracted from the POST body

        @return: json with identifier (PUT, DELETE) or json with object (GET)
        @rval: json string
        """
        self._setup_provider()
        method = cherrypy.request.method
        if method == 'GET':
            return self._get_by_id(owner, object, id_, **kwargs)
        elif method in ('PUT', 'POST'):
            return self._update_by_id(owner, object, id_, **kwargs)
        elif method == 'DELETE':
            kwargs.update({'X-Force-Delete': cherrypy.request.headers.get('X-Force-Delete', False)})
            self._delete_by_id(owner, object, id_, **kwargs)
            cherrypy.response.status = 204
        else:
            raise ITOAError(status="501", message=_("Unsupported HTTP method"))

    @route('/:owner/:object/:id_/:action=refresh')
    @expose_page(must_login=True, methods=['PUT', 'POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def object_refresh_by_id(self, owner, object, id_, action='refresh', **kwargs):
        """
        CRUD interface for IT context object to refresh its state without refreshing
        related objects, primarily used by UI

        @param self: The self reference
        @param owner: The owner context
        @param object: Target object type
        @param id_: Target object identifier
        @param **kwargs: Key word arguments extracted from the POST body

        @return: None
        """
        if action != 'refresh':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "refresh".') % action)

        self._setup_provider()
        return self._object_refresh_by_id(owner, object, id_, **kwargs)


    ###############################################################################
    # Service Template Link Endpoint
    ###############################################################################

    @route('/:owner/:object/:id_/:action=base_service_template')
    @expose_page(must_login=True, methods=['GET', 'PUT', 'POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def link_service_template(self, owner, object, id_, action, **kwargs):
        """
        Get service template id from service /
        Link a single service to a service template

        @param self: The self reference
        @param owner: The owner context
        @param object: Target object type
        @param id_: Target object identifier
        @param **kwargs: Key word arguments extracted from the POST body

        @return: None
        """
        if action != 'base_service_template':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "base_service_template".') % action)
        self._setup_provider()
        return self._link_template_to_service(owner, object, id_, **kwargs)

    ##############################################################################
    # Bulk Import
    ##############################################################################
    @route('/:action=load_csv/:owner')
    @handle_json_in
    @expose_page(must_login=True, methods=['POST','PUT'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def load_csv(self, action, owner, **kwargs):
        """
        Loads entities/services into w/e backend storage is currently defined
        @param self: Self reference
        @param action: action param
        @param **kwargs: key word arguments extracted from the request

        @return created keys or error message.
        @type json string
        """
        if action != 'load_csv':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "load_csv".') % action)

        self._setup_provider()
        return self._bulk_csv_import(owner, **kwargs)

    ##############################################################################
    # Bulk Edit of Entity Information Fields
    ##############################################################################
    @route('/:owner/:object/:action=bulk_entities_update')
    @expose_page(must_login=True, methods=['POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def bulk_entities_update(self, action, owner, object, **kwargs):
        """
        POST (UPDATE of subordinate objects) for entity objects INFO FIELDS only

        @param self: The self reference
        @param owner: The owner context
        @param object: The object type being bulk updated, only supports entity
        @param **kwargs: Key word arguments extracted from the POST body
           - entities - A list of entity bodies to be modified as sent from the client
           - update - A collection of key/value pairs to set on all entities sent

        @return: None
        """
        if action != 'bulk_entities_update':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "bulk_entities_update".') % action)

        self._setup_provider()
        return self._bulk_entities_update(owner, object, **kwargs)

    ##############################################################################
    # Bulk Edit of Objects
    ##############################################################################
    @route('/:owner/:object/:action=bulk_update')
    @expose_page(must_login=True, methods=['POST', 'PUT'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def bulk_update(self, action, owner, object, **kwargs):
        """
        POST (UPDATE of subordinate objects) for entity objects INFO FIELDS only

        @param self: The self reference
        @param owner: The owner context
        @param object: The object type being bulk updated
        @param **kwargs: Key word arguments extracted from the POST body
           - data - A list of objects to update
           - is_partial_data - A bool indicating if payload contains partial object specs or full

        @return: None
        """
        if action != 'bulk_update':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "bulk_update".') % action)

        self._setup_provider()
        return self._bulk_update(owner, object, **kwargs)

    #################################################################################
    # These methods are used to get the search snippets used by entities/services
    #################################################################################
    @route('/:action=get_kpi_searches/:owner')
    @expose_page(must_login=True, methods=['POST', 'PUT'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_kpi_searches(self, action, owner, **kwargs):
        """
        Get search strings in a KPI when user wants to filter by entity.
        @type owner: basestring
        @param owner: usually "nobody". indicates context of this request.

        @rtype: dict
        @return: dictionary of search strings
        """
        if action != 'get_kpi_searches':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_kpi_searches".') % action)

        self._setup_provider()
        return self._get_kpi_searches(owner, **kwargs)

    @route('/:action=get_kpi_searches_gt/:owner')
    @expose_page(must_login=True, methods=['POST', 'PUT'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='glass_table', logger=logger)
    def get_kpi_searches_gt(self, action, owner, **kwargs):
        """
        Fetch KPI searches for data models in glass table ad hoc widgets
        @type owner: basestring
        @param owner: usually "nobody". indicates context of this request.

        @rtype: dict
        @return: dictionary of search strings
        """
        if action != 'get_kpi_searches_gt':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_kpi_searches_gt".') % action)

        self._setup_provider()
        return self._get_kpi_searches(owner, **kwargs)

    @route('/:action=preview_merge/:owner')
    @handle_json_in
    @expose_page(must_login=True, methods=['POST'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def preview_merge(self, action, owner, **kwargs):
        """
        This method takes in a list of entities as a json struct and will then return a list of "previewed" entities.
        The order of the entities received will be the order returned in the list
        outputs a json structure that contains a potential merge
        Other attributes passed in will be retained
        """
        if action != 'preview_merge':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "preview_merge".') % action)

        self._setup_provider()
        return self._preview_merge(owner, **kwargs)

    @route('/:action=get_alias_list/:owner')
    @expose_page(must_login=True, methods=['GET'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_alias_list(self, action, owner, **kwargs):
        """
        Retrieves the alias list for use with kpis
        """
        if action != 'get_alias_list':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_alias_list".') % action)

        self._setup_provider()
        return self._get_alias_list(owner, **kwargs)

    @route('/:action=get_backfill_search/:owner')
    @expose_page(must_login=True, methods=['POST', 'PUT'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_backfill_search(self, action, owner, object, **kwargs):
        """
        Get backfill searches for KPI.
        """
        if action != 'get_backfill_search':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_backfill_search".') % action)

        self._setup_provider()
        return self._get_backfill_search(owner, **kwargs)

    @route('/:action=get_entity_filter/:owner')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_entity_filter(self, action, owner, **kwargs):
        """
        Get entity filter for given service.
        """
        if action != 'get_entity_filter':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_entity_filter".') % action)

        self._setup_provider()
        return self._get_entity_filter(owner, **kwargs)

    @route('/:action=get_entity_filter/:owner/:aggregate=count')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def get_entity_filter_count(self, action, owner, aggregate, **kwargs):
        """
        Get entity filter count for given service.
        """
        if action != 'get_entity_filter':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_entity_filter".') % action)

        self._setup_provider()
        return self._get_entity_filter_count(owner, **kwargs)

    @route('/:action=get_service_trees/:owner')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='home_view', logger=logger)
    def get_service_trees(self, action, owner, **kwargs):
        """
        invoke this endpoint to fetch/update permissions on objects.
        Only users with an `admin` role will be able to do stuff.

        @type action: string
        @param actin: route name registered with cherrypy

        @type kwargs: dictionary
        @param kwargs: permissions for an object or list of objects

        @returns json data on success
        @raises ITOAError on failure
        """
        if action != 'get_service_trees':
            # This may look silly, considering the parameter 'action' is already
            # "defined" and registered with cherrypy for this method.
            # However, there have been cases where cherrypy has routed a request incorrectly
            # to the wrong method. This check will guard us against this occurrence.
            raise ITOAError(status=500,
                message=_('Request has been improperly routed with action="%s". Expecting "get_topology_view".') % action)

        self._setup_provider()
        return self._get_service_trees(owner, **kwargs)
