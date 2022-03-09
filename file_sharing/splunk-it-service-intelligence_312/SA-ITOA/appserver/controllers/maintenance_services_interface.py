# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Exposes Cherrypy/Splunkweb endpoints that do basic CRUD on for maintenance
purposes
"""

import sys

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.auth import getCurrentUser
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import (
    NormalizeRESTRequestForSharedObjects,
    handle_json_in,
    ITOAError
)
from itsi.access_control.access_control_controller_utils import EnforceRBAC
from maintenance_services.constants import CAPABILITY_MATRIX
from maintenance_services.maintenance_services_rest_provider.maintenance_services_rest_provider \
    import MaintenanceServicesRestProvider

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

logger = setup_logging("maintenance_services.log", "maintenance_services.controllers.MaintenanceServices")
logger.debug("Initialized maintenance services log")

# Multi-inheritance prevents the custom controller grafting from intermittently
# failing with multiple controllers in the app
class MaintenanceServices(ITOABaseController, controllers.BaseController, MaintenanceServicesRestProvider):
    """
    MaintenanceServices provides backend interaction via REST for maintenance operations like CRUD for maintenance
    configuration
    """
    def _setup_provider(self):
        """
        Thin wrapper to setup CherryPy specific provider info

        @type: object
        @param self: self reference

        @rtype: None
        @return: None
        """
        self._setup(cherrypy.session['sessionKey'], getCurrentUser()['name'], cherrypy.request.method)

    @route('/:action=get_supported_object_types')
    @expose_page(must_login=True, methods=['GET'])
    def get_supported_object_types(self, action) :
        """
        An app or an SA might want to query the supported object types
        Return a list of supported object types
        No Access Control enforcement on this endpoint...

        @type: object
        @param self: The self reference

        @type: string
        @param: action for the REST call

        @type: list
        @return: an array of supported object types
        """
        self._setup_provider()
        return self._get_supported_object_types()

    @route('/:owner/:object')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET','DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def crud(self, owner, object, **kwargs):
        """
        CRUD interface for IT context objects (routes without an ID)

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object: maintenance object type

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        """
        self._setup_provider()
        result = self._bulk_crud(owner, object, **kwargs)
        if cherrypy.request.method == 'DELETE':
            cherrypy.response.status = 204
        return result

    @route('/:owner/:object/:aggregation=count')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    @EnforceRBAC(logger)
    def object_count(self, owner, object, aggregation, **kwargs):
        """
        Get the object count

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object: maintenance object type

        @type: string
        @param aggregation: aggregation operation request in the REST call

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)

        """
        self._setup_provider()
        return self._get_object_count(owner, object, **kwargs)

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
        result = self._crud_by_id(owner, object, id_, **kwargs)
        if cherrypy.request.method == 'DELETE':
            cherrypy.response.status = 204
        return result
