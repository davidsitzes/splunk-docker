# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

'''
Exposes CherryPy / Splunkweb endpoint for Backfill related operations
'''

import sys
import logging
import json
import copy

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.backfill.itsi_backfill_requests import BackfillRequestCollection, BackfillRequestModel
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import handle_json_in, ITOAError

REST_ROOT_PATH = "/services"

logger = setup_logging("itsi_backfill_services.log", "itsi.controllers.backfill_services")
logger.debug("Initialized backfill services log...")

def get_interface_adapter(session_key, _cached_interface={}):
    """
    Lazy init method for the interface adapter
    The interface class instance is cached in the mutable _cached_interface default
    arg array and is persisted between calls to this function.
    """
    if len(_cached_interface) == 0 or session_key not in _cached_interface:
        logger.debug("Caching interface adapter for session key %s", session_key)
        _cached_interface.clear()
        _cached_interface[session_key] = BackfillRequestModel.initialize_interface(session_key)
    return _cached_interface[session_key]

# Multi-inheritance prevents the custom controller grafting from
# intermittently failing with multiple controllers in the app

class backfill_services(ITOABaseController, controllers.BaseController):
    """
    Provides endpoints for backfill CRUD operations
    """
    def __init__(self):
        super(backfill_services, self).__init__()

    @route('/:action=backfill/:owner')
    @expose_page(must_login=True, methods=['POST', 'GET', 'DELETE'])
    @handle_json_in
    def backfill_crud(self, action, owner, **kwargs):
        """
        CR-D operations for the backfill objects.
        GET and DELETE perform bulk fetch/delete operations
        POST creates a single objects
        Updates require an object key and are handled by a different endpoint

        @param **kwargs: Key word arguments extracted from the POST body or a GET query string
            For a POST, kwargs dict must be the attributes dict for the backfill request
            The following attributes are expected (see itsi_backfill_requests.py for details):
                'status' (set to 'new')
                'search' (obtained from the backfill search endpoint)
                'kpi_id'
                'earliest' (epoch seconds)
                'latest' (epoch seconds)
            For a GET kwargs may contain a 'filter' string, e.g. '{"status": "updated"}'
            For a DELETE, kwargs are not used
        """
        local_session_key = cherrypy.session["sessionKey"]
        interface = get_interface_adapter(local_session_key)
        method = cherrypy.request.method
        collection = BackfillRequestCollection(interface=interface)
        if method == 'POST':
            post_data = kwargs.get('data') or kwargs  # postargs get wrapped in 'data' attr
            request_model = BackfillRequestModel(post_data, interface=interface)
            return self.render_json(request_model.save())
        elif method == 'GET':
            filter_data = None
            if 'filter' in kwargs:
                filter_data = json.loads(kwargs['filter'])
            collection.fetch(filters=filter_data)
            return self.render_json([x.data for x in collection])
        elif method == 'DELETE':
            collection.fetch()
            logger.warning("Batch-deleting all backfill requests!")
            return collection.delete()
        else:
            raise ITOAError(status="500", message=_("Unsupported HTTP method"))

    @route('/:action=backfill/:owner/:id_')
    @expose_page(must_login=True, methods=['PUT', 'POST', 'GET', 'DELETE'])
    @handle_json_in
    def backfill_crud_by_id(self, action, owner, id_, **kwargs):
        """
        CRUD operations for the backfill objects (by id)

        @param id_: key used to fetch request objects
        @param **kwargs: Key word arguments extracted from the POST/PUT
            For a POST/PUT, kwargs dict must be the attributes dict for the backfill request
            The following attributes are expected (see itsi_backfill_requests.py for details):
                'status'
                'search' (obtained from the backfill search endpoint)
                'kpi_id'
                'earliest' (epoch seconds)
                'latest' (epoch seconds)
            For a GET/DELETE kwargs are ignored

        If an error is thrown when trying to fetch objects on GET/DELETE, it is assumed
        that the provided key is invalid and a 404 error is returned.
        """
        local_session_key = cherrypy.session["sessionKey"]
        interface = get_interface_adapter(local_session_key)
        method = cherrypy.request.method

        if method in ('POST', 'PUT'):
            post_data = kwargs.get('data') or kwargs  # postargs get wrapped in 'data' attr
            request_model = BackfillRequestModel(post_data, key=id_, interface=interface)
            return self.render_json(request_model.save())
        elif method in ('GET', 'DELETE'):
            try:
                request_model = BackfillRequestModel.fetch_from_key(id_, interface=interface)
            except Exception as e:
                logger.exception(e)
                logger.error("Exception thrown when trying to fetch from key %s", id_)
                raise ITOAError(status="404", message=_("Failed to fetch resource with id {}.").format(id_))
            if method == 'GET':
                return self.render_json(request_model.data)
            elif method == 'DELETE':
                return request_model.delete()
        else:
            raise ITOAError(status="500", message=_("Unsupported HTTP method"))
