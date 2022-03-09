# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Exposes CherryPy / Splunkweb endpoints for all the Notable Event
related operations. Includes executing an event action, changing state, owner,
severity, adding comments etc...
"""

import json
import sys

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk import ResourceNotFound, BadRequest
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import i18n

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import normalizeBoolean

from splunk import RESTException
from splunk.auth import getCurrentUser

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.event_management.notable_event_utils import CAPABILITY_MATRIX
from ITOA.controller_utils import (
    handle_json_in,
    ITOAError
)
from itsi.event_management.event_management_rest_provider import EventManagementRestProvider
from itsi.access_control.access_control_controller_utils import EnforceRBAC

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

logger = setup_logging('itsi_event_management.log', 'itsi.controllers.event_management_interface')


def handle_json_in(f):
    """
    Decorator to handle application/json content type

    no-op if content type is not application/json, else
    convert json to a dict and put that dict in the kwargs
    data argument.
    """

    def wrapper(*args, **kwargs):
        if 'application/json' in cherrypy.request.headers.get('Content-Type', ''):
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            passed_json = json.loads(rawbody)
            if 'data' not in passed_json:
                kwargs.update({'data': passed_json})
            else:
                kwargs.update(passed_json)
            logger.debug('Received data="%s"', kwargs)
        return f(*args, **kwargs)

    return wrapper


class EventManagementServiceCherryPy(
        ITOABaseController,
        controllers.BaseController,
        EventManagementRestProvider):
    """
    Endpoints are defined in this class
    """
    def _setup_provider(self):
        self._setup(cherrypy.session['sessionKey'], getCurrentUser()['name'], cherrypy.request.method)

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
            raise ITOAError(status=500, message=_('Request has been improperly routed with action="%s". Expecting "perms".') % action)

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
            raise ITOAError(status=500, message=_('Request has been improperly routed with action="%s". Expecting "perms".') % action)

        self._setup_provider()
        return self._perms_by_id(object, id_, **kwargs)


    @route('/:owner/:object')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET', 'DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @EnforceRBAC(logger)
    def bulk_crud(self, owner, object, **kwargs):
        """
        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target object type

        @type kwargs: args
        @param **kwargs: Key word arguments extracted from the POST body

        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        @rtype: json or Exception
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
    @EnforceRBAC(logger)
    def object_count(self, owner, object, **kwargs):
        """
        get a count of the objects
        @type owner: basestring
        @param owner: indicates namespace

        @type object: basestring
        @param object: object type i.e. notable_event_tag etc...

        @type kwargs: dict
        @param kwargs: input params extracted from the HTTP request
        """
        self._setup_provider()
        return self._get_object_count(owner, object, **kwargs)

    @route('/:owner/:object/:id_')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET', 'DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @EnforceRBAC(logger)
    def crud(self, owner, object, id_, **kwargs):
        """
        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target object type

        @type kwargs: args
        @param kwargs: Key word arguments extracted from the POST body

        @type id_: basestring
        @param id_: the key of the object to CRUD

        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        @rtype: json
        """
        self._setup_provider()
        result = self._crud_by_id(owner, object, id_, **kwargs)
        if cherrypy.request.method == 'DELETE':
            cherrypy.response.status = 204
        return result

    @route('/:main_action=notable_event_actions/:action_name')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='notable_event_action', logger=logger)
    def notable_event_action(self, **kwargs):
        """
        Get or execute one action
        @type kwargs - dict

        @param kwargs: Hold data
                data - is dict then only one action is being performed
                data structure would looks like this
                    ids : [] -> list of events or group ids
                    name:  -> action name
                    params: key:value pair for action parameters
                    _is_sync - bool to check if action is sync or async
                    _is_group - bool to check if action is being perform on group or not
                    _group_data - list if event ids where action is perform if list is empty then action is being
                        done on all events of the group

        @return: list of dict
                    [{
                        sid: search id
                        ids: [] list of events or group id where action is being perform
                        action_name: name of action which is being performed
                    }...]
        """
        self._setup_provider()
        return self._do_notable_event_action(**kwargs)

    @route('/:main_action=notable_event_actions')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='notable_event_action', logger=logger)
    def notable_event_actions(self, **kwargs):
        """
        Get or execute one or more actions
        @type data - list (when data is list then action is executed in bulk)
        @param data: data
                data - when it is list then more than one event action is being perform
                data - is dict then only one action is being performed
                data structure would looks like this
                    ids : [] -> list of events or group ids
                    name:  -> action name
                    params: key:value pair for action parameters
                    _is_sync - bool to check if action is sync or async
                    _is_group - bool to check if action is being perform on group or not
                    _group_data - list if event ids where action is perform if list is empty then action is being
                        done on all events of the group

        @return: list of dict
                    [{
                        sid: search id
                        ids: [] list of events or group id where action is being perform
                        action_name: name of action which is being performed
                    }...]
        """
        self._setup_provider()
        return self._do_notable_event_action(**kwargs)

    # Get notable event configuration
    @route('/:action=notable_event_configuration/:sub_action=all_info')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    def get_notable_event_configuration(self, action, sub_action, **kwargs):
        """
        Get notable event configuration like severity, status owner and email formats.
        It is mainly useful for UI to shows up drop down etc

        @type action: basestring
        @param action: action name

        @type kwargs: dict
        @param kwargs: Extra arguments

        @rtype: dict
        @return: Return a dictionary which hold information about severities, status and owners
            {
                severities: [
                {
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..],
                statuses: [
                {
                    label: <name>,
                    value: <name>,
                    default: 0|1
                } ...],
                owners: [{
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..],
                email_formats: [{
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..

            }
        """
        self._setup_provider()
        return self._get_notable_event_configuration(**kwargs)

    @route('/:action=ticketing/:id_')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='notable_event_ticketing', logger=logger)
    def ticket_info_by_id(self, action, id_, **kwargs):
        """
        This method fetches all the ticket information for a particular event id on a GET

        @param action: completely useless passed static string of "ticketing"

        @param id_: the key of the notable event to deal with for ticketing

        @param kwargs: only GET arg is used at this endpoint

        @return:
        """
        self._setup_provider()
        return self._cru_ticket_info(id_, **kwargs)


