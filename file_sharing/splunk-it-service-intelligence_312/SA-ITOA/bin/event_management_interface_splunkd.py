# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json
import urllib

from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ITOAError, ItoaValidationError
from ITOA.rest_interface_provider_base import SplunkdRestInterfaceBase
from itsi.event_management.event_management_rest_provider import EventManagementRestProvider, \
    get_interactable_object_types, handle_exceptions
from ITOA.event_management.notable_event_utils import CAPABILITY_MATRIX
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.access_control.splunkd_controller_rbac_utils import EnforceRBACSplunkd


logger = setup_logging('itsi_event_management.log',
                       'itsi.controllers.event_management_interface_splunkd')
logger.debug("Initialized SA-ITOA splunkd event management rest services log...")


class EventMgmtInterfaceProviderSplunkd(EventManagementRestProvider):
    """
    This wrapper class for the REST provider in EventManagementRestProvider which
    handles all access check decorators and passes on to provider to serve
    rest of the request
    """
    def __init__(self, session_key, current_user, rest_method):
        """
        Constructor initializing splunkd specific info

        @type: string
        @param session_key: the splunkd session key for the request

        @type: string
        @param current_user: current user invoking the request

        @type: string
        @param: type of REST method of this request, GET/PUT/POST/DELETE
        """
        self._setup(session_key, current_user, rest_method)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    @EnforceRBACSplunkd(is_bulk_op=True)
    def bulk_crud(self, owner, object_type, **kwargs):
        """
        Routes CRUD operations on objects

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the REST method results
        """
        return self._bulk_crud(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
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
        return self._crud_by_id(owner, object_type, object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def get_objects_count(self, owner, object_type, **kwargs):
        """
        Gets count of objects with filters applied

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._get_object_count(owner, object_type, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def do_notable_event_action(self, owner, object_type, **kwargs):
        """
        Do requested notable event action

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request, unused, here for access check simplification

        @type: string
        @param object_type: type of object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._do_notable_event_action(**kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def do_notable_event_group_action(self, owner, object_type, **kwargs):
        """
        Do requested notable event group action

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request, unused, here for access check simplification

        @type: string
        @param object_type: type of object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._do_notable_event_group_action(**kwargs)

    def get_notable_event_configuration(self, **kwargs):
        """
        Do requested notable event action

        @type: object
        @param self: the self reference

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._get_notable_event_configuration(**kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def cru_ticket_info(self, owner, object_type, object_id, **kwargs):
        """
        NOTE: POST 2.6.X, WE WILL NOT HAVE SPLUNKWEB ENDPOINTS FOR CREATING/UPDATING TICKETS. 
        THESE OPERATIONS WILL BE PERFORMED THROUGH EVENT ACTIONS ENDPOINT. THEREFORE, IN FUTURE,
        THIS ENDPOINT SHOULD BECOME READ TICKET INFO ENDPOINT TO ONLY SUPPORT READ OPERATION.
        FOR CONTEXT, REFER PBL-704.
        
        Perform create/read/update operations on notable event ticket

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request, not used, here for access check simplification

        @type: string
        @param object_type: type of object

        @type: string
        @param object_id: id of notable event object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the CRU operations
        """
        if self._rest_method is not 'GET':
            logger.warning('Please be advised, this endpoint will soon be deprecated for operations PUT and POST.'
                                'POST and PUT operations for ticketing will become part of "notable_event_actions" '
                                'splunkd endpoint. For more information, refer ITSI docs for Splunkd Endpoints')
        return self._cru_ticket_info(object_id, **kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def bulk_cru_ticket_info(self, owner, object_type, **kwargs):
        """
        NOTE: POST 2.6.X, WE WILL NOT HAVE SPLUNKWEB ENDPOINTS FOR BULK UPSERT OF TICKETS. 
        UPSERT OPERATIONS WILL BE PERFORMED THROUGH EVENT ACTIONS ENDPOINT. THEREFORE, TO 
        MAINTAIN CONSISTENCY, THIS SPLUNKD ENDPOINT SHOULD BE DEPRECATED IN FUTURE.
        FOR CONTEXT, REFER PBL-704.
        
        Perform create/read/update operations on notable event ticket

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request, not used, here for access check simplification

        @type: string
        @param object_type: type of object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the results of the bulk cru operation
        """
        if self._rest_method in ('POST', 'PUT'):
            logger.warning('Please be advised, this endpoint will soon be deprecated for operations PUT and POST.'
                                'POST and PUT operations for ticketing will become part of "notable_event_actions" '
                                'splunkd endpoint. For more information, refer ITSI docs for Splunkd Endpoints')
        return self._bulk_cru_ticket_info(**kwargs)

    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def delete_ticket_info(
        self,
        owner,
        object_type,
        object_id,
        ticket_system,
        ticket_id,
        **kwargs
    ):
        """
        NOTE: POST 2.6.X, WE WILL NOT HAVE SPLUNKWEB ENDPOINTS FOR DELETION OF TICKETS. 
        DELETE OPERATION WILL BE PERFORMED THROUGH EVENT ACTIONS ENDPOINT. THEREFORE, TO 
        MAINTAIN CONSISTENCY, THIS SPLUNKD ENDPOINT SHOULD BE DEPRECATED IN FUTURE.
        FOR CONTEXT, REFER PBL-704.
        
        Delete the notable event ticket

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request, not used, here for access check simplification

        @type: string
        @param object_type: type of object

        @type: string
        @param object_id: id of notable event object

        @type: string
        @param ticket_system: the ticket system of the notable event that needs to be deleted

        @type: string
        @param ticket_id: the ticket id of the notable event that needs to be deleted

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        if self._rest_method in ('DELETE'):
            logger.warning('Please be advised, this endpoint will soon be deprecated. DELETE operation for'
                                ' ticketing will become part of "notable_event_actions" splunkd endpoint. '
                                'For more information, refer ITSI docs for Splunkd Endpoints')
        return self._delete_ticket_info(object_id, ticket_system, ticket_id, **kwargs)

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

    def do_mad_event_action(self, **kwargs):
        """
        Do requested MAD notable event action

        @type: object
        @param self: the self reference

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._do_mad_event_action(**kwargs)

    def process_user_message_mad_event(self, **kwargs):
        """
        Do requested MAD notable event action

        @type: object
        @param self: the self reference

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of objects
        """
        return self._process_user_message_mad_event(**kwargs)

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

class EventManagementInterfaceSplunkd(PersistentServerConnectionApplication, SplunkdRestInterfaceBase):
    """
    Class implementation for REST handler providing services for event management interface endpoints.
    """
    def __init__(self, command_line, command_arg):
        """
        Basic constructor

        @type: string
        @param command_line: command line invoked for handler

        @type: string
        @param command_arg: args for invoked command line for handler
        """
        super(EventManagementInterfaceSplunkd, self).__init__()

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
        This handler's thin layer parses the paths and routes actual handling for the call
        to EventMgmtInterfaceProviderSplunkd

        @type: dict
        @param args: the args routed for the REST method

        @rtype: dict
        @return: results of the REST method
        """
        if not isinstance(args, dict):
            message = _('Invalid REST args received by event management interface - {}').format(args)
            raise ItoaValidationError(message=message, logger=logger)

        session_key = args['session']['authtoken']
        current_user = args['session']['user']
        rest_method = args['method']

        rest_method_args = {}
        SplunkdRestInterfaceBase.extract_rest_args(args, 'query', rest_method_args)

        rest_method_args.update(SplunkdRestInterfaceBase.extract_data_payload(args))

        interface_provider = EventMgmtInterfaceProviderSplunkd(session_key, current_user, rest_method)

        rest_path = args['rest_path']
        if not isinstance(rest_path, basestring):
            message = _('Invalid REST path received by event management interface - {}').format(rest_path)
            raise ItoaValidationError(message=message, logger=logger)

        # Double check this is event management interface path
        path_parts = rest_path.strip().strip('/').split('/')
        if (not isinstance(path_parts, list)) or (len(path_parts) < 2) or (path_parts[0] != 'event_management_interface'):
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

        owner = self.extract_request_owner(args, rest_method_args)

        # First check for helper methods which would occur as the first term in the path
        if first_path_part == 'notable_event_actions':
            action_name = None
            if len(path_parts) == 2 and path_parts[1] is not None:
                rest_method_args['action_name'] = path_parts[1]
            return interface_provider.do_notable_event_action(owner, 'notable_event_action', **rest_method_args)
        elif first_path_part == 'ticketing':
            if len(path_parts) == 1:
                return interface_provider.bulk_cru_ticket_info(
                    owner,
                    'notable_event_ticketing',
                    **rest_method_args
                )
            elif len(path_parts) == 2:
                object_id = urllib.unquote(path_parts[1])
                # cru_ticket_info expects ticket related information at root level {"ticket_system": "jira", ....}
                # however, curl passes params within data {"data": {"ticket_system": "jira", ....} } and
                # it needs to be stripped
                data_args = rest_method_args.get('data', {})
                return interface_provider.cru_ticket_info(owner, 'notable_event_ticketing', object_id, **data_args)
            elif len(path_parts) == 4:
                object_id = urllib.unquote(path_parts[1])
                ticket_system = urllib.unquote(path_parts[2])
                ticket_id = urllib.unquote(path_parts[3])
                # Must be delete method
                return interface_provider.delete_ticket_info(
                    owner,
                    'notable_event_ticketing',
                    object_id,
                    ticket_system,
                    ticket_id,
                    **rest_method_args
                )
        elif first_path_part == 'notable_event_configuration':
            if len(path_parts) < 2 or path_parts[1] != 'all_info':
                raise ITOAError(
                    status=404,
                    message=_('Specified REST url/path is invalid. Url: {}.').format(rest_path)
                )
            return interface_provider.get_notable_event_configuration(**rest_method_args)
        elif first_path_part == 'notable_event_group_action':
            return interface_provider.do_notable_event_group_action(owner, 'notable_event_action', **rest_method_args)
        elif first_path_part == 'mad_event_action':
            return interface_provider.do_mad_event_action(**rest_method_args)
        elif first_path_part == 'user_message_mad_event':
            return interface_provider.process_user_message_mad_event(**rest_method_args)
        elif first_path_part in interface_provider.SUPPORTED_OBJECT_TYPES:

            object_type = first_path_part

            if object_type in get_interactable_object_types():
                if len(path_parts) == 2 and path_parts[1] == 'perms':
                    return interface_provider.object_permissions(owner, object_type, **rest_method_args)
                elif len(path_parts) == 3 and path_parts[2] == 'perms':
                    return interface_provider.object_permissions_by_id(
                        owner,
                        object_type,
                        path_parts[1],
                        **rest_method_args
                    )

            if len(path_parts) == 1:
                return interface_provider.bulk_crud(owner, object_type, **rest_method_args)
            elif len(path_parts) == 2:
                if path_parts[1] == 'count':
                    return interface_provider.get_objects_count(owner, object_type, **rest_method_args)
                elif path_parts[1] != 'perms':
                    # Path is for object CRUD by id
                    object_id = path_parts[1]
                    return interface_provider.crud_by_id(owner, object_type, urllib.unquote(object_id), **rest_method_args)

        # No takers so far implies REST path is crazy, error out
        raise ITOAError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))

