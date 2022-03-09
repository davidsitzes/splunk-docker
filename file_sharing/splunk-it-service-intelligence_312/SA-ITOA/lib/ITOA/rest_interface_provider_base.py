# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json

from splunk import RESTException
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n
from splunk.appserver.mrsparkle.lib import jsonresponse

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'appserver', 'controllers']))
from user_access_errors import UserAccessError

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.storage import itoa_storage
from ITOA.storage.statestore import StateStoreError
from ITOA.itoa_config import get_collection_name_for_itoa_object
from ITOA.itoa_exceptions import ItoaError
from ITOA.setup_logging import setup_logging, InstrumentCall
from ITOA.controller_utils import ITOAError, ItoaValidationError

logger = setup_logging("itsi.log", "itsi.controllers.itoa_rest_interface_provider")
logger.debug("Initialized itoa interface provider log")


class ItoaInterfaceProviderBase(object):
    """
    Base provider implementing services for REST APIs
    It primarily consists of CRUD/bulk actions to configure and use basic ITSI objects like entities, services, etc.
    Specific REST handlers derive from this class to fit functionality to specific REST handling
    """
    def __init__(self):
        """
        Basic constructor

        @type: object
        @param self: The self reference
        """
        super(ItoaInterfaceProviderBase, self).__init__()
        self._session_key = None
        self._current_user = None
        self._rest_method = None
        self._instrument = None

    def _setup(self, session_key, current_user, rest_method, loggero=None):
        """
        Method to setup provider before handler from the provider are invoked

        @type: string
        @param session_key: session key to splunkd

        @type: string
        @param current_user: current user initiating REST call

        @type: string
        @param rest_method: REST method initiated, GET/POST/PUT/DELETE

        @type loggero: logger
        @param loggero: caller's logger

        @return: None
        """
        self._session_key = session_key if isinstance(session_key, basestring) else None
        self._current_user = current_user if isinstance(current_user, basestring) else None
        self._rest_method = rest_method.upper() if isinstance(rest_method, basestring) else None
        self._instrument = InstrumentCall(loggero) if loggero else InstrumentCall(logger)

    def render_json(self, json_response):
        """
        given data, convert it to a JSON which is consumable by a web client

        @type: json
        @param json_response: the response to render for REST

        @rtype: string
        @return: normalized JSON as a string
        """
        # Escape slashes if they exist in the data
        if isinstance(json_response, jsonresponse.JsonResponse):
            response = json_response.toJson().replace("</", "<\\/")
        else:
            try:
                response = json.dumps(json_response).replace("</", "<\\/")
            except (ValueError, TypeError) as e:
                logger.exception(e)
                response = str(json_response).replace("</", "<\\/")

        # Pad with 256 bytes of whitespace for IE security issue. See SPL-34355
        return ' ' * 256  + '\n' + response

    def _get_storage_interface(self, object_type=None):
        """
        Method to obtain a storage interface object for a given object type to work on

        @type: ItoaInterfaceProviderBase
        @param self: The self reference

        @type: string
        @param object_type: ITOA Object type (service/entity/kpi/glass_table etc...)

        @rtype: ITOAStorage
        @return storage_interface: itoa_storage instance initialized to appropriate collection
        """
        collection = get_collection_name_for_itoa_object(object_type)
        logger.debug('Collection name for object type "%s" is "%s"', object_type, collection)
        init_params = {}
        if collection:
            init_params['collection'] = collection
        logger.debug('Initializing itoa_storage obj with "%s"', init_params)
        return itoa_storage.ITOAStorage(**init_params)

    def _validate_field(self, field):
        """
        Quick and dirty validation that we have a non-None field,
        Here as a method because I was doing it everywhere

        @type: object
        @param self: The self reference

        @type: string
        @param field: The field to be tested

        @rtype: string
        @return: The validated field
        """
        if field is None:
            message = _("Missing field")
            logger.error(message)
            raise ITOAError(status="400", message=message)
        return field

class SplunkdRestInterfaceBase(object):
    """
    Class implementation for REST handler providing services for maintenance services interface endpoints.
    Meant for use with a persisted non-EAI rest handler deriving from PersistentServerConnectionApplication
    """
    def __init__(self):
        """
        Basic constructor
        """
        super(SplunkdRestInterfaceBase, self).__init__()

    def _default_handle(self, args):
        """
        Blanket handler for all REST calls on the interface routing the GET/POST/PUT/DELETE requests.
        Derived implementation from PersistentServerConnectionApplication.
        This is a generic implementation that specific derived implementation could use optionally

        @type args: json
        @param args: a JSON string representing a dictionary of arguments to the REST call.

        @rtype: json
        @return: a valid REST response
        """
        logger.debug('Splunkd REST handler for ITOA interface received request with args: %s', args)

        response_status = 500
        response_payload = []

        try:
            args = json.loads(args)

            result = self._dispatch_to_provider(args)

            if result is None or isinstance(result, basestring):
                rest_method = args['method']
                response_status = 200
                if rest_method == 'DELETE':
                    response_status = 204
                response_payload = result
            else:
                response_status = 500
                response_payload = {'message': 'Received unexpected results from dispatcher: {}'.format(result)}
        except (ITOAError, UserAccessError) as e:
            logger.exception(e)
            response_status = e.status
            response_payload = {'message': str(e)}
        except RESTException as e:
            logger.exception(e)
            response_status = e.statusCode
            response_payload = {'message': str(e)}
        except StateStoreError as e:
            response_status = e.status_code or 500
            response_payload = {'message': str(e)}
        except ItoaError as e:
            response_status = e.status_code or 500
            response_payload = {'message': str(e)}
        except Exception as e:
            logger.exception(e)
            response_status = 500
            response_payload = {'message': str(e)}

        try:
            response_status = int(response_status)
        except (ValueError, TypeError):
            response_status = 500

        return {
            'status': response_status,
            'payload': response_payload
        }

    def _dispatch_to_provider(self, args):
        """
        Parses the REST path on the interface to help route to specific providers in derived overrides

        @type: dict
        @param args: the args routed for the REST method

        @rtype: dict
        @return: results of the REST method
        """
        raise NotImplementedError

    @staticmethod
    def extract_request_owner(args, rest_method_args):
        """
        Helper method to identify owner specified in request
        Owner is the user specified in namespace for the splunkd url like /servicesNS/<owner>/<app>
        Extract this owner or default to current user as owner

        @type: dict
        @param args: args provided by splunkd server to handler for REST request

        @rtype: basestring
        @return: the owner identified
        """
        owner = args['session']['user']
        if 'ns' in args and 'user' in args['ns']:
            owner = args['ns']['user']

        # Clean up the owner from the REST method args to enforce/reflect namespace owner only applies
        if 'owner' in rest_method_args:
            del rest_method_args['owner']
        return owner

    @staticmethod
    def extract_rest_args(args, args_field, args_dict):
        """
        Helper method to extract dict form of a given field's value from splunkd server provided args to a handler

        @type: dict
        @param args: args provided by splunkd server to handler for REST request

        @type: string
        @param args_field: field to extract as dict. This field's value MUST be a list in args

        @type: dict
        @param args_dict: the in/out of this method which is a dict to which args from the field are appended/overwritten

        @rtype: None
        @return: None
        """
        if (not (
            isinstance(args, dict) and
            isinstance(args_field, basestring) and
            isinstance(args_dict, dict) and
            isinstance(args.get(args_field, []), list)
        )):
            raise ITOAError(_('Invalid args received by extract_rest_args. args: {}, field: {}').format(args, args_field))
        for term in args.get(args_field, []):
            if len(term) == 2:
                # term[0] is arg name and term[1] is value
                args_dict[term[0]] = term[1]

    @staticmethod
    def extract_force_delete_header(args, args_dict):
        """
        Helper method to extract the 'X-Force-Delete' header from splunkd provided args to a handler

        @type: dict
        @param args: args provided by splunkd server to handler for REST request

        @type: dict
        @param args_dict: the in/out of this method which is a dict to which args from the field are appended/overwritten

        @rtype: None
        @return: None
        """
        # Looking for a specific key
        key = 'X-Force-Delete'

        if args.get('headers') is not None and isinstance(args.get('headers'), list):
            for array in args['headers']:
                for term in array:
                    if term == key:
                        if len(array) == 2 and array[0] == key:
                            args_dict[array[0]] = array[1]

    @staticmethod
    def extract_data_payload(args):
        """
        Custom fit method that extracts "data" from payload in a specific way that may work only for
        some splunkd REST handlers.

        @type: dict
        @param args: args provided by splunkd server to handler for REST request

        @rtype: json
        @return: data payload extracted from the REST args
        """
        form_data = {}
        # Note that form data being present here implies head specified content type correctly
        data = None

        # Allow both raw payload (Content-Type application/json) and form payload
        # (Content-Type application/x-www-form-urlencoded). Will skip checking headers here
        # so as to allow current client API sets to continue without incurring changes/convenience
        # for client API. If needed, we could add specific header checks in future.
        is_use_form = True
        if 'payload' in args and len(args['payload']) > 0:
            try:
                form_data = json.loads(args['payload'])
                is_use_form = False
            except (ValueError, TypeError) as e:
                logger.exception(e)
                # Ignore payload contents since it isnt valid JSON, lets try form data
                is_use_form = True

        if is_use_form:
            SplunkdRestInterfaceBase.extract_rest_args(args, 'form', form_data)
        if 'data' in form_data:
            data = form_data['data']
        else:
            data = form_data

        form_data = {}
        try:
            if isinstance(data, basestring):
                form_data['data'] = json.loads(data)
            elif isinstance(data, dict) or isinstance(data, list):
                form_data['data'] = data
        except (ValueError, TypeError) as e:
            logger.exception(e)
            raise ItoaValidationError(_('Could not extract "data" from payload. Check input.'), logger)

        return form_data
