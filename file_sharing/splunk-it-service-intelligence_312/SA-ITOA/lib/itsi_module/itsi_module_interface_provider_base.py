# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import sys
from splunk.appserver.mrsparkle.lib import i18n
from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.setup_logging import setup_logging
from ITOA.rest_interface_provider_base import SplunkdRestInterfaceBase
from itsi_module_common import ItsiModuleError
from itsi_module_interface_object_manifest import object_manifest
from itsi_module.itsi_module_modules import ItsiModuleModules

logger = setup_logging('itsi_module_interface.log', 'itsi.rest_handler_splunkd.itsi_module_interface')


class ItsiModuleInterfaceProviderBase(object):
    """
    Base provider implementing services for REST APIs.
    It primarily consists of CRUD and actions for ITSI module and objects like
    service_template, kpi_base_search, kpi_group, entity_source_template.
    """

    _supported_objects_str = ', '.join([key for key in object_manifest.keys() if key != '-'])

    def __init__(self):
        """
        Basic constructor

        @type: object
        @param self: The self reference
        """
        super(ItsiModuleInterfaceProviderBase, self).__init__()
        self._session_key = None
        self._current_user = None
        self._rest_method = None

    def _setup(self, session_key, current_user, rest_method):
        """
        Method to setup provider before handler from the provider are invoked

        @type: string
        @param session_key: session key to splunkd

        @type: string
        @param current_user: current user initiating REST call

        @type: string
        @param rest_method: REST method initiated, GET/POST/PUT/DELETE

        @return: None
        """
        self._session_key = session_key if isinstance(session_key, basestring) else None
        self._current_user = current_user if isinstance(current_user, basestring) else None
        self._rest_method = rest_method.upper() if isinstance(rest_method, basestring) else None

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
        return ' ' * 256 + '\n' + response

    def _auth_object(self, object_type):
        """
        Authenticates the object_type passed to it

        @type object_type: object
        @param object_type: object type

        @rtype: object
        @return: an initialized object
        """
        return object_type(self._session_key)

    def _get_instance(self, object_type):
        """
        Returns either the object instance type, or a list of all object instance types when given "-"

        @type object: string
        @param object_type: name of object type given in url

        @rtype: object or a list
        @return: an individual or list of initialized supported objects
        """
        object_class = object_manifest.get(object_type)

        # Addresses the case when we are trying to get all object types
        if type(object_class) is list:
            return list(map(self._auth_object, object_class))
        return self._auth_object(object_class)

    def _delete_data(self, kwargs):
        """
        Deleting extra data from kwargs otherwise data would be passed twice

        @rtype: dict
        @return: updated kwargs
        """
        kwargs.pop('data', None)

    def _get_module(self, owner, itsi_module, **kwargs):
        """
        Get ITSI module metadata for specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of ITSI module metadata
        """
        self._validate_module_name(itsi_module, allow_wildcard=True)

        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)
        result = itsi_module_modules.get(itsi_module, **kwargs)

        return self.render_json(result)

    def _create_module(self, owner, itsi_module, **kwargs):
        """
        Create ITSI module with given ITSI module name.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of ITSI module id created
        """
        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)
        result = itsi_module_modules.create(itsi_module, **kwargs)

        return self.render_json(result)

    def _update_module(self, owner, itsi_module, **kwargs):
        """
        Update specified ITSI module

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of ITSI module id created
        """
        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)
        result = itsi_module_modules.update(itsi_module, **kwargs)

        return self.render_json(result)

    def _validate_module(self, owner, itsi_module, **kwargs):
        """
        Validate ITSI module metadata and its objects for specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)

        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)
        result = itsi_module_modules._handle_validate_module(itsi_module, **kwargs)

        return self.render_json(result)

    def _generate_module_package(self, owner, itsi_module, **kwargs):
        """
        Generate app package for specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of app package information
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)

        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)

        result = itsi_module_modules._handle_generate_package_action(itsi_module, **kwargs)

        return self.render_json(result)

    def _download_module(self, owner, itsi_module, **kwargs):
        """
        Download the module as a binary stream

        @type: string
        @param itsi_module: ITSI module name

        @rtype: json
        @return: json object with field "file_contents" that contains the binary
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)

        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)

        result = itsi_module_modules._handle_download_module(itsi_module, **kwargs)

        return self.render_json(result)

    def _list_module_contents(self, owner, itsi_module, **kwargs):
        """
        Get all objects of all object types within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the all objects
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)

        itsi_module_modules = ItsiModuleModules(self._session_key, owner=owner)

        object_instances = self._get_instance('-')

        result = itsi_module_modules.list_contents(itsi_module, object_instances, **kwargs)

        return self.render_json(result)

    def _get_objects(self, owner, itsi_module, object_type, **kwargs):
        """
        Get all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the objects
        """
        self._validate_module_name(itsi_module, allow_wildcard=True)
        self._validate_object_type(object_type, allow_wildcard=False)

        logger.debug('Getting object=%s in module=%s', object_type, itsi_module)
        object_instance = self._get_instance(object_type)
        # self._delete_data(kwargs)

        result = object_instance.get(itsi_module, None, **kwargs)
        logger.debug('Returning values=%s', result)
        return self.render_json(result)

    def _get_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Get object of object_id per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        self._validate_module_name(itsi_module, allow_wildcard=True)
        self._validate_object_type(object_type, allow_wildcard=False)

        logger.debug('Getting _key=%s of object=%s in module=%s', object_id, object_type, itsi_module)
        object_instance = self._get_instance(object_type)
        # self._delete_data(kwargs)

        result = object_instance.get(itsi_module, object_id, **kwargs)
        logger.debug('Returning values=%s', result)
        return self.render_json(result)

    def _create_objects(self, owner, itsi_module, object_type, **kwargs):
        """
        Create all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the objects
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)
        self._validate_object_type(object_type, allow_wildcard=False)

        object_instance = self._get_instance(object_type)

        data = kwargs.get('data') or kwargs
        self._delete_data(kwargs)

        logger.debug('Creating new %s in module=%s', object_type, itsi_module)
        result = object_instance.create(itsi_module, data, **kwargs)
        logger.debug('Returning values=%s', result)

        return self.render_json(result)

    def _update_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Update object of object_id per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)
        self._validate_object_type(object_type, allow_wildcard=False)

        object_instance = self._get_instance(object_type)

        data = kwargs.get('data') or kwargs
        self._delete_data(kwargs)

        logger.debug('Performing update for id=%s of object=%s in module=%s', object_id, object_type, itsi_module)
        result = object_instance.update(itsi_module, object_id, data, **kwargs)
        logger.debug('Returning values=%s', result)

        return self.render_json(result)

    def _delete_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Delete object of object_id per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)
        self._validate_object_type(object_type, allow_wildcard=False)

        logger.debug('Deleting _key=%s of object=%s in module=%s', object_id, object_type, itsi_module)
        object_instance = self._get_instance(object_type)
        # self._delete_data(kwargs)

        # cherrypy.response.status = 204
        object_instance.delete(itsi_module, object_id, **kwargs)

    def _get_objects_count(self, owner, itsi_module, object_type, **kwargs):
        """
        Get count of all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the objects count
        """
        self._validate_module_name(itsi_module, allow_wildcard=True)
        self._validate_object_type(object_type, allow_wildcard=True)

        logger.debug('Getting aggregation count of object=%s in module=%s', object_type, itsi_module)
        object_instance = self._get_instance(object_type)

        response = self._get_object_counts(owner, itsi_module, object_instance, kwargs)
        logger.debug('Returning values=%s', response)
        return self.render_json(response)

    def _get_object_counts(self, owner, itsi_module, object_instance, kwargs):
        """
        Helper function to get count of all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string or list
        @param object_instance: object type or a list of them

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: dict or list
        @return: count per object_type per ITSI module
        """
        if type(object_instance) is list:
            response = {}
            for object_type in object_instance:
                object_type_count = object_type.get_count(itsi_module, **kwargs)
                if len(object_type_count) == 1:
                    curr_object_type = object_type_count.keys()[0]
                    response[curr_object_type] = object_type_count[curr_object_type]
                else:
                    for module_name in object_type_count:
                        if module_name not in response:
                            response[module_name] = {}
                        for key in object_type_count[module_name].keys():
                            response[module_name][key] = object_type_count[module_name][key]
        else:
            response = object_instance.get_count(itsi_module, **kwargs)
        return response

    def _validate_objects(self, owner, itsi_module, object_type, **kwargs):
        """
        Validate all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)
        self._validate_object_type(object_type, allow_wildcard=False)

        logger.debug('Validate object=%s in module=%s', object_type, itsi_module)
        object_instance = self._get_instance(object_type)

        result = object_instance.validate(itsi_module, None)
        logger.debug('Returning values=%s', result)
        return self.render_json(result)

    def _validate_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Validate object per object type per object id within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        self._validate_module_name(itsi_module, allow_wildcard=False)
        self._validate_object_type(object_type, allow_wildcard=False)

        logger.debug('Validate object=%s, id=%s in module=%s', object_type, object_id, itsi_module)
        object_instance = self._get_instance(object_type)

        result = object_instance.validate(itsi_module, object_id)
        logger.debug('Returning values=%s', result)
        return self.render_json(result)

    def _validate_module_name(self, itsi_module, allow_wildcard=False):
        """
        Validate ITSI module name and raise ItsiModuleError if it is invalid.

        @type: string
        @param itsi_module: ITSI module name

        @type: boolean
        @param allow_wildcard: allows wildcard '-' if True
        """
        if isinstance(itsi_module, basestring) and (
                    itsi_module.startswith('DA-ITSI-') or itsi_module == self._ALL_MODULES):
            if itsi_module == self._ALL_MODULES and not allow_wildcard:
                message = _('Wildcard is not supported for ITSI module name in this REST path.')
                raise ItsiModuleError(status='400', message=message)
        else:
            message = _('ITSI module name is invalid. It should start with DA-ITSI-')
            message += ' or as -' if allow_wildcard else ''

            raise ItsiModuleError(status='400', message=message)

    def _validate_object_type(self, object_type, allow_wildcard=False):
        """
        Validate object type and raise ItsiModuleError if it is invalid.

        @type: string
        @param object_type: object type

        @type: boolean
        @param allow_wildcard: allows wildcard '-' if True
        """
        if isinstance(object_type, basestring) and object_type in object_manifest:
            if object_type == self._ALL_OBJECTS and not allow_wildcard:
                message = _('Wildcard is not supported for object type in this REST path.')
                raise ItsiModuleError(status='400', message=message)
        else:
            message = _('Object type is invalid. It should be: %s') % self._supported_objects_str
            message += ' or as -' if allow_wildcard else ''

            raise ItsiModuleError(status='400', message=message)


class ItsiModuleInterfaceSplunkdRestInterfaceBase(SplunkdRestInterfaceBase):
    """
    Base class implementation for REST handler providing services for ITSI module services interface endpoints.
    Meant for use with a persisted non-EAI rest handler deriving from PersistentServerConnectionApplication
    """

    def __init__(self):
        """
        Basic constructor
        """
        super(ItsiModuleInterfaceSplunkdRestInterfaceBase, self).__init__()


    def _default_handle(self, args):
        """
        Handler for all REST calls on the interface routing the GET/POST/PUT/DELETE requests.
        Derived implementation from PersistentServerConnectionApplication.
        This is a generic implementation that specific derived implementation could use optionally.

        @type args: json
        @param args: a JSON string representing a dictionary of arguments to the REST call.

        @rtype: json
        @return: a valid REST response
        """
        logger.info('Splunkd REST handler for ITSI Module Interface received request with args: %s', args)

        try:
            args = json.loads(args)
            result = self._dispatch_to_provider(args)
            if result is None or isinstance(result, basestring):
                rest_method = args['method']
                response_status = 200 if rest_method != 'DELETE' else 204
                response_payload = result
            else:
                response_status = 500
                response_payload = {'message': _('Received unexpected results from dispatcher: {}.').format(result)}
        except ItsiModuleError as e:
            logger.exception(e)
            response_status = e.status
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
