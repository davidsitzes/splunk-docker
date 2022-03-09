# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import operator
import re
import sys
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.setup_logging import setup_logging
from ITOA.rest_interface_provider_base import SplunkdRestInterfaceBase
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi_module.itsi_module_interface_provider_base import (
    ItsiModuleInterfaceSplunkdRestInterfaceBase,
    ItsiModuleInterfaceProviderBase
)
from itsi_module.itsi_module_common import ItsiModuleError

logger = setup_logging('itsi_module_interface.log', 'itsi.rest_handler_splunkd.itsi_module_interface')
logger.debug("Initialized ITSI module REST splunkd handler interface log")


class ItsiModuleInterfaceProvider(ItsiModuleInterfaceProviderBase):
    """
    This wrapper class for the REST provider in ItsiModuleInterfaceProviderBase which
    serve rest of the request.
    """

    _ALL_MODULES = '-'
    _ALL_OBJECTS = '-'

    def __init__(self, session_key, current_user, rest_method):
        """
        Basic constructor

        @type: string
        @param session_key: the splunkd session key for the request

        @type: string
        @param current_user: current user invoking the request

        @type: string
        @param: type of REST method of this request, GET/PUT/POST/DELETE
        """
        self._setup(session_key, current_user, rest_method)

    def get_all_modules(self, owner, **kwargs):
        """
        Get ITSI module metadata for all ITSI modules on Splunkd.

        @type: string
        @param owner: owner making the request

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of all ITSI module metadata
        """
        return self._get_module(owner, self._ALL_MODULES, **kwargs)

    def get_modules_count(self, owner, **kwargs):
        """
        Get count of all ITSI modules on Splunkd.

        @type: string
        @param owner: owner making the request

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of count of all ITSI modules
        """
        raise NotImplementedError

    def crud_module(self, owner, itsi_module, **kwargs):
        """
        Perform CRUD on specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of CRUD result
        """
        method = self._rest_method

        if method == 'GET':
            return self._get_module(owner, itsi_module, **kwargs)

        elif method == 'POST':
            return self._create_module(owner, itsi_module, **kwargs)

        elif method == 'PUT':
            return self._update_module(owner, itsi_module, **kwargs)

        else:
            message = _('Unsupported operation - {0}').format(method)
            raise Exception(message)

    def validate_module(self, owner, itsi_module, **kwargs):
        """
        Valididate ITSI module metadata and its objects for specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        return self._validate_module(owner, itsi_module, **kwargs)

    def download_module(self, owner, itsi_module, **kwargs):
        """
        Downloads the ITSI module that has been validated and exported

        @type: string
        @param itsi_module: ITSI module

        @rtype: json
        @return: JSON object containing base64 encoded data of SPL file to be downloaded
        """
        return self._download_module(owner, itsi_module, **kwargs)

    def generate_module_package(self, owner, itsi_module, **kwargs):
        """
        Generate app package for specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of app package information
        """
        return self._generate_module_package(owner, itsi_module, **kwargs)

    def list_module_contents(self, owner, itsi_module, **kwargs):
        """
        List all objects of all object types within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the objects
        """
        return self._list_module_contents(owner, itsi_module, **kwargs)

    def crud_objects(self, owner, itsi_module, object_type, **kwargs):
        """
        Crud on all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of CRUD result
        """
        method = self._rest_method

        if method == 'GET':
            return self._get_objects(owner, itsi_module, object_type, **kwargs)

        elif method == 'POST':
            return self._create_objects(owner, itsi_module, object_type, **kwargs)

        else:
            message = _('Unsupported operation - {0}').format(method)
            raise Exception(message)

    def get_objects_count(self, owner, itsi_module, object_type, **kwargs):
        """
         Get count of all objects per object type within specified ITSI module.

         @type: string
         @param owner: owner making the request

         @type: string
         @param itsi_module: ITSI module name

         @type: string
         @param object_type: object type

         @type: dict
         @param kwargs: key word arguments extracted from request

         @rtype: json
         @return: json of the objects count
         """
        return self._get_objects_count(owner, itsi_module, object_type, **kwargs)

    def validate_objects(self, owner, itsi_module, object_type, **kwargs):
        """
        Validate all objects per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        return self._validate_objects(owner, itsi_module, object_type, **kwargs)

    def crud_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Crud on object of object_id per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of CRUD result
        """
        method = self._rest_method

        if method == 'GET':
            return self._get_object_by_id(owner, itsi_module, object_type, object_id, **kwargs)

        elif method == 'POST':
            return self._update_object_by_id(owner, itsi_module, object_type, object_id, **kwargs)

        elif method == 'DELETE':
            return self._delete_object_by_id(owner, itsi_module, object_type, object_id, **kwargs)
        else:
            message = _('Unsupported operation - {0}').format(method)
            raise Exception(message)

    def validate_object_by_id(self, owner, itsi_module, object_type, object_id, **kwargs):
        """
        Validate object of object_id per object type within specified ITSI module.

        @type: string
        @param owner: owner making the request

        @type: string
        @param itsi_module: ITSI module name

        @type: string
        @param object_type: object type

        @type: string
        @param object_id: object id

        @type: dict
        @param kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of validation result
        """
        return self._validate_object_by_id(owner, itsi_module, object_type, object_id, **kwargs)


class ItsiModuleInterfaceSplunkd(PersistentServerConnectionApplication, ItsiModuleInterfaceSplunkdRestInterfaceBase):
    """
    Class implementation for REST handler providing services for ITSI module interface endpoints.
    """

    _module_level_actions = {
        'validate': 'validate_module',
        'generate_package': 'generate_module_package',
        'list_contents': 'list_module_contents',
        'download': 'download_module'
    }

    _object_type_actions = {
        'count': 'get_objects_count',
        'validate': 'validate_objects'
    }

    def __init__(self, command_line, command_arg):
        """
        Basic constructor

        @type: string
        @param command_line: command line invoked for handler

        @type: string
        @param command_arg: args for invoked command line for handler
        """
        super(ItsiModuleInterfaceSplunkd, self).__init__()

    def handle(self, args):
        """
        Handler for all REST calls on the interface routing the GET/POST/PUT/DELETE requests.
        Derived implementation from PersistentServerConnectionApplication.

        @type: object
        @param self: The self reference

        @type args: json
        @param args: a JSON string representing a dictionary of arguments to the REST call.

        @rtype: json
        @return: a valid REST response
        """
        return self._default_handle(args)

    def _dispatch_to_provider(self, args):
        """
        Parses the REST path on the interface to help route actual handling for the call
        to ItsiModuleInterfaceProvider.

        @type: dict
        @param args: the args routed for the REST method

        @rtype: json or None
        @return: results of the REST method
        """
        if not isinstance(args, dict):
            message = _('Invalid REST args received by ITSI module interface - {}').format(args)
            logger.error('%s', message)
            raise ItsiModuleError(status='400', message=message)

        rest_path = args['rest_path']
        if not isinstance(rest_path, basestring):
            message = _('Invalid REST path received by ITSI module interface - {}').format(rest_path)
            logger.error('%s', message)
            raise ItsiModuleError(status='400', message=message)

        # Double check this is ITSI module interface path
        path_parts = rest_path.strip().strip('/').split('/')
        if (not isinstance(path_parts, list)) or (path_parts[0] != 'itsi_module_interface'):
            raise ItsiModuleError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))
        path_parts.pop(0)

        # Version check the API. It should be in the second part of URL if specified. Samples:
        # /itsi_module_interface/vLatest/... where vLatest implies latest ITSI version
        # /itsi_module_interface/<Latest ITSI version>/...
        session_key = args['session']['authtoken']
        if len(path_parts) > 0:
            if path_parts[0] in ['vLatest', 'v' + ITOAInterfaceUtils.get_app_version(session_key, app='itsi')]:
                path_parts.pop(0)
            elif re.match(r'v[0-9]+(\.[0-9]+)*', path_parts[0]):
                raise ItsiModuleError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))

        current_user = args['session']['user']
        rest_method = args['method']

        rest_method_args = {}
        SplunkdRestInterfaceBase.extract_rest_args(args, 'query', rest_method_args)
        SplunkdRestInterfaceBase.extract_force_delete_header(args, rest_method_args)
        rest_method_args.update(SplunkdRestInterfaceBase.extract_data_payload(args))

        owner = self.extract_request_owner(args, rest_method_args)

        logger.debug(
            '_dispatch_to_provider after parsing args : owner=%s, current_user=%s, rest_method=%s, rest_method_args=%s',
            owner, current_user, rest_method, rest_method_args)

        logger.debug('_dispatch_to_provider: path_parts=%s', path_parts)
        provider_action_args = self._get_dispatch_provider_action(path_parts)
        logger.debug(
            '_dispatch_to_provider after get dispatch provider_action: provider_action_args=%s', provider_action_args)

        if provider_action_args:
            provider_type_name = provider_action_args[0]
            action_name = provider_action_args[1]
            args = provider_action_args[2:]

            provider_type = getattr(sys.modules[__name__], provider_type_name)
            provider_instance = provider_type(session_key, current_user, rest_method)

            return operator.methodcaller(action_name, owner, *args, **rest_method_args)(provider_instance)
        else:
            raise ItsiModuleError(status=404, message=_('Specified REST url/path is invalid - {}.').format(rest_path))

    def _get_dispatch_provider_action(self, path_parts, provider_type_name='ItsiModuleInterfaceProvider'):
        """
        Get provider and its action name w/ args to dispatch, given rest path parts

        @type: list
        @param path_parts: rest path parts after /itsi_module_interface/{vLatest/v2.4.0}/

        @type: string
        @param provider_type_name: provider type name, default to ItsiModuleInterfaceProvider

        @rtype: tuple or None
        @return: tuple of provider type name, action name, action args.
        """
        if len(path_parts) == 0:
            # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/
            return provider_type_name, 'get_all_modules'
        elif len(path_parts) == 1:
            if path_parts[0] == 'count':
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/count
                return provider_type_name, 'get_modules_count'
            else:
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}
                itsi_module = path_parts[0]
                logger.debug('_ItsiModuleInterfaceSplunkd _dispatch_to_provider: call module_name: %s', itsi_module)
                return provider_type_name, 'crud_module', itsi_module
        elif len(path_parts) == 2:
            itsi_module = path_parts[0]

            if path_parts[1] in self._module_level_actions:
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}/{action_name}
                action_name = self._module_level_actions.get(path_parts[1])
                return provider_type_name, action_name, itsi_module
            else:
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}/{object_type}
                object_type = path_parts[1]
                return provider_type_name, 'crud_objects', itsi_module, object_type
        elif len(path_parts) == 3:
            itsi_module = path_parts[0]
            object_type = path_parts[1]

            if path_parts[2] in self._object_type_actions:
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}/{object_type}/{action_name}
                action_name = self._object_type_actions.get(path_parts[2])
                return provider_type_name, action_name, itsi_module, object_type
            else:
                # REST url: /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}/{object_type}/{object_id}
                object_id = path_parts[2]
                return provider_type_name, 'crud_object_by_id', itsi_module, object_type, object_id
        elif len(path_parts) == 4:
            if path_parts[3] == 'validate':
                # REST url:
                # /servicesNS/nobody/SA-ITOA/itsi_module_interface/{module_name}/{object_type}/{object_id}/validate
                itsi_module = path_parts[0]
                object_type = path_parts[1]
                object_id = path_parts[2]
                return provider_type_name, 'validate_object_by_id', itsi_module, object_type, object_id
