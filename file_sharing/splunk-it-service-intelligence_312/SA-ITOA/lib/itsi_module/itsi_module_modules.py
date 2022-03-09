# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import socket
import os
import re
import base64

from splunk import BadRequest, ResourceNotFound
from splunk.util import normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.clilib.cli_common as comm

from ITOA.setup_logging import setup_logging
from itsi_module_package.itsi_module_builder import ItsiModuleBuilder
import itsi_module_common as utils
from itsi_module_interface_object_manifest import object_manifest


class ItsiModuleModules(object):
    """
    Class to create, get, handle_action for ITSI module
    """

    """
    Class variables
    """
    _metadata_base_endpoint_single_module = '/services/apps/local/%s?output_mode=json'
    _metadata_base_endpoint_all_modules = '/services/apps/local?search=DA-ITSI&output_mode=json'
    _ALL_MODULES = '-'

    _validation_error_messages = {
        'package_prefix_mismatch': _('Module package name should starts with DA-ITSI-.'),
        'label_required': _('Module need to contain a label.'),
        'description_required': _('Module need to contain a description.'),
        'version_required': _('Module need to contain a version.'),
        'author_required': _('Module need to contain an author.'),
        'filename_required': _('No filename specified. Please specify a filename to download.'),
        'invalid_filename': _('The filename you are requesting is an invalid SPL package.'),
        'no_files_exported': _('Cannot download requested file. No downloads have been exported yet.'),
        'package_not_found': _('Requested package does not exist. Either module was not created, or not exported yet.')
    }

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initialize objects

        @type session_key: basestring
        @param session_key: session key

        @type app: basestring
        @param app: current app

        @type owner: basestring
        @param owner: current user

        @type logger: object
        @param logger: logger to use

        @rtype: object
        @return: instance of the class
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def get(self, itsi_module, **kwargs):
        """
        Gets all metadata about a ITSI module

        @type itsi_module: string
        @param itsi_module: ITSI module that was requested

        @rtype: dict
        @return: dictionary of ITSI module metadata
        """
        # Set up target endpoint to make request to, and then attempt to get data
        if itsi_module == self._ALL_MODULES:
            target_endpoint = self._metadata_base_endpoint_all_modules
        else:
            target_endpoint = self._metadata_base_endpoint_single_module % itsi_module

        self.logger.debug('Attempting get from modules from endpoint: %s', target_endpoint)

        # Construct response that provides all module metadata
        response = utils.construct_metadata_response(target_endpoint, itsi_module, self.session_key, **kwargs)
        self.logger.debug('Get response for module %s: %s', itsi_module, json.dumps(response))
        return response

    def create(self, itsi_module, **kwargs):
        """
        Create a ITSI module

        @type itsi_module: basestring
        @param itsi_module: the name of ITSI module to be created

        @type kwargs: dict
        @param kwargs: extra params
            {
                title: <string, required>,
                description: <string, optional>,
                author: <string, required>,
                version: <string, required>,
                overwrite: <true/false, optional>,
                readme: <string, optional>,
                small_icon: <string, optional>,
                large_icon: <string, optional>
            }

        @rtype: dict {'appid': <string>, 'meta_file_upload_result': <dict>}
        @return: appid of ITSI module that is created
        """
        self.logger.info('ItsiModuleModules create is called %s' % kwargs)

        data = kwargs.get('data') or kwargs

        self._validate_module_name(itsi_module)

        # Check required parameters
        args = ['title', 'author', 'version']
        missed = [arg for arg in args if data.get(arg) is None]
        if missed:
            msg = _('Required parameter(s) are missing: %s.') % ', '.join(missed)
            self.logger.error(msg)
            raise BadRequest(extendedMessages=msg)

        # Prepare app meta and call actual builder
        app_name = 'DA-ITSI-%s' % itsi_module if not itsi_module.startswith('DA-ITSI-') else itsi_module
        meta_items = ['title', 'description', 'author', 'version', 'overwrite', 'readme', 'small_icon', 'large_icon']
        meta = {k: v for k, v in data.items() if k in meta_items}
        meta['app_name'] = app_name
        try:
            module_builder = ItsiModuleBuilder(app_name, session_key=self.session_key, logger=self.logger)

            overwrite = normalizeBoolean(data.get('overwrite', False))
            meta_file_upload_result = module_builder.generate_module(meta, overwrite)
        except Exception as e:
            raise BadRequest(extendedMessages=e.message)

        msg = _('ITSI module is created successfully:%s') % app_name
        self.logger.info(msg)

        result = {'appid': app_name, 'meta_file_upload_result': meta_file_upload_result}
        return result

    def update(self, itsi_module, **kwargs):
        """
        Update an existing ITSI module's metadata fields or files

        @type itsi_module: basestring
        @param itsi_module: the name of ITSI module to be created

        @type kwargs: dict
        @param kwargs: extra params
            {
                title: <string, optional>,
                description: <string, optional>,
                author: <string, optional>,
                version: <string, optional>,
                readme: <string, optional>,
                small_icon: <string, optional>,
                large_icon: <string, optional>
            }

        @rtype: dict {'appid': <string>}
        @return: appid of ITSI module that is created
        """
        data = kwargs.get('data') or kwargs
        app_name = 'DA-ITSI-%s' % itsi_module if not itsi_module.startswith('DA-ITSI-') else itsi_module
        meta_items = ['title', 'description', 'author', 'version', 'overwrite', 'readme', 'small_icon', 'large_icon']
        meta = {k: v for k, v in data.items() if k in meta_items}
        meta['app_name'] = app_name

        try:
            module_builder = ItsiModuleBuilder(app_name, session_key=self.session_key, logger=self.logger)

            return module_builder.update_module(meta)
        except Exception as e:
            raise BadRequest(extendedMessages=e.message)


    def handle_action(self, itsi_module, module_action_name, **kwargs):
        """
        Handle custom action for ITSI module

        @type itsi_module: basestring
        @param itsi_module: the name of ITSI module

        @type module_action_name: basestring
        @param module_action_name: custom action for ITSI module

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: dict if module_action_name is generate_package
        @return: - if module_action_name is generate_package,
            appid, url path, file path of ITSI module that is packaged.
            - if module_action_name is validate, return a list of validation
            errors/infos related to all of the object types and metadata
            - if module_action_name is download_package, return the data for
            the packaged .spl file that should be downloaded.  If the file doesn't
            exist, return a 404
        """
        self._validate_module_name(itsi_module)
        self._validate_module_action(module_action_name)

        self.logger.debug('Executing action %s', module_action_name)
        if module_action_name == 'generate_package':
            return self._handle_generate_package_action(itsi_module, **kwargs)
        elif module_action_name == 'validate':
            return self._handle_validate_module(itsi_module, **kwargs)
        elif module_action_name == 'download_package':
            return self._handle_download_module(itsi_module, **kwargs)

    def _handle_generate_package_action(self, itsi_module, **kwargs):
        """
        Package ITSI module

        @type itsi_module: basestring
        @param itsi_module: the name of ITSI module

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: dict
        @return:
            {
                'appid': <string>,
                'path': <string>,
                'url': <string>,
            }
        """
        # First, collect the URL flag to make the module readonly
        make_readonly = normalizeBoolean(kwargs.get('make_readonly', False))

        # Call actual builder to package ITSI module app
        try:
            module_builder = ItsiModuleBuilder(itsi_module, session_key=self.session_key, logger=self.logger)
            package_file_name, download_file_path = module_builder.package_module(make_readonly=make_readonly)
            donwload_url_path = _get_splunk_web_uri() + '/static/app/SA-ITOA/download/' + package_file_name
        except Exception as e:
            raise BadRequest(extendedMessages=e.message)

        msg = _('ITSI module is packaged successfully:{}. Local file path: {}. Download url: {}'). \
            format(itsi_module, download_file_path, donwload_url_path)
        self.logger.info(msg)

        result = {
            'appid': itsi_module,
            'path': download_file_path,
            'url': donwload_url_path
        }
        return result

    def list_contents(self, itsi_module, object_instances, **kwargs):
        """
        List object contents in ITSI module

        @type itsi_module: basestring
        @param itsi_module: the name of ITSI module

        @type object_instances: list
        @param object_instances: objects of supported object types

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: dict
        @return:
            {
                <object_type>: []
            }
        """
        response = {}
        if type(object_instances) is list:
            for object_instance in object_instances:
                object_content = object_instance.get(itsi_module, None, **kwargs)

                for entry in object_content:
                    object_type = entry['object_type']

                    if object_type not in response:
                        response[object_type] = []

                    response[object_type].append(entry)

        return response

    def _validate_module_name(self, itsi_module):
        """
        Validate passed ITSI module name
        """
        if not itsi_module:
            msg = _('ITSI module name is not valid.')
            self.logger.error(msg)
            raise BadRequest(extendedMessages=msg)

    def _validate_module_action(self, module_action_name):
        """
        Validate passed ITSI module action
        """
        msg = ''

        if not module_action_name:
            msg = _('ITSI module action is not valid.')
        elif module_action_name not in ['generate_package', 'validate', 'download_package']:
            msg = _('ITSI module action is not supported: {}.').format(module_action_name)

        if msg:
            self.logger.error(msg)
            raise BadRequest(extendedMessages=msg)

    def _handle_validate_module(self, itsi_module, **kwargs):
        """
        Validate the module contents

        @type itsi_module: basestring
        @param itsi_module: the name of itsi module

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: dictionary
        @return: dictionary of object type to actual validation result
        """
        all_results = {
            'module': {}
        }
        module_metadata = self.get(itsi_module)

        module_errors = []
        if not module_metadata.get('package_name').startswith(itsi_module):
            module_errors.append([itsi_module, itsi_module, self._validation_error_messages['package_prefix_mismatch']])

        if not module_metadata.get('label'):
            module_errors.append([itsi_module, itsi_module, self._validation_error_messages['label_required']])

        if not module_metadata.get('description'):
            module_errors.append([itsi_module, itsi_module, self._validation_error_messages['description_required']])

        if not module_metadata.get('version'):
            module_errors.append([itsi_module, itsi_module, self._validation_error_messages['version_required']])

        if not module_metadata.get('author'):
            module_errors.append([itsi_module, itsi_module, self._validation_error_messages['author_required']])

        if len(module_errors):
            all_results['module']['errors'] = module_errors

        # Validate all the supported objects
        for object_type in object_manifest.keys():
            if not type(object_manifest[object_type]) is list:
                object_instance = object_manifest[object_type](self.session_key)
                all_results[object_type] = object_instance.validate(itsi_module, None)

        self.logger.debug('Found following validation results for module %s: %s', itsi_module, all_results)
        return all_results

    def _handle_download_module(self, itsi_module, **kwargs):
        """
        Handles the module download given a file name passed into the URL

        @type itsi_module: string
        @param itsi_module: ITSI module that is being requested

        @rtype: dictionary
        @return: Dictionary containing a single field "file_contents" with the base64 encoded file contents inside
        """
        response_object = {}
        file_data = ''
        VALID_FILENAME_PATTERN = r'^DA-ITSI-([0-9a-zA-Z_]+)_([0-9]_?)+\.spl$'

        # Make sure that the filename is provided
        filename = kwargs.get('filename')
        if not filename:
            raise BadRequest(extendedMessages=self._validation_error_messages.get('filename_required'))

        # Make sure that the user is requesting a valid SPL file
        valid_filename = re.match(VALID_FILENAME_PATTERN, filename)
        if not valid_filename:
            raise BadRequest(extendedMessages=self._validation_error_messages.get('invalid_filename'))

        download_folder_path = make_splunkhome_path(['etc', 'apps', 'SA-ITOA', \
            'appserver', 'static', 'download'])

        # If path doesn't exist, or is a file, no downloads have been exported yet
        if not os.path.isdir(download_folder_path):
            raise ResourceNotFound(self._validation_error_messages.get('no_files_exported'))

        file_path = os.path.join(download_folder_path, filename)

        # If filename doesn't exist, either module not created or may not have been exported yet
        if not os.path.isfile(file_path):
            raise ResourceNotFound(extendedMessages=self._validation_error_messages.get('package_not_found'))

        # Open file, base 64 encode the file contents, and dump into the response object 
        try:
            with open(file_path, 'r') as file:
                file_data = file.read()
                response_object['file_contents'] = base64.standard_b64encode(file_data)
        except Exception as e:
            raise utils.ItsiModuleError(status=500, message=_('Failed to get contents of SPL file.'))

        return response_object

def _get_splunk_web_uri():
    """
    Returns Splunkweb uri
    """
    return comm.getWebUri().replace('127.0.0.1', socket.gethostname().lower())
