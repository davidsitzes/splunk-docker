# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import urllib
from splunk.appserver.mrsparkle.lib import i18n
import itsi_module_common as utils
from ITOA.setup_logging import setup_logging
import json


class ItsiModuleEntitySourceTemplate(object):
    """
    Class to create, update, get, getCount, delete EntitySourceTemplate
    """

    """
    Class variables
    """
    _base_url = '/servicesNS/nobody/%s/configs/conf-inputs'
    _object_id_prefix = 'itsi_csv_import://'
    _base_args = '?output_mode=json&count=-1'
    ACCEPTED_KEYS = ['log_level', 'import_from_search', 'csv_location', 'search_string',
                     'index_earliest', 'index_latest', 'entity_title_field', 'selected_services', 'service_rel',
                     'entity_service_columns', 'entity_identifier_fields', 'entity_description_column',
                     'entity_informational_fields', 'entity_field_mapping', 'service_title_field',
                     'service_description_column', 'update_type', 'interval']
    CONF_FILE = 'inputs'
    _fields_to_split_by_comma = ['entity_identifier_fields', 'entity_informational_fields']

    _validation_error_messages = {
        'id_prefix_mismatch': _('Entity source template needs to be prefixed with module ID.')
    }

    _validation_info_messages = {
        'entity_template_missed': _('No entity source template defined.')
    }

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initializes the ItsiModuleEntitySourceTemplate object

        @type session_key: string
        @param session_key: the session key

        @type app: string
        @param app: the app context, defaults to SA-ITOA

        @type owner: string
        @param owner: the owner context, defaults to nobody

        @type logger: string
        @param logger: the logger
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.object_type = 'entity_source_template'

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def create(self, itsi_module, data, **kwargs):
        """
        Create inputs conf file

        If itsi_object_id is given, then grab the stanza from inputs.conf under itsi
        and write into conf under given module
        If itsi_object_id is not given, then emit payload directly to conf

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        data_to_post = {}
        new_stanza_name = ''
        entity_source_id = data.get('itsi_object_id')

        if entity_source_id:
            # Get inputs.conf content from itsi
            get_conf_response, get_conf_content = utils.get_conf_by_namespace(self.session_key, self.CONF_FILE)
            if get_conf_response.status != 200:
                self.logger.error('Error getting inputs.conf stanza %s', entity_source_id)
                raise utils.ItsiModuleError(status=400, message=_('Error getting inputs.conf stanza %s.') % entity_source_id)
            conf_content = json.loads(get_conf_content)
            entries = conf_content.get('entry')

            # Find target stanza in inputs.conf from itsi and filter out unwanted key/values
            stanza_content = self._get_target_stanza(entries, 'itsi_csv_import://%s' % entity_source_id)
            self.logger.debug('Found following mod input stanza to target: %s', stanza_content)
            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, stanza_content)

            # The stanza name needs to be prefixed by itsi_csv_import://
            kwargs = {'prefix': 'itsi_csv_import://'}
            new_stanza_name = utils.make_stanza_name(itsi_module, entity_source_id, **kwargs)

        else:
            if not data.get('name'):
                raise utils.ItsiModuleError(status=400, message=_('Bad Request: the key "name" does not exist in payload.'))
            new_stanza_name = data.get('name')
            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)

        # Add stanza name to payload and write to conf
        data_to_post['name'] = new_stanza_name
        self.logger.debug('Generated new mod input stanza: %s', new_stanza_name)
        self.logger.debug('Entity source template data: %s', json.dumps(data_to_post))
        create_conf_response, create_conf_content = utils.create_conf_stanza(self.session_key, self.CONF_FILE, data_to_post, itsi_module)
        if create_conf_response.status == 200 or create_conf_response.status == 201:
            return new_stanza_name
        else:
            self.logger.error('Error writing data to conf file: %s', create_conf_content)
            raise utils.ItsiModuleError(status=400, message=_('Error writing into conf file %s.') % create_conf_content)

    def get(self, itsi_module, object_id, **kwargs):
        """
        Returns the count of entity_source_template in a given module

        If itsi_module is specified as "-", returns counts of entity source templates for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested

        @type object_id: string
        @param object_id: ID of KPI base search being requested
        """
        encoded_prefix = urllib.quote_plus(self._object_id_prefix)
        if object_id is not None:
            object_id = (encoded_prefix + object_id)
        else:
            self._base_args = self._base_args + "&search=%s" % encoded_prefix

        # Get the endpoint for entity source templates
        entity_source_template_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, object_id)
        self.logger.debug('Attempting get from entity source template endpoint: %s', entity_source_template_endpoint)

        # Construct the response object based on the request for service_template
        response = utils.construct_get_response(entity_source_template_endpoint, self.object_type, object_id, self.session_key, [])

        # Parse the response, and split the entity_identifier_fields and entity_informational_fields by comma
        parsed_response = self._parse_all_identifier_informational_fields(response)

        self.logger.debug('Get response for entity source template %s in module %s: %s', object_id, itsi_module, json.dumps(parsed_response))
        return parsed_response

    def get_count(self, itsi_module, **kwargs):
        """
        Returns the count of entity_source_template in a given module

        If itsi_module is specified as "-", returns counts of entity source templates for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module that was requested
        """
        # Set up the endpoint
        entity_source_template_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        self.logger.debug('Attempting get_count from entity source template endpoint: %s', entity_source_template_endpoint)

        # Construct the response object based on the request for entity_source_template
        response = utils.construct_count_response(entity_source_template_endpoint, itsi_module, self.object_type, self.session_key)
        self.logger.debug('Get_count response for entity source template %s in module %s: %s', entity_source_template_endpoint, itsi_module, json.dumps(response))
        return response

    def update(self, itsi_module, object_id, data, **kwargs):
        """
        Update inputs conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: id of the object, it's also the stanza name in the conf file

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)
        response, content = utils.update_conf_stanza(self.session_key, self.CONF_FILE, object_id, data_to_post, itsi_module)
        if response.status == 200 or response.status == 201:
            self.logger.debug('Successfully updated entity source template %s in module %s', itsi_module, object_id)
            return object_id
        else:
            self.logger.error('Error writing into conf file %s', content)
            raise utils.ItsiModuleError(status=400, message=_('Failed updating object id %s: %s.') % (object_id, content))

    def delete(self, itsi_module, object_id, **kwargs):
        """
        Delete stanza from conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: None
        @return: return nothing or raise an exception
        """

        # Make sure that object_id is prefixed with itsi_csv_import:// if not already
        csv_import_search = ('itsi_csv_import://%s' % object_id) if not object_id.startswith('itsi_csv_import://') else object_id

        response, content = utils.delete_conf_stanza(self.session_key, self.CONF_FILE, csv_import_search, itsi_module)
        if response.status == 200 or response.status == 201:
            self.logger.debug('Successfully deleted entity source template %s in module %s', itsi_module, object_id)
            return
        else:
            self.logger.error('Error writing into conf file %s', content)
            raise utils.ItsiModuleError(status=400, message=_('Failed deleting object id %s: %s.') % (object_id, content))

    def validate(self, itsi_module, object_id):
        """
        Validates the entity source template objects

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: dictionary
        @return: dictionary of validation result type to actual contents
        """
        validation_errors = []
        validation_infos = []
        entity_source_templates = self.get(itsi_module, object_id)

        if len(entity_source_templates) == 0:
            validation_infos.append(
                [itsi_module, itsi_module, self._validation_info_messages['entity_template_missed']])

            self.logger.debug('Found following validation information for entity source template %s in module %s: %s',
                              object_id, itsi_module, validation_infos)

        else:
            for entity_source_template in entity_source_templates:
                if not entity_source_template.get('id', '').startswith(self._object_id_prefix + entity_source_template.get('source_itsi_module')):
                    validation_errors.append(
                        utils.generate_validation_error_line(entity_source_template, self._validation_error_messages['id_prefix_mismatch']))

            self.logger.debug('Found following validation errors for entity source template %s in module %s: %s',
                              object_id, itsi_module, validation_errors)

        return utils.construct_validation_result(errors=validation_errors, infos=validation_infos)

    def _parse_single_identifier_informational_fields(self, entity_source_template):
        """
        Goes through both the entity_informational_fields and entity_identifier_fields
        keys within each entity_source_template, splits the string by a comma, and then
        strips each string in that array

        @type entity_source_template: dict
        @param entity_source_template: Entity source template object
        """
        for field in self._fields_to_split_by_comma:
            if field in entity_source_template['content']:
                entity_source_template['content'][field] = map(lambda field: field.strip(), \
                    entity_source_template['content'][field].split(','))
            else:
                entity_source_template['content'][field] = []
        return entity_source_template

    def _parse_all_identifier_informational_fields(self, response):
        """
        Handles the cases where the returned entity source template object is a list of
        entity source templates, and when it's a single dict

        @type response: dict or list
        @param response: Response object returned from the server
        """
        if isinstance(response, list):
            return map(self._parse_single_identifier_informational_fields, response)
        return self._parse_single_identifier_informational_fields(response)

    def _get_target_stanza(self, entries, target_stanza):
        """
        Find stanza with the target stanza name

        @type entries: list
        @param entries: list of stanzas read from conf

        @target_stanza: string
        @param target_stanza: name of the target stanza to find

        @rtype: dict
        @return targeted stanza content
        """
        for entry in entries:
            if entry.get('name') == target_stanza:
                return entry.get('content')
        raise utils.ItsiModuleError(status=400, message=_('%s cannot be found in ITSI.') % target_stanza)
