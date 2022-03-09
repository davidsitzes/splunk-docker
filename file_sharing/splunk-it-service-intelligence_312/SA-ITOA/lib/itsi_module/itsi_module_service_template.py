# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import splunk
from splunk.appserver.mrsparkle.lib import i18n
from splunk.util import normalizeBoolean
from ITOA.setup_logging import setup_logging
import itsi_module_common as utils
from itsi_module_kpi_base_search import ItsiModuleKpiBaseSearch
from itsi_module_kpi_group import ItsiModuleKpiGroup


class ItsiModuleServiceTemplate(object):
    """
    Class to create, update, get, getCount, delete ServiceTemplate
    """

    """
    Class variables
    """
    _base_url = '/servicesNS/nobody/%s/configs/conf-itsi_service_template'
    _base_args = '?output_mode=json&count=-1'
    ACCEPTED_KEYS = ['title', 'description', 'entity_rules', 'recommended_kpis', 'optional_kpis']
    SUMMARY_KEYS = ['title', 'description', 'entity_rules']
    CONF_FILE = 'itsi_service_template'

    _validation_error_messages = {
        'id_prefix_mismatch': _('Service template ID needs to be prefixed with module ID.'),
        'title_required': _('Service template needs to contain a title.'),
        'atleast_1_recommended_kpi': _('Service template needs to contain at least 1 recommended KPI.'),
        'recommended_kpi_not_exported': _('Recommended KPI refers to KPI ID {} that is not part of an exported KPI group.'),
        'optional_kpi_not_exported': _('Optional KPI refers to KPI ID {} that is not part of an exported KPI group.')
    }

    _validation_info_messages = {
        'service_template_missed': _('No service template defined.'),
        'description_missed': _('Service template does not contain a description.')
    }

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initializes the ItsiModuleServiceTemplate object

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
        self.object_type = 'service_template'

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def create(self, itsi_module, data, **kwargs):
        """
        Create itsi_service_template conf file

        If itsi_object_id is given, then this endpoint can also accept 3 flags: include_kpi_base_search.
        entity_source_template_id and include_kpi_group, which indicate whether or not itsi_kpi_base_search.conf,
        inputs.conf and itsi_kpi_template.conf should be exported.

        If itsi_object_id is not given, then emit the payload directly to conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        service_id = data.get('itsi_object_id')
        data_to_post = {}
        if service_id:
            # Templatize service object by id
            templatize_response, templatize_content = utils.templatize_obj_by_id(self.session_key, 'service', service_id)
            if templatize_response.status != 200:
                self.logger.error('Error templatizing service: %s', service_id)
                raise utils.ItsiModuleError(status=400, message=_('Error templatizing service: %s') % service_id)
            service_object = json.loads(templatize_content)
            kpis = [kpi for kpi in service_object.get('kpis') if kpi.get('title') != 'ServiceHealthScore']
            service_object['kpis'] = kpis

            # Filter out unwanted keys and reformat some of the values
            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, service_object)

            # Construct service_template_id (stanza name) and include it in the payload
            service_template_id = utils.make_stanza_name(itsi_module, service_object.get('title'))
            data_to_post['name'] = service_template_id

            include_kpi_group = normalizeBoolean(data.get('include_kpi_group'))
            include_kpi_base_search = normalizeBoolean(data.get('include_kpi_base_search'))
            if not include_kpi_group and include_kpi_base_search:
                self.logger.warning(
                    'include_kpi_base_search cannot be true if include_kpi_group is false. Assuming include_kpi_base_search as false and continuing...')

            # If include_kpi_group is set to 1, then export itsi_kpi_template.conf based on the list of kpis and add return value to recommended_kpi
            elif include_kpi_group:
                kpi_group = ItsiModuleKpiGroup(self.session_key)
                kwargs = {'suffix': 'KPIs'}
                kpi_group_id = utils.make_stanza_name(itsi_module, service_object.get('title'), **kwargs)
                self.logger.debug('Creating KPI group for service %s: %s', service_id, kpi_group_id)
                results = kpi_group.create(itsi_module, {'itsi_object_id': kpi_group_id,
                                                         'kpis': service_object.get('kpis'),
                                                         'title': service_object.get('title') + ' KPIs',
                                                         'description': 'KPIs for %s' % service_object.get('title'),
                                                         'include_kpi_base_search': include_kpi_base_search})

                # Return type from kpi_group should be {kpi_group_id: <list of kpi_template_kpi_id>}
                recommended_kpis_list = results.values()[0]
                self.logger.debug('Generated following recommended KPIs: %s', recommended_kpis_list)
                if isinstance(recommended_kpis_list, list):
                    # Results should only have 1 key/value pair
                    data_to_post['recommended_kpis'] = ','.join(recommended_kpis_list)
                else:
                    self.logger.error('Error writing stanza %s into itsi_kpi_template file', results.keys()[0])
                    raise utils.ItsiModuleError(status=400, message=_('Error writing stanza %s into itsi_kpi_template file.') % results.keys()[0])
        else:
            # Construct service_template_id if not given
            service_template_id = data.get('name')
            if not service_template_id:
                service_template_id = utils.make_stanza_name(itsi_module, data.get('title'))
            # Filter out unwanted keys and re-format some values
            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)
            data_to_post['name'] = service_template_id

        create_conf_response, create_conf_content = utils.create_conf_stanza(self.session_key, self.CONF_FILE, data_to_post, itsi_module)
        if create_conf_response.status == 200 or create_conf_response.status == 201:
            self.logger.debug(
                'Created service template %s in module %s with payload: %s',
                service_template_id,
                itsi_module,
                data_to_post)
            return service_template_id
        else:
            raise utils.ItsiModuleError(status=400, message=_('Error writing into conf file %s.') % create_conf_content)

    def get(self, itsi_module, object_id, **kwargs):
        """
        Returns the count of service_template in a given module

        If itsi_module is specified as "-", returns counts of service templates for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested

        @type object_id: string
        @param object_id: ID of service template being requested
        """
        if normalizeBoolean(kwargs.get('get_summary', False)):
            return self.get_summary(itsi_module, **kwargs)

        req_args = {}

        # Determine whether resolve_kpis flag is present, and parse into python type if so
        resolve_kpis = normalizeBoolean(kwargs['resolve_kpis']) if 'resolve_kpis' in kwargs else False

        # Determine whether resolve_kpis_from_itsi flag is present and parse into python type if so
        resolve_kpis_from_itsi = normalizeBoolean(kwargs['resolve_kpis_from_itsi']) if 'resolve_kpis_from_itsi' in kwargs else False

        # Both flags cannot be allowed to be set, raise a BadRequest
        if resolve_kpis and resolve_kpis_from_itsi:
            raise splunk.BadRequest(_('Either the flag "resolve_kpis" or "resolve_kpis_from_itsi" can be set, not both.'))

        # If flag 'resolve_kpis_from_itsi' is set, get the filter and fields params from the URL
        if resolve_kpis_from_itsi:
            kpi_fields_string = kwargs['fields'] if kwargs.has_key('fields') else ''
            kpi_filter_string = kwargs['filter'] if kwargs.has_key('filter') else ''

            # Build a request object from all URL params to return correct output to service template
            # Even though both 'resolve_kpis' and 'resolve_kpis_from_itsi' are given, only one can be true
            # due to previous check
            try:
                kpi_filter = json.loads(kpi_filter_string) if kpi_filter_string else {'$and': []}
            except Exception as e:
                raise splunk.BadRequest(_('The filter provided is invalid JSON.'))

            payload_filter = self._compute_filter(itsi_module, kpi_filter)
            payload_fields = self._compute_fields(kpi_fields_string)

            if payload_filter:
                req_args['filter'] = json.dumps(payload_filter)
            if kpi_fields_string:
                req_args['fields'] = payload_fields

        # Args that determine whether KPIs are to be resolved from itsi_module_interface
        # or from KV Store
        resolve_args = {
            'resolve_kpis': resolve_kpis,
            'resolve_kpis_from_itsi': resolve_kpis_from_itsi
        }

        # Get the endpoint for service templates
        service_template_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, object_id)
        self.logger.debug('Attempting get from service template endpoint: %s', service_template_endpoint)

        # Construct the response object based on the request for service_template
        response = utils.construct_get_response(service_template_endpoint, self.object_type, object_id, self.session_key, ['entity_rules'])

        # Then, process service template(s) comma separated lists for recommended/optional KPIs and resolve KPIs
        # from either KV Store or module interface if requested
        parsed_response = self._make_optional_recommended_kpis_list(response, req_args, resolve_args, itsi_module)

        self.logger.debug('Get response for service template %s in module %s: %s', object_id, itsi_module, json.dumps(response))
        return parsed_response

    def get_summary(self, itsi_module, **kwargs):
        """
        Get basic information of services in a module
        @type itsi_module: string
        @param itsi_module: ITSI module requested        
        """
        service_template_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        return utils.get_simple_response(service_template_endpoint, self.SUMMARY_KEYS, self.session_key, itsi_module)

    def get_count(self, itsi_module, **kwargs):
        """
        Returns the count of service_template in a given module

        If itsi_module is specified as "-", returns counts of service templates for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested
        """
        # Set up the endpoint
        service_template_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        self.logger.debug('Attempting get_count from service template endpoint: %s', service_template_endpoint)

        # Construct the response object based on the request for service_template
        response = utils.construct_count_response(service_template_endpoint, itsi_module, self.object_type, self.session_key)
        self.logger.debug('Get_count response for service template %s in module %s: %s', service_template_endpoint, itsi_module, json.dumps(response))
        return response

    def update(self, itsi_module, object_id, data, **kwargs):
        """
        Update itsi_service_template conf file

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
            self.logger.debug('Successfully updated service template %s in module %s', itsi_module, object_id)
            return object_id
        else:
            self.logger.error('Failed to update service template object id %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed updating object id %s: %s.') % (object_id, content))

    def delete(self, itsi_module, object_id, **kwargs):
        """
        Delete stanza from itsi_service_template conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: None
        @return: return nothing or raise an exception
        """
        kpi_group = ItsiModuleKpiGroup(self.session_key)
        try:
            kpi_group.delete(itsi_module, object_id + '_KPIs')
        except utils.ItsiModuleError as e:
            self.logger.error('Failed to delete dependent kpi group. {}'.format(e.message))

        try:
            existing_groups = kpi_group.get(itsi_module, None)
            base_searches_used_by_other_service = set()
            for group in existing_groups:
                for kpi in group.get('content').get('kpis'):
                    base_searches_used_by_other_service.add(kpi.get('base_search_id'))

            kpi_base_search = ItsiModuleKpiBaseSearch(self.session_key)
            for search in kpi_base_search.get_existing_base_search_keys_from_conf(itsi_module):
                if search not in base_searches_used_by_other_service:
                    kpi_base_search.delete(itsi_module, search)
        except Exception as e:
            self.logger.error('Failed to delete dependent kpi base search. {}'.format(e.message))

        response, content = utils.delete_conf_stanza(self.session_key, self.CONF_FILE, object_id, itsi_module)
        if response.status == 200 or response.status == 201:
            self.logger.debug('Successfully deleted service template %s in module %s', itsi_module, object_id)
            return
        else:
            self.logger.error('Failed deleting service template object id: %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed deleting object id %s: %s.') % (object_id, content))

    def validate(self, itsi_module, object_id):
        """
        Validates the service template objects

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: dictionary
        @return: dictionary of validation result type to actual contents
        """
        validation_errors = []
        validation_infos = []
        service_templates = self.get(itsi_module, object_id)

        if len(service_templates) == 0:
            validation_infos.append(
                [itsi_module, itsi_module, self._validation_info_messages['service_template_missed']])

            self.logger.debug('Found following validation information for service template %s in module %s: %s',
                              object_id, itsi_module, validation_infos)

        else:
            kpi_group_object = ItsiModuleKpiGroup(self.session_key)
            kpi_groups = kpi_group_object.get(itsi_module, None)
            self.logger.debug('kpi_groups is: %s', kpi_groups)

            def get_kpi_template_ids_from_kpi_group(kpi_group):
                return map(lambda kpi: kpi.get('kpi_template_kpi_id'), kpi_group.get('kpis'))

            kpi_template_kpi_ids = reduce(
                lambda id_list, kpi_group: id_list + get_kpi_template_ids_from_kpi_group(kpi_group.get('content', {})), kpi_groups, [])

            for service_template in service_templates:
                if not service_template.get('id', '').startswith(service_template.get('source_itsi_module')):
                    validation_errors.append(
                        utils.generate_validation_error_line(service_template, self._validation_error_messages['id_prefix_mismatch']))

                if not service_template.get('content', {}).get('title'):
                    validation_errors.append(
                        utils.generate_validation_error_line(service_template, self._validation_error_messages['title_required']))

                if not service_template.get('content', {}).get('description'):
                    validation_infos.append(
                        utils.generate_validation_error_line(service_template, self._validation_info_messages['description_missed']))

                # Extracts the recommended_kpis string to make sure at least 1 recommended KPI is provided
                recommended_kpis = service_template.get('content', {}).get('recommended_kpis', [])

                if len(recommended_kpis) == 0:
                    validation_errors.append(
                        utils.generate_validation_error_line(service_template, self._validation_error_messages['atleast_1_recommended_kpi']))

                # Now, extracts optional_kpis string, since it's not required
                optional_kpis = service_template.get('content', {}).get('optional_kpis', [])

                for kpi in recommended_kpis:
                    if kpi not in kpi_template_kpi_ids:
                        validation_errors.append(
                            utils.generate_validation_error_line(
                                service_template,
                                self._validation_error_messages['recommended_kpi_not_exported'].format(kpi)))

                for kpi in optional_kpis:
                    if kpi not in kpi_template_kpi_ids:
                        validation_errors.append(
                            utils.generate_validation_error_line(
                                service_template,
                                self._validation_error_messages['optional_kpi_not_exported'].format(kpi)))

            self.logger.debug('Found following validation errors for service template %s in module %s: %s', object_id, itsi_module, validation_errors)
            self.logger.debug('Found following validation information for service template %s in module %s: %s', object_id, itsi_module, validation_infos)

        return utils.construct_validation_result(errors=validation_errors, infos=validation_infos)

    def _build_module_kpi_mapping(self, itsi_module, resolve_path, req_args, **kwargs):
        """
        Build the mapping between modules, KPI IDs, and KPI objects by calling build_module_kpi_mapping in ItsiModuleKpiGroup

        @type itsi_module: string
        @param itsi_module: ITSI module that is being requested for KPI groups

        @type resolve_path: string
        @param resolve_path: This can be either 'kv_store' or 'itsi_module_interface', and it determines
        whether to build the mapping and resolve the KPIs from either calling the itsi_module_interface
        KPI group endpoint or the KV store KPI template endpoint

        @type req_args: dict
        @param req_args: Arguments that are provided to filter or request specific fields when making
        a request from the KV store
        """
        if resolve_path == 'itsi_module_interface':
            self.logger.debug('resolve_kpis flag has been set to true.  Building module-KPI mapping from itsi_module_interface...')
            kpi_groups = ItsiModuleKpiGroup(self.session_key)
            return kpi_groups.build_module_kpi_mapping(itsi_module=itsi_module)
        else:
            self.logger.debug('resolve_kpis_from_itsi has been set to true.  Building module-KPI mapping from KV store...')
            return utils.build_module_kpi_mapping_kv_store(session_key=self.session_key, kv_store_args=req_args)

    def _strip_kpi(self, kpi):
        """
        Strips the leading and trailing characters of each KPI

        @type kpi: string
        @param kpi: KPI ID
        """
        return kpi.strip()

    def _parse_recommended_and_optional_kpis(self, service_template, itsi_module, **kwargs):
        """
        Parses out recommended KPIs comma separated string to an array

        Parses out optional KPIs comma separated string to an array if field exists

        If string ends up being empty for optional KPIs, deletes it out

        @type service_template: dict
        @param service_template: Service template dictionary

        @type itsi_module: string
        @param itsi_module: Requested ITSI module
        """
        # Goes through keys 'recommended_kpis' and 'optional_kpis'.  If they exist, split by comma
        # into list, and if they exist but are empty strings, initialize to empty list
        keys_to_check = ['recommended_kpis', 'optional_kpis']
        for key in keys_to_check:
            if key not in service_template['content'] or service_template['content'][key] == '':
                service_template['content'][key] = []
            else:
                # Stripping leading/trailing characters for each KPI
                service_template['content'][key] = map(self._strip_kpi, service_template['content'][key].split(','))
        return service_template

    def _compute_fields(self, kpi_fields_string):
        """
        Computes the fields string to only return the number of fields requested
        Regardless of fields requested, every request must return 'source_itsi_da'
        and 'kpis.kpi_template_kpi_id' so that the module mapping can be generated
        in order to resolve the KPIs

        @type kpi_fields_string: string
        @param kpi_fields_string: comma separated string of fields requested in the URL along
        with the base fields requested above
        """
        base_fields = ['source_itsi_da', 'kpis.kpi_template_kpi_id']
        kpi_fields = (kpi_fields_string.split(',') + base_fields) if kpi_fields_string else base_fields
        return ','.join(kpi_fields)

    def _compute_filter(self, itsi_module, url_filter):
        """
        If a module context is given that isn't a request for all modules, returns the
        base filter that includes the requested 'source_itsi_da' as the module context

        @type itsi_module: string
        @param itsi_module: Requested ITSI module

        @type url_filter: dict
        @param url_filter: Items to filter the query to KV store by
        """
        base_filter = {
            '$and': [
            ]
        }
        if itsi_module == '-':
            base_filter = {}
        else:
            base_filter['$and'].append({'source_itsi_da': itsi_module})
            base_filter['$and'] = base_filter['$and'] + url_filter['$and']
        return base_filter

    def _map_kpi_id_to_payload(self, module_kpi_mapping, kpi_id, service_template):
        """
        Utility method called by map which returns the KPI object given a KPI ID

        @type module_kpi_mapping: dict
        @param module_kpi_mapping: A mapping from the module to KPI IDs, and below that the KPI IDs
        to the physical KPI objects

        @type kpi_id: string
        @param kpi_id: The ID of the KPI being retrieved from the map

        @param service_template: dict
        @type service_template: Service template object
        """
        return module_kpi_mapping[service_template['source_itsi_module']][kpi_id]

    def _resolve_kpis(self, module_kpi_mapping, service_template):
        """
        Resolves the KPIs given in a service template by using the mapping between modules and KPI ids
        to replace each KPI id in the reccommended/optional KPI lists with their entire objects

        @type module_kpi_mapping: dict
        @param module_kpi_mapping: A mapping from the module to KPI IDs, and below that the KPI IDs
        to the physical KPI objects

        @type service_template: dict
        @param service_template: Service template object
        """
        # Aliases to cut down on amount of typing in subsequent lines
        rec_kpis = service_template['content']['recommended_kpis']
        opt_kpis = service_template['content']['optional_kpis']

        # Map all of the KPI ids to their physical objects
        service_template['content']['recommended_kpis'] = \
            map(lambda rec_kpi: self._map_kpi_id_to_payload(module_kpi_mapping, rec_kpi, service_template), rec_kpis)
        service_template['content']['optional_kpis'] = \
            map(lambda opt_kpi: self._map_kpi_id_to_payload(module_kpi_mapping, opt_kpi, service_template), opt_kpis)
        return service_template

    def _make_optional_recommended_kpis_list(self, response, req_args, resolve_args, itsi_module):
        """
        Converts the response from an endpoint from the comma separated list of recommended and optional KPIs to arrays.

        Either does this for a single service template if requested by an ID, or for all the service templates returned in the list

        If resolve_kpis is specified as true, fetches the KPI groups from its endpoint,
        builds a mapping from modules to their KPIs by ID, and then resolves the KPIs
        in the place of the ID

        @type response: dict or array
        @param response: Either a single service template dict or a list of service templates

        @type req_args: dict
        @param req_args: Arguments given to itsi_module_interface which provide the necessary filter and fields
        requested arguments if KPIs should be resolved from KV store

        @type resolve_args: dict
        @param resolve_args: Arguments given to determine whether KPIs should be resolved, and if so,
        whether to be resolved via itsi_module_interface or KV store

        @type itsi_module: string
        @param itsi_module: Requested ITSI module
        """
        # Get the mapping between module(s) requested and their KPIs
        # Only one of these can evaluate by definition, since both flags set to true will throw
        # an exception up the call stack
        module_kpi_mapping = {}
        if resolve_args['resolve_kpis']:
            module_kpi_mapping = self._build_module_kpi_mapping(itsi_module, 'itsi_module_interface', req_args)
        if resolve_args['resolve_kpis_from_itsi']:
            module_kpi_mapping = self._build_module_kpi_mapping(itsi_module, 'kv_store', req_args)

        # Single service template request by ID
        if isinstance(response, dict):
            response = self._parse_recommended_and_optional_kpis(response, response['source_itsi_module'])
            if resolve_args['resolve_kpis'] or resolve_args['resolve_kpis_from_itsi']:
                return self._resolve_kpis(module_kpi_mapping, response)

        # Either request for all service templates for single module or all modules
        else:
            for service_template in response:
                # Parse the recommended and optional KPIs to an array from their comma separated string
                parsed_service_template = self._parse_recommended_and_optional_kpis(
                    service_template, service_template['source_itsi_module'])
                service_template = self._resolve_kpis(module_kpi_mapping, parsed_service_template) \
                    if resolve_args['resolve_kpis'] or resolve_args['resolve_kpis_from_itsi'] else parsed_service_template
        return response
