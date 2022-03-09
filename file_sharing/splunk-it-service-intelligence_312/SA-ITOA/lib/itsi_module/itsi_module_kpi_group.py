# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
import itsi_module_common as utils
from itsi_module_kpi_base_search import ItsiModuleKpiBaseSearch


class ItsiModuleKpiGroup(object):
    """
    Class to create, update, get, getCount, delete KpiGroup
    """

    """
    Class variables
    """
    _base_url = '/servicesNS/nobody/%s/configs/conf-itsi_kpi_template'
    _base_args = '?output_mode=json&count=-1'
    ACCEPTED_KEYS = ['title', 'description', '_owner', 'source_itsi_da', 'kpis']
    CONF_NAME = 'itsi_kpi_template'

    _validation_error_messages = {
        'id_prefix_mismatch': _('KPI template ID needs to be prefixed with module ID.'),
        'title_required': _('KPI template needs to contain a title.'),
        'description_required': _('KPI template needs to contain a description.'),
        'atleast_1_kpi': _('KPI template needs to contain at least 1 KPI.'),
        'kpi_id_prefix_mismatch': _('ID for KPI {} needs to be prefixed with module ID.'),
        'kpi_base_search_not_exported': _('KPI {} refers to base search ID {} that is not part of an exported KPI base search.'),
        'kpi_base_search_metric_not_exported': _('KPI {} refers to base search ID {} and base search metric {} that is not part of an exported KPI base search.')
    }

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initializes the ItsiModuleKpiGroup object

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
        self.object_type = 'kpi_group'

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def create(self, itsi_module, data, **kwargs):
        """
        Create itsi_kpi_template conf file

        If itsi_object_id is given, then this endpoint would also require a list
        of kpi titles to be grouped.
        If itsi_object_id is not given, then emit the payload directly to conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        kpi_group_id = data.get('itsi_object_id')
        # If kpi_group_id is not given then construct the id
        if not kpi_group_id:
            kpi_template_title = data.get('title')
            # Title should not be empty
            if kpi_template_title:
                kwargs = {'suffix': 'KPIs'}
                kpi_group_id = utils.make_stanza_name(itsi_module, kpi_template_title, **kwargs)
            else:
                self.logger.error('KPI group title missing from the payload')
                raise utils.ItsiModuleError(status=400, message=_('KPI group title is missing from the payload.'))

        # If include_kpi_base_search is set to true, then export itsi_kpi_base_search.conf based on base_search_id_list
        if data.get('include_kpi_base_search') is True:
            # Get base_search_id useds in all kpis within this kpi group and store in a list
            # No duplicated base_search_id allowed
            base_search_id_set = set([kpi.get('base_search_id') for kpi in data.get('kpis') if kpi.get('search_type') == 'shared_base'])
            base_search_id_list = list(base_search_id_set)
            if not base_search_id_list:
                self.logger.info('No KPI base search id found in current KPI group')
            else:
                kpi_base_search_id_mapping = {}
                kpi_base_search_id_metrics_mapping = {}
                self.logger.debug('Creating templatized base searches for KPI group %s: %s', kpi_group_id, base_search_id_list)
                base_search_instance = ItsiModuleKpiBaseSearch(self.session_key)
                # Create a conf stanza for each base search id
                for base_search_id in base_search_id_list:
                    base_search_new_id_with_metrics_mapping = base_search_instance.create(itsi_module, {'itsi_object_id': base_search_id})
                    # Set mapping between old base search id and newly returned base search id
                    kpi_base_search_id_mapping[base_search_id] = base_search_new_id_with_metrics_mapping.keys()[0]
                    # Set mapping between newly returned base search id, its metrics and old key and new key mapping for each metric
                    kpi_base_search_id_metrics_mapping.update(base_search_new_id_with_metrics_mapping)

                # Update kpis with the new base_search id ad new metric key
                self.logger.debug('Updating KPIs with the following base search id mappings: %s', json.dumps(kpi_base_search_id_mapping))
                self.logger.debug('Updating KPIs with the following base search metric mappings: %s', json.dumps(kpi_base_search_id_metrics_mapping))
                data['kpis'] = self._update_kpis(itsi_module, data.get('kpis'), kpi_base_search_id_mapping, kpi_base_search_id_metrics_mapping)

        # Set kpi_template_kpi_id
        data['kpis'] = self._set_kpi_template_kpi_id(itsi_module, data.get('kpis'))
        # Fetch a list of kpi_template_kpi_id
        kpi_template_kpi_id_list = [kpi.get('kpi_template_kpi_id') for kpi in data.get('kpis')]

        # Filter out non-accepted keys
        data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)

        # Set _owner to nobody and source_itsi_da to itsi_module if they are not given
        if not data.get('_owner'):
            data_to_post['_owner'] = 'nobody'
        if not data.get('source_itsi_da'):
            data_to_post['source_itsi_da'] = itsi_module

        # Set name and write into conf
        data_to_post['name'] = kpi_group_id
        response, content = utils.create_conf_stanza(self.session_key, self.CONF_NAME, data_to_post, itsi_module)
        if response.status == 200 or response.status == 201:
            response = {kpi_group_id: kpi_template_kpi_id_list}
            self.logger.debug(
                'Created KPI template %s in module %s with following mapping: %s',
                kpi_group_id,
                itsi_module,
                json.dumps(response))
            return response
        else:
            self.logger.error('Error writing KPI template %s in module %s conf', kpi_group_id, itsi_module)
            raise utils.ItsiModuleError(status=400, message=_('Error writing into conf file %s.') % content)

    def get(self, itsi_module, object_id, **kwargs):
        """
        Returns the kpi_group in a given module given an id, or all kpi groups in a module

        If itsi_module is specified as "-", returns counts of kpi groups for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested

        @type object_id: string
        @param object_id: ID of KPI group being requested
        """

        url = self._base_url
        service_id = kwargs.get('service_id')

        # Get the endpoint for KPI groups
        kpi_group_endpoint = utils.get_object_endpoint(url, self._base_args, itsi_module, object_id)
        self.logger.debug('Attempting get from KPI group endpoint: %s', kpi_group_endpoint)

        # Construct the response object based on the request for kpi_template
        response = utils.construct_get_response(kpi_group_endpoint, self.object_type, object_id, self.session_key, ['kpis'])

        # Add the necessary fields to each KPI in order to ensure proper operation of KPI Thresholding Template
        parsed_response = self._add_aggregate_and_entity_fields_for_thresholding(response)

        self.logger.debug('Get response for KPI group %s in module %s: %s', object_id, itsi_module, json.dumps(parsed_response))
        if service_id is not None and service_id != '':
            from itsi_module_service_template import ItsiModuleServiceTemplate
            service_template_instance = ItsiModuleServiceTemplate(self.session_key, self.app, self.owner, self.logger)
            services = service_template_instance.get(itsi_module, None)
            return utils.filter_kpis(parsed_response, services, service_id)
        return parsed_response

    def get_count(self, itsi_module, **kwargs):
        """
        Returns the count of kpi_group in a given module

        If itsi_module is specified as "-", returns counts of kpi groups for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested
        """
        # Set up the endpoint and make the request
        kpi_group_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        self.logger.debug('Attempting get_count from KPI group endpoint: %s', kpi_group_endpoint)

        # Construct the response object based on the request for kpi_template
        response = utils.construct_count_response(kpi_group_endpoint, itsi_module, self.object_type, self.session_key)
        self.logger.debug('Get_count response for KPI group %s in module %s: %s', kpi_group_endpoint, itsi_module, json.dumps(response))
        return response

    def update(self, itsi_module, object_id, data, **kwargs):
        """
        Update itsi_kpi_template conf file stanza

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: object id (stanza name)

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)
        response, content = utils.update_conf_stanza(self.session_key, self.CONF_NAME, object_id, data_to_post, itsi_module)
        if response.status == 200:
            self.logger.debug('Successfully updated KPI group %s in module %s', itsi_module, object_id)
            return object_id
        else:
            self.logger.error('Failed to update KPI group object id %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed updating object id %s: %s.') % (object_id, content))

    def delete(self, itsi_module, object_id, **kwargs):
        """
        Delete a specific itsi_kpi_template conf file stanza

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: object id (stanza name)

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        response, content = utils.delete_conf_stanza(self.session_key, self.CONF_NAME, object_id, itsi_module)
        if response.status == 200:
            self.logger.debug('Successfully deleted KPI group %s in module %s', itsi_module, object_id)
            return
        else:
            self.logger.error('Failed deleting KPI group object id: %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed deleting object id %s: %s.') % (object_id, content))

    def validate(self, itsi_module, object_id):
        """
        Validates the KPI group objects

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: dictionary
        @return: dictionary of validation result type to actual contents
        """
        validation_errors = []
        kpi_groups = self.get(itsi_module, object_id)
        kpi_base_search_object = ItsiModuleKpiBaseSearch(self.session_key)
        kpi_base_searches = kpi_base_search_object.get(itsi_module, None)

        def get_metric_ids_from_base_search(kpi_base_search):
            return map(lambda metric: metric.get('_key'), kpi_base_search.get('content', {}).get('metrics'))

        def make_kpi_base_search_dictionary(kpi_list, kpi_base_search):
            kpi_list[kpi_base_search.get('id')] = get_metric_ids_from_base_search(kpi_base_search)
            return kpi_list

        kpi_base_search_id_to_metric = reduce(make_kpi_base_search_dictionary, kpi_base_searches, {})

        for kpi_group in kpi_groups:
            if not kpi_group.get('id', '').startswith(kpi_group.get('source_itsi_module')):
                validation_errors.append(
                    utils.generate_validation_error_line(kpi_group, self._validation_error_messages['id_prefix_mismatch']))

            if not kpi_group.get('content', {}).get('title'):
                validation_errors.append(
                    utils.generate_validation_error_line(kpi_group, self._validation_error_messages['title_required']))

            if not kpi_group.get('content', {}).get('description'):
                validation_errors.append(
                    utils.generate_validation_error_line(kpi_group, self._validation_error_messages['description_required']))

            if len(kpi_group.get('content', {}).get('kpis')) == 0:
                validation_errors.append(
                    utils.generate_validation_error_line(kpi_group, self._validation_error_messages['atleast_1_kpi']))

            for kpi in kpi_group.get('content', {}).get('kpis'):
                if not kpi.get('kpi_template_kpi_id', '').startswith(kpi_group.get('source_itsi_module')):
                    validation_errors.append(
                        utils.generate_validation_error_line(
                            kpi_group,
                            self._validation_error_messages['kpi_id_prefix_mismatch'].format(kpi.get('title'))))

                if kpi.get('search_type') == 'shared_base':
                    if kpi.get('base_search_id') not in kpi_base_search_id_to_metric:
                        validation_errors.append(
                                utils.generate_validation_error_line(
                                    kpi_group,
                                    self._validation_error_messages['kpi_base_search_not_exported']
                                        .format(kpi.get('title'), kpi.get('base_search_id'))))
                    elif kpi.get('base_search_metric') not in kpi_base_search_id_to_metric[kpi.get('base_search_id')]:
                        validation_errors.append(
                                utils.generate_validation_error_line(
                                    kpi_group,
                                    self._validation_error_messages['kpi_base_search_metric_not_exported']
                                        .format(kpi.get('title'),
                                                kpi.get('base_search_id'),
                                                kpi.get('base_search_metric'))))

        self.logger.debug('Found following validation errors for KPI group %s in module %s: %s', object_id, itsi_module, validation_errors)
        return utils.construct_validation_result(errors=validation_errors)

    def build_module_kpi_mapping(self, itsi_module, **kwargs):
        """
        Build the mapping between modules, KPI IDs, and KPI objects
        Sample object:
        {
            'DA-ITSI-TEST': {
                'KPI-ID-1': {
                    ...
                },
                'KPI-ID-2': {
                    ...
                }
            }
        }

        @type itsi_module: string
        @param itsi_module: ITSI module that is being requested for KPI groups
        """
        # Initialize the module-KPI mapping, and then request all modules' KPI groups
        request_module = itsi_module if itsi_module else '-'
        module_kpi_mapping = {}
        response = self.get(itsi_module=request_module, object_id=None)

        # Build the mapping, and add fields linking back to the parent KPI template ID and title
        for kpi_group in response:
            itsi_module = kpi_group['content']['source_itsi_da']
            if itsi_module not in module_kpi_mapping:
                module_kpi_mapping[itsi_module] = {}
            for kpi in kpi_group['content']['kpis']:
                kpi['parent_kpi_template_id'] = kpi_group['id']
                kpi['parent_kpi_template_title'] = kpi_group['content']['title']
                module_kpi_mapping[itsi_module][kpi['kpi_template_kpi_id']] = kpi
        return module_kpi_mapping

    def _add_aggregate_and_entity_fields_for_thresholding(self, response):
        """
        Adds the fields 'search_time_series_aggregate' and 'search_time_series_entities' to the
        response object within each KPI so that the fields get properly picked up by the thresholding
        template in the module detail page

        @type response: dict
        @param response: Response object for KPI groups formatted to itsi_module_interface standards
        """
        parsed_response = response
        for kpi_group in parsed_response:
            for kpi in kpi_group['content']['kpis']:
                has_aggregate_search = True if 'aggregate_thresholds' in kpi \
                    and 'search' in kpi['aggregate_thresholds'] else False
                has_entities_search = True if 'entity_thresholds' in kpi \
                    and 'search' in kpi['entity_thresholds'] else False
                kpi['search_time_series_aggregate'] = kpi['aggregate_thresholds']['search'] if \
                    has_aggregate_search else ''
                kpi['search_time_series_entities'] = kpi['entity_thresholds']['search'] if \
                    has_entities_search else ''

        return parsed_response

    def _set_kpi_template_kpi_id(self, itsi_module, kpi_obj_list):
        """
        Set kpi_template_kpi_id for each kpi with constructed id value

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type kpi_obj_list: list
        @param kpi_obj_list: a list of kpi objects

        @rtype: list
        @return: a list with updated kpi objects
        """
        for kpi in kpi_obj_list:
            kpi['kpi_template_kpi_id'] = utils.make_stanza_name(itsi_module, kpi.get('title'))
        return kpi_obj_list

    def _update_kpis(self, itsi_module, kpis, kpi_base_search_id_mapping, kpi_base_search_id_metrics_mapping):
        """
        Update kpis with new base_search_id

        @type kpis: list
        @param kpis: list of kpi object

        @type kpi_base_search_id_mapping: dict
        @param kpi_base_search_id_mapping: mapping between old base search id and new base search id

        @type kpi_base_search_id_metrics_mapping: dict
        @param kpi_base_search_id_metrics_mapping: mapping between new base search id, its metric and key mapping for each metric

        @rtype: list
        @return: list of updated kpi objects
        """
        updated_kpis = []
        for kpi in kpis:
            if kpi.get('search_type') == 'shared_base':
                old_base_search_id = kpi.get('base_search_id')
                old_base_search_metric = kpi.get('base_search_metric')
                new_base_search_id = kpi_base_search_id_mapping.get(old_base_search_id)
                new_metrics_key = kpi_base_search_id_metrics_mapping.get(new_base_search_id).get('metrics').get(old_base_search_metric)
                if old_base_search_id and old_base_search_id in kpi_base_search_id_mapping and new_metrics_key and new_base_search_id in kpi_base_search_id_metrics_mapping:
                    kpi['base_search_id'] = new_base_search_id
                    kpi['base_search_metric'] = new_metrics_key

                    updated_kpis.append(kpi)
                    self.logger.debug('Update %s KPI in in module %s: base_search_id  from %s to %s, base_search_metric from %s to %s', kpi.get('title'), itsi_module,
                                      old_base_search_id, new_base_search_id, old_base_search_metric, new_metrics_key)
            else:
                updated_kpis.append(kpi)
        return updated_kpis
