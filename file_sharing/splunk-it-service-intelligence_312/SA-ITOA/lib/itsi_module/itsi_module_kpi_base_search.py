# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
import itsi_module_common as utils


class ItsiModuleKpiBaseSearch(object):
    """
    Class to create, update, get, getCount, delete KpiBaseSearch
    """

    """
    Class variables
    """
    _base_url = '/servicesNS/nobody/%s/configs/conf-itsi_kpi_base_search'
    _base_args = '?output_mode=json&count=-1'
    ACCEPTED_KEYS = ['description', 'title', '_owner', 'base_search', 'metrics', 'is_entity_breakdown', 'is_service_entity_filter',
                     'entity_id_fields', 'entity_alias_filtering_fields', 'alert_period', 'search_alert_earliest', 'alert_lag',
                     'metric_qualifier', 'source_itsi_da']
    CONF_NAME = 'itsi_kpi_base_search'

    _validation_error_messages = {
        'id_prefix_mismatch': _('KPI base search ID needs to be prefixed with module ID.'),
        'title_prefix_mismatch': _('KPI base search title needs to be prefixed with module ID.'),
        'atleast_1_metric': _('KPI base search needs to contain at least 1 metric.'),
        'metric_id_missing': _('KPI base search metric {} must have an ID.')
    }

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initializes the ItsiModuleKpiBaseSearch object

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
        self.object_type = 'kpi_base_search'

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def create(self, itsi_module, data, **kwargs):
        """
        Create itsi_kpi_base_search conf file

        If itsi_object_id is given, then templatize the object based on id and write into conf
        If itsi_object_id is not given, then emit payload directly to conf

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: dict
        @return: {<new base_search_key>: {'metrics': {<old_metrics_key>: <new_metrics_key>}}}
        """
        base_search_id = data.get('itsi_object_id')
        metric_key_mapping = {}
        existing_base_search_ids = self.get_existing_base_search_keys_from_conf(itsi_module)
        if base_search_id:
            if base_search_id in existing_base_search_ids:
                return {base_search_id: {'metrics': self.get(itsi_module, base_search_id)['content']['metrics']}}
            # Contruct a mapping between old metric keys and new metric keys
            self._set_metrics_key_mapping(base_search_id, metric_key_mapping)

            # Templatize the KPI base search
            templatize_response, templatize_content = utils.templatize_obj_by_id(self.session_key, 'kpi_base_search',
                                                                                 base_search_id)
            if templatize_response.status != 200:
                self.logger.error('Failed templatizing %s', base_search_id)
                raise utils.ItsiModuleError(status=400, message=_('Failed templatizing %s.') % base_search_id)
            self.logger.debug('Templatized base search id %s: %s', base_search_id, templatize_content)
            base_search_object = json.loads(templatize_content)

            # Construct stanza name and filter out unwanted key/value pairs
            base_search_conf_stanza_name = utils.make_stanza_name(itsi_module, base_search_object.get('title'))

            # Add _key for each metric
            for metric in base_search_object.get('metrics'):
                metric['_key'] = utils.replace_special_chars_with_underscore(metric.get('title').strip())

            # Prefix itsi_module to kpi base search title
            new_title = itsi_module + ':' + base_search_object.get('title')
            base_search_object['title'] = new_title

            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, base_search_object)

        # If itsi_object_id is not given, then emit the payload to conf directly
        else:
            # Construct stanza name using title if 'name' is not givin in payload
            # Othwerwise use name as stanza name
            base_search_conf_stanza_name = data.get('name')
            if not base_search_conf_stanza_name:
                base_search_conf_stanza_name = utils.make_stanza_name(itsi_module, data.get('title'))

            # Contruct a mapping between old metric keys and new metric keys
            # And set new key back to metric
            metrics = data.get('metrics')
            for metric in metrics:
                new_key = utils.replace_special_chars_with_underscore(metric.get('title').strip())
                metric_key_mapping[metric.get('_key')] = new_key
                metric['_key'] = new_key

            # Filter out unwanted key/value pairs
            data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)

        # Add stanza name to payload and write to conf
        data_to_post['name'] = base_search_conf_stanza_name
        # Generate base search stanza if base search id does not exist

        # Refresh the existing ids before post, this won't fix the racing issue for good.
        existing_base_search_ids = self.get_existing_base_search_keys_from_conf(itsi_module)
        if base_search_conf_stanza_name not in existing_base_search_ids:
            create_conf_response, create_conf_content = utils.create_conf_stanza(self.session_key, self.CONF_NAME, data_to_post, itsi_module)
            if create_conf_response.status == 201:
                response = {base_search_conf_stanza_name: {'metrics': metric_key_mapping}}
                self.logger.debug(
                    'Created base search template %s in module %s with following mapping: %s',
                    base_search_conf_stanza_name,
                    itsi_module,
                    json.dumps(response))
                return response
            else:
                self.logger.error('Error writing base search template %s in module %s conf', base_search_conf_stanza_name, itsi_module)
                raise utils.ItsiModuleError(status=400, message=_('Error writing data into conf.'))
        else:
            # Only return key mapping to be used for updating KPIs in KPI group if base search id already exists in the conf file
            self.logger.debug('base_search_id: %s already exists in conf file.' % base_search_conf_stanza_name)
            return {base_search_conf_stanza_name: {'metrics': metric_key_mapping}}

    def update(self, itsi_module, object_id, data, **kwargs):
        """
        Update itsi_kpi_base_search conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: object id

        @type data: dict
        @param data: key/value pairs to be written to conf file

        @rtype: string
        @return: newly created id (conf stanza name) or raise an exception
        """
        data_to_post = utils.filter_keys_reformat_certain_values_from_payload(itsi_module, self.ACCEPTED_KEYS, data)
        response, content = utils.update_conf_stanza(self.session_key, self.CONF_NAME, object_id, data_to_post, itsi_module)
        if response.status == 200:
            self.logger.debug('Successfully updated base search %s in module %s', itsi_module, object_id)
            return object_id
        else:
            self.logger.error('Failed to update base search object id %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed updating object id %s: %s.') % (object_id, content))

    def delete(self, itsi_module, object_id, **kwargs):
        """
        Delete itsi_kpi_base_search conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: ITSI module object id

        @rtype: None
        @return: return nothing or raise an exception
        """
        response, content = utils.delete_conf_stanza(self.session_key, self.CONF_NAME, object_id, itsi_module)
        if response.status == 200:
            self.logger.debug('Successfully deleted base search %s in module %s', itsi_module, object_id)
            return
        else:
            self.logger.error('Failed deleting base search object id: %s', object_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed deleting object id %s: %s.') % (object_id, content))

    def get_count(self, itsi_module, **kwargs):
        """
        Returns the count of kpi_base_search in a given module

        If itsi_module is specified as "-", returns counts of kpi base searches for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested
        """
        # Set up the endpoint
        base_search_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        self.logger.debug('Attempting get_count from base search endpoint: %s', base_search_endpoint)

        # Construct the response object based on the request for kpi_base_search
        response = utils.construct_count_response(base_search_endpoint, itsi_module, self.object_type, self.session_key)
        self.logger.debug('Get_count response for base search %s in module %s: %s', base_search_endpoint, itsi_module,
                          json.dumps(response))
        return response

    def get(self, itsi_module, object_id, **kwargs):
        """
        Returns the count of kpi_base_search in a given module

        If itsi_module is specified as "-", returns counts of kpi base searches for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module requested

        @type object_id: string
        @param object_id: ID of KPI base search being requested
        """
        # Get the endpoint for KPI base search
        kpi_base_search_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, object_id)
        self.logger.debug('Attempting get from base search endpoint: %s', kpi_base_search_endpoint)

        # Construct the response object based on the request for kpi_template
        response = utils.construct_get_response(kpi_base_search_endpoint, self.object_type, object_id, self.session_key,
                                                ['metrics'])
        self.logger.debug('Get response for base search %s in module %s: %s', object_id, itsi_module,
                          json.dumps(response))

        service_id = kwargs.get('service_id')
        if service_id is not None and service_id != '':
            from itsi_module.itsi_module_kpi_group import ItsiModuleKpiGroup # Avoid cyclic import
            kpi_group_instance = ItsiModuleKpiGroup(self.session_key, self.app, self.owner, None)
            kpi_groups = kpi_group_instance.get(itsi_module, object_id, **kwargs)
            base_search_ids = set()
            for kpi_group in kpi_groups:
                for kpi in kpi_group['content']['kpis']:
                    base_search_id = kpi.get('base_search_id')
                    if base_search_id is not None and base_search_id != '':
                        base_search_ids.add(base_search_id)
            response = [item for item in response if item['id'] in base_search_ids]
        return response

    def validate(self, itsi_module, object_id):
        """
        Validates the KPI base search objects

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @type object_id: string
        @param object_id: stanza name (object id)

        @rtype: dictionary
        @return: dictionary of validation result type to actual contents
        """
        validation_errors = []
        base_searches = self.get(itsi_module, object_id)

        for base_search in base_searches:
            if not base_search.get('id', '').startswith(base_search.get('source_itsi_module')):
                validation_errors.append(
                    utils.generate_validation_error_line(base_search,
                                                         self._validation_error_messages['id_prefix_mismatch']))

            if not base_search.get('content', {}).get('title').startswith(base_search['source_itsi_module']):
                validation_errors.append(
                    utils.generate_validation_error_line(base_search,
                                                         self._validation_error_messages['title_prefix_mismatch']))

            if len(base_search.get('content', {}).get('metrics')) == 0:
                validation_errors.append(
                    utils.generate_validation_error_line(base_search,
                                                         self._validation_error_messages['atleast_1_metric']))

            for metric in base_search.get('content', {}).get('metrics'):
                if not metric.get('_key'):
                    validation_errors.append(
                        utils.generate_validation_error_line(
                            base_search,
                            self._validation_error_messages['metric_id_missing'].format(metric['title'])))

        self.logger.debug('Found following validation errors for base search %s in module %s: %s', object_id,
                          itsi_module, validation_errors)
        return utils.construct_validation_result(errors=validation_errors)

    def get_existing_base_search_keys_from_conf(self, itsi_module):
        """
        Get existing base search keys from the conf file

        @type itsi_module: string
        @param itsi_module: ITSI module name

        @rtype: list
        @return: list of existing base search keys
        """
        response, content = utils.get_conf_by_namespace(self.session_key, self.CONF_NAME, itsi_module)
        if response.status != 200:
            self.logger.error('Failed to get existing base search ids')
            raise utils.ItsiModuleError(status=400, message=_('Failed to get existing base search ids.'))
        entries = json.loads(content).get('entry')
        return [entry.get('name') for entry in entries] if entries else []

    def _set_metrics_key_mapping(self, base_search_id, metric_key_mapping):
        """
        Set key value pairs for metrics key

        @type base_search_id: string
        @param base_search_id: base search id inside which metrics are included

        @type metric_key_mapping: dictionary
        @param metric_key_mapping: mapping of metrics keys. {old_key : new_key}
        """
        get_response, get_content = utils.get_obj_by_id(self.session_key, 'kpi_base_search', base_search_id)
        if get_response.status != 200:
            self.logger.error('Failed to fetch %s', base_search_id)
            raise utils.ItsiModuleError(status=400, message=_('Failed to fetch %s.') % base_search_id)

        metrics = json.loads(get_content).get('metrics')
        for metric in metrics:
            metric_key_mapping[metric.get('_key')] = \
                utils.replace_special_chars_with_underscore(metric.get('title').strip())
