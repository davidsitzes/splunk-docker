# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import json

from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
import ITOA.itoa_common as utils
from itsi.objects.itsi_kpi_threshold_template import ItsiKpiThresholdTemplate
from itsi.objects.itsi_kpi import ItsiKpi

logger = utils.get_itoa_logger('itsi.object.kpi_template')

class ItsiKpiTemplate(ItoaObject):
    '''
    Implements ITSI KPI Template
    '''

    log_prefix = '[ITSI KPI Template] '
    collection_name = 'itsi_services'

    def __init__(self, session_key, current_user_name):
        super(ItsiKpiTemplate, self).__init__(
            session_key, current_user_name, 'kpi_template', collection_name=self.collection_name,
            is_securable_object=True)

    def validate_kpi_time_policies(self, kpi):
        # Assume KPI already validate to be valid JSON

        if not 'time_variate_thresholds_specification' in kpi:
            kpi['time_variate_thresholds_specification'] = {}

        itsi_kpi_threshold_template = ItsiKpiThresholdTemplate(
                self.session_key,
                self.current_user_name)

        itsi_kpi_threshold_template.validate_time_policies(kpi['time_variate_thresholds_specification'])

    def validate_kpi_templates(self, objects):
        """
        Validate the following kpi_template specific variables:
         - "description" is a mandatory field, data type is a string
         - "kpis" is a mandatory field, data type is an array, at least 1 element in the kpis list
        """

        itsi_kpi = ItsiKpi(
            self.session_key,
            self.current_user_name)

        for json_data in objects:
            if not utils.is_valid_str(json_data.get('description', None)):
                self.raise_error_bad_validation(logger, 'There is no description specified for object_type: %s .' \
                        'Please provide some description for this kpi template!' % self.object_type)

            kpis = json_data.get('kpis', [])

            if utils.is_valid_str(kpis):
                json_data['kpis'] = json.loads(kpis)
                kpis = json_data['kpis']

            if not utils.is_valid_list(kpis):
                self.raise_error_bad_validation(
                    logger,
                    'KPIs seem invalid. Expected list, found {0}.'.format(type(kpis))
                )

            if len(kpis) == 0:
                self.raise_error_bad_validation(logger, 'Need at least 1 KPI defined in the KPI template.')

            for kpi in kpis:
                if not utils.is_valid_str(kpi.get('kpi_template_kpi_id', None)):
                    # Populate the field if it does not exist
                    template_kpi_id = kpi.get('title')
                    kpi['kpi_template_kpi_id'] = "itsi_" + template_kpi_id.replace(" ", "_").lower()
                itsi_kpi.validate_kpi_basic_structure(kpi)
                self.validate_kpi_time_policies(kpi)

    def do_additional_setup(self, owner, objects, req_source = 'unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        # Assume json_data already validated as list of dicts
        self.validate_kpi_templates(objects)
