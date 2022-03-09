# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from .itoa_change_handler import ItoaChangeHandler
from ITOA import itoa_common as utils
from itsi.objects.itsi_kpi_threshold_template import ItsiKpiThresholdTemplate
from itsi.objects.itsi_service import ItsiService


class KpiThresholdsTemplateDeleteHandler(ItoaChangeHandler):
    """
    Source:
        If a thresholds template is deleted, update all the associated KPI thresholds template ID to null,
        and keep the actual threshold content as it is for the KPIs.

    This handler does the following
        - Query all the KPIs (from all services) based on the specific kpi_threshold_template_id value.
        - Update the thresholds based on the updated thresholds template.
        - Save the updated KPIs back to the kvstore.
    """
    def deferred(self, change, transaction_id=None):
        """
        Getting impacted objects and updating them

        @param change: dict
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: String identifier of the object type in the changed_object
                change_type: The type of change that occurred
                object_type: 'refresh_job'
                change_detail: dict of kpi and its info
            }

        @rtype boolean
        @return: True if all operations were successful, False otherwise
        """

        if change.get('changed_object_type') != 'kpi_threshold_template':
            raise Exception(_('Expected changed_object_type to be "kpi_threshold_template"'))

        if change.get('change_type') != 'service_kpi_thresholds_template_delete':
            raise Exception(_('Expected change_type to be "service_kpi_thresholds_template_delete"'))

        change_detail = change.get('change_detail', {})

        kpi_thresholds_template = change_detail.get('kpi_thresholds_template')

        if not utils.is_valid_dict(kpi_thresholds_template):
            raise Exception(_('Incoming kpi_thresholds_template is not a valid json object'))

        # Identify all the services/kpis that are impacted.
        service_interface = ItsiService(self.session_key, 'nobody')
        service_filter = {'kpis.kpi_threshold_template_id': kpi_thresholds_template.get('_key')}
        impacted_services = service_interface.get_bulk('nobody', filter_data=service_filter, transaction_id=transaction_id)

        impacted_objects = {
            'updated_services': impacted_services,
            'kpi_thresholds_template': kpi_thresholds_template
        }

        updated_services = impacted_objects.get('updated_services', [])
        kpi_thresholds_template = impacted_objects.get('kpi_thresholds_template', {})

        if not utils.is_valid_list(updated_services):
            raise Exception(_('Invalid service list'))

        if len(updated_services) == 0:
            return True

        for service in updated_services:
            for kpi in service.get('kpis', []):
                if kpi.get('kpi_threshold_template_id') == kpi_thresholds_template.get('_key'):
                    # reassign the updated thresholds template values to the KPI
                    ItsiKpiThresholdTemplate.update_kpi_threshold_from_kpi_threshold_template(kpi, {})

        service_interface.batch_save_backend('nobody', updated_services, transaction_id=transaction_id)
        return True
