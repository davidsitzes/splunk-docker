# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import copy

from .itoa_change_handler import ItoaChangeHandler
from ITOA import itoa_common as utils
from itsi.objects.itsi_kpi_threshold_template import ItsiKpiThresholdTemplate
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_service_template import ItsiBaseServiceTemplate


class KpiThresholdsTemplateUpdateHandler(ItoaChangeHandler):
    """
    Source:
        When a KPI thresholds template is updated, need to update all the associated KPIs with the
        updated thresholds values.
        If a thresholds template is deleted, update all the associated KPI thresholds template to "custom"

    This handler does the following
        - Query all the KPIs (from all services) based on the specific kpi_threshold_template_id value.
        - Update the thresholds based on the updated thresholds template.
        - Save the updated KPIs back to the kvstore.
    """
    def deferred(self, change, transaction_id=None):
        """
        Processing objects impacted by this change

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

        if change.get('change_type') != 'service_kpi_thresholds_template_update':
            raise Exception(_('Expected change_type to be "service_kpi_thresholds_template_update"'))

        change_detail = change.get("change_detail", {})

        kpi_thresholds_template = change_detail.get('kpi_thresholds_template')

        if not utils.is_valid_dict(kpi_thresholds_template):
            raise Exception(_('Incoming kpi_thresholds_template is not a valid json object'))

        # Identify all the services/kpis that are impacted.
        service_interface = ItsiService(self.session_key, 'nobody')
        service_filter = {'kpis.kpi_threshold_template_id': kpi_thresholds_template.get('_key')}
        impacted_services = service_interface.get_bulk('nobody', filter_data=service_filter)

        # Identify all the service_templates/kpis that are impacted.
        service_template_interface = ItsiBaseServiceTemplate(self.session_key, 'nobody')
        impacted_service_templates = service_template_interface.get_bulk('nobody', filter_data=service_filter)

        impacted_objects = {
            'updated_services': impacted_services,
            'updated_service_templates': impacted_service_templates,
            'kpi_thresholds_template': kpi_thresholds_template
        }

        if not utils.is_valid_dict(impacted_objects):
            raise Exception(_('Impacted objects is not a valid json object.'))

        updated_services = impacted_objects.get('updated_services', [])
        updated_service_templates = impacted_objects.get('updated_service_templates', [])
        kpi_thresholds_template = impacted_objects.get('kpi_thresholds_template', {})

        if not utils.is_valid_list(updated_services):
            raise Exception(_('Invalid service list'))
        if not utils.is_valid_list(updated_service_templates):
            raise Exception(_('Invalid service templates list'))

        if len(updated_services) == 0 and len(updated_service_templates) == 0:
            return True

        # save batch for the service templates that need to be updated
        for service_template in updated_service_templates:
            for kpi in service_template.get('kpis', []):
                if kpi.get('kpi_threshold_template_id') == kpi_thresholds_template.get('_key'):
                    if kpi.get('_key', '').startswith('SHKPI-'):
                        continue
                    ItsiKpiThresholdTemplate.update_kpi_threshold_from_kpi_threshold_template(kpi,
                                                                                              kpi_thresholds_template)

        if len(updated_service_templates) > 0:
            service_template_interface.batch_save_backend('nobody', updated_service_templates,
                                                          transaction_id=transaction_id)

        # update services
        kpi_dict = {}
        changed_kpis = {}
        kpi_svc_dict = {}
        for service in updated_services:
            old_service = copy.deepcopy(service)  # For change analysis
            for kpi in service.get('kpis', []):
                if kpi.get('kpi_threshold_template_id') == kpi_thresholds_template.get('_key'):
                    if kpi.get('_key', '').startswith('SHKPI-'):
                        continue
                    # reassign the updated thresholds template values to the KPI

                    ItsiKpiThresholdTemplate.update_kpi_threshold_from_kpi_threshold_template(kpi,
                                                                                kpi_thresholds_template)
                kpi_svc_dict[kpi.get('_key')] = service.get('_key')
                kpi_dict[kpi.get('_key')] = kpi
            changed_kpis.update(service_interface._determine_changed_kpis_at_ad(service, old_service,
                                                            "adaptive_thresholds_is_enabled",
                                                            "adaptive_thresholding_training_window"))
            del old_service

        if len(updated_services) > 0:
            # Save changes to the services
            service_interface.batch_save_backend('nobody', updated_services, transaction_id=transaction_id)

            # Place refresh jobs to update the AT searches for the impacted KPIs
            refresh_jobs = []
            service_interface._enqueue_atad_refresh_jobs(refresh_jobs, kpi_dict, kpi_svc_dict, 'service_kpi_at',
                                                         changed_kpis, transaction_id)
            service_interface.create_refresh_jobs(refresh_jobs)

        return True
