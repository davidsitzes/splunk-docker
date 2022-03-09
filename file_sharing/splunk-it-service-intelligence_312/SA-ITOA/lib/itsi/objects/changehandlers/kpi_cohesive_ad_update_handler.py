# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
CUD the Cohesive AD operation based on the service/KPI setting
"""
from splunk.appserver.mrsparkle.lib import i18n
from . import itoa_change_handler
from ITOA import itoa_common as utils
from itsi.mad.itsi_mad_cohesive_searches import ItsiMADCohesiveContextManager
from itsi.mad.itsi_mad_utils import ITSI_MAD_COHESIVE_CONTEXT_NAME


class KpiCohesiveAdUpdateHandler(itoa_change_handler.ItoaChangeHandler):
    """
    Interact with Mad context manager for the following operation:
      1. enable/disable the mad context for cohesive AD
      2. insert/delete the instance for each KPI for which Cohesive AD is enabled

    """

    def deferred(self, change, transaction_id=None):
        """
        Will enable/disable anomaly detection searches
        @param change: The original passed to assess_impacted_object
        @param impacted_objects: The dict returned from assess_impacted_object
        @returns: True if all operations are success, false otherwise

        @param change: dict
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_type: must equal `kpi`
                changed_object_key: list of KPI IDs with cohesive AD setting changed
                change_type: The type of change that occurred. E.g 'service_kpi_cad'
                object_type: 'refresh_job'
                change_detail: dict with at least the following fields:
                            - kpi_data: dict keyed by KPI ids containing relevant KPI attributes
                                - kpi_data.alert_period: alert period for that KPI (in minutes)
                                - kpi_data.service_id :
                                - kpi_data.anomaly_detection_is_enabled: boolean flag specifying enable/disable state
            }

        @return: Boolean indicating success or failure
        @rtype: boolean
        """
        if change.get('changed_object_type') != 'kpi':
            raise Exception(_('Expected changed_object_type to be "kpi"'))

        change_type = change.get('change_type', '')
        if not change_type.startswith('service_kpi_cad'):
            raise Exception(_('Expected change_type to be "service_kpi_ad"'))

        impacted_objects = {}
        if change_type == 'service_kpi_cad':
            change_detail = change.get("change_detail", {})
            impacted_objects = change_detail.get("kpi_data")

        kpi_id = ''
        service_id = ''
        ad_mode = False

        if impacted_objects is None or len(impacted_objects) == 0:
            return True  # Noop

        if not utils.is_valid_dict(impacted_objects):
            raise Exception(_('Impacted objects is not a valid json object'))

        old_instances = []
        context_mgr = ItsiMADCohesiveContextManager(self.session_key)
        if not context_mgr.get_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME):
            context_mgr.create_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME)
            context_mgr.enable_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME)
        else:
            old_instances = context_mgr.get_mad_instances(ITSI_MAD_COHESIVE_CONTEXT_NAME)

        new_instances = []
        for kpi_id, kpi in impacted_objects.iteritems():
            ad_mode = kpi.get('anomaly_detection_is_enabled', False)
            if ad_mode:
                data = {
                    'resolution': kpi.get('alert_period', '5m'),
                    'sensitivity': kpi.get('cohesive_ad', {}).get('sensitivity')
                }
                instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_COHESIVE_CONTEXT_NAME,
                                                                      kpi_id, old_instances)
                # NOTE: This code is nearly identical to kpi_ad_update_handler
                # I'm sad that I missed this.  Still, we're going to opt for update
                # Like in the previous one
                if instance_id:
                    # Update the existing instance, don't add a new one
                    status = context_mgr.update_mad_instance(ITSI_MAD_COHESIVE_CONTEXT_NAME, instance_id, data)
                    if not status:
                        return False
                else:
                    data.update({
                        'filters': {'itsi_kpi_id': kpi_id, 'itsi_service_id': kpi.get('service_id', '')}
                    })
                    new_instances.append(context_mgr.generate_instance_payload(data))
            else:
                instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_COHESIVE_CONTEXT_NAME,
                                                                      kpi_id, old_instances)
                if instance_id:
                    context_mgr.delete_mad_instance(ITSI_MAD_COHESIVE_CONTEXT_NAME, instance_id)
                else:
                    self.logger.warning("Could not find MAD instance to delete instance_id=%s kpi_id=%s tid=%s",
                                        instance_id,
                                        kpi_id,
                                        transaction_id)

        if len(new_instances) > 0:
            # creating instances in batch mode
            if context_mgr.create_bulk_mad_instances(new_instances) is None:
                return False

        # Delete the context if there are no more active instances for the context
        all_instance = context_mgr.get_mad_instances(ITSI_MAD_COHESIVE_CONTEXT_NAME)
        if all_instance is not None and len(all_instance) == 0:
            context_mgr.delete_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME)

        return True
