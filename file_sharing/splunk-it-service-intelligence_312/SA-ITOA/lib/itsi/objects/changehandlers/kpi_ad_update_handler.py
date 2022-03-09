# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
CUD the AD operation based on the service/KPI setting
"""
from splunk.appserver.mrsparkle.lib import i18n
from itoa_change_handler import ItoaChangeHandler
from ITOA import itoa_common as utils
from itsi.mad.itsi_mad_trending_searches import ItsiMADTrendingContextManager
from itsi.mad.itsi_mad_utils import ITSI_MAD_CONTEXT_NAME


class KpiAdUpdateHandler(ItoaChangeHandler):
    """
    Interact with Mad context manager for the following operation:
      1. enable/disable the mad context
      2. insert/delete the instance (for each MAD enabled kpis)

    """

    def deferred(self, change, transaction_id=None):
        """
        Will enable/disable anomaly detection searches
        @param change: The original passed to assess_impacted_object

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

        @returns: True if all operations are success, false otherwise
        @rtype boolean
        """
        if change.get('changed_object_type') != 'kpi':
            raise Exception(_('Expected changed_object_type to be "kpi"'))

        change_type = change.get('change_type', '')
        if not change_type.startswith('service_kpi_ad'):
            raise Exception(_('Expected change_type to be "service_kpi_ad"'))

        impacted_objects = {}
        if change_type == 'service_kpi_ad':
            change_detail = change.get("change_detail", {})
            impacted_objects = change_detail.get("kpi_data")

        if impacted_objects is None or len(impacted_objects) == 0:
            return True  # Noop

        if not utils.is_valid_dict(impacted_objects):
            raise Exception(_('impacted objects is not a valid json object'))

        kpi_id = ''
        service_id = ''
        ad_mode = False

        context_mgr = ItsiMADTrendingContextManager(self.session_key)
        old_instances = []
        if not context_mgr.get_mad_context(ITSI_MAD_CONTEXT_NAME):
            context_mgr.create_mad_context(ITSI_MAD_CONTEXT_NAME)
            context_mgr.enable_mad_context(ITSI_MAD_CONTEXT_NAME)
        else:
            old_instances = context_mgr.get_mad_instances(ITSI_MAD_CONTEXT_NAME)

        new_instances = []
        for kpi_id, kpi in impacted_objects.iteritems():
            ad_mode = kpi.get('anomaly_detection_is_enabled', False)
            if ad_mode:
                data = {
                    'resolution': kpi.get('alert_period', '5m'),
                    'sensitivity': kpi.get('trending_ad', {}).get('sensitivity')
                }
                instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_CONTEXT_NAME, kpi_id, old_instances)
                # Based on the previous implementation, it seems like we should return False
                # If the instance fails to update.  This seems like a bug to me and really should
                # Be thought about
                if instance_id:
                    # Update the existing instance, don't add a new one
                    status = context_mgr.update_mad_instance(ITSI_MAD_CONTEXT_NAME, instance_id, data)
                    if not status:
                        return False
                else:
                    data.update({
                        'filters': {'itsi_kpi_id': kpi_id, 'itsi_service_id': kpi.get('service_id', '')}
                    })

                    new_instances.append(context_mgr.generate_instance_payload(data))
            else:
                instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_CONTEXT_NAME, kpi_id, old_instances)
                if instance_id:
                    context_mgr.delete_mad_instance(ITSI_MAD_CONTEXT_NAME, instance_id)
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
        all_instance = context_mgr.get_mad_instances(ITSI_MAD_CONTEXT_NAME)
        if all_instance is not None and len(all_instance) == 0:
            context_mgr.delete_mad_context(ITSI_MAD_CONTEXT_NAME)

        return True
