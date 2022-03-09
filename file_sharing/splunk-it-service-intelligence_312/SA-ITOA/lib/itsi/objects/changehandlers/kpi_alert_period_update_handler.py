# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
CUD the AD operation based on the service/KPI setting
"""
from splunk.appserver.mrsparkle.lib import i18n
from . import itoa_change_handler
from ITOA import itoa_common as utils
from itsi.mad.itsi_mad_utils import (get_mad_trending_instance_kpi_mapping,
                                     get_mad_cohesive_instance_kpi_mapping,
                                     update_mad_trending_instance_time_resolution,
                                     update_mad_cohesive_instance_time_resolution)


class KpiAlertPeriodUpdateHander(itoa_change_handler.ItoaChangeHandler):
    """
    Interact with Mad context manager for the following operation:
      1. Detect if the alert period value has changed.
      2. Updated the MAD instance with the new alert period value.
    """

    def _extract_instance_id(self, kpi_mapping, kpi_id):
            """
            Extract MAD instance id associated with the KPI
            :param kpi_mapping: Dict of kpi id and instance id mapping
            :return: MAD instance id
            """
            instance_id = kpi_mapping.get(kpi_id, '')
            if isinstance(instance_id, list) and len(instance_id) == 1:
                return instance_id[0]
            else:
                raise Exception(_('No MAD instance to update'))

    def deferred(self, change, transaction_id=None):
        """
        Update the MAD instance with the changed alert period value.
        @param change: The original passed to assess_impacted_object
        @param impacted_objects: The dict returned from assess_impacted_object
        @returns: True if all operations are success, false otherwise

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
        """
        if change.get('changed_object_type') != 'kpi':
            raise Exception(_('Expected changed_object_type to be "kpi"'))

        change_type = change.get('change_type', '')
        if not change_type.startswith('service_kpi_update_alert_period'):
            raise Exception(_('Expected change_type to be "service_kpi_update_alert_period"'))

        impacted_objects = {}
        change_detail = change.get("change_detail", {})
        impacted_objects['changed'] = change_detail

        if impacted_objects is None or len(impacted_objects) == 0:
            return True  # Noop

        if not utils.is_valid_dict(impacted_objects):
            raise Exception(_('Impacted objects is not a valid json object'))

        # Mad trending instances
        trending_kpi_mapping = get_mad_trending_instance_kpi_mapping(self.session_key)

        # Mad cohesive instances
        cohesive_kpi_mapping = get_mad_cohesive_instance_kpi_mapping(self.session_key)

        kpis = impacted_objects.get('changed', {})
        for kpi_id in kpis:
            resolution = str(kpis.get(kpi_id, '5')) + 'm'
            if kpi_id in trending_kpi_mapping:
                # retrieve the corresponding instance id and perform the update
                # default value is always 5m, append the unit at the end.
                instance_id = self._extract_instance_id(trending_kpi_mapping, kpi_id)
                update_mad_trending_instance_time_resolution(self.session_key,
                                                             instance_id,
                                                             resolution)

            if kpi_id in cohesive_kpi_mapping:
                instance_id = self._extract_instance_id(cohesive_kpi_mapping, kpi_id)
                update_mad_cohesive_instance_time_resolution(self.session_key,
                                                             instance_id,
                                                             resolution)
        return True
