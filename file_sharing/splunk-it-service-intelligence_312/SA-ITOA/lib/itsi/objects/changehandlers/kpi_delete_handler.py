# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from . import itoa_change_handler
from .backfill_cleanup_utils import cancel_or_delete_backfill_records, get_backfill_records
from ITOA.itoa_common import post_splunk_user_message
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from itsi.objects.itsi_service import ItsiService, ItsiKpi
from itsi.mad.itsi_mad_utils import (delete_mad_trending_instances,
                                     delete_mad_cohesive_instances,
                                     get_mad_trending_instance_kpi_mapping,
                                     get_mad_cohesive_instance_kpi_mapping)


class KpiDeleteHandler(itoa_change_handler.ItoaChangeHandler):
    """
    When one or more Kpis are deleted we need to refresh correlation searches
    Disable correlation searches when not all KPIs on a correlation search are deleted
    Delete correlation searches when all KPIs on a correlation search are deleted
    """

    def _get_correlation_search_object(self):
        """
        Return correlation search instance
        @return:
        @rtype: ItsiCorrelationSearch
        """
        return ItsiCorrelationSearch(
            self.session_key,
            user='nobody',
            app='itsi',
            logger=self.logger
        )

    def deferred(self, change, transaction_id=None):
        """
        Will delete/disable correlation searches based on if correlation search still has valid KPIs
        @param change: The original passed to assess_impacted_objects
        @param impacted_objects: The dict returned from assess_impacted_objects
        @return True if all operations are success, False otherwise
        @rtype: boolean
        @param change:
               change.changed_object_type: must equal `kpi`
               change.change_type: must equal `service_kpi_deletion`
               change.changed_object_key: list of KPI IDs being deleted
               change.change_detail: dict with the following fields:
                                   - service_kpi_mapping: dict of deleted KPI ids keyed by associated service id
        """

        if change.get('changed_object_type') != 'kpi':
            raise Exception(_('Expected changed_object_type to be "kpi"'))

        if change.get('change_type') != 'service_kpi_deletion':
            raise Exception(_('Expected change_type to be "service_kpi_deletion"'))

        service_interface = ItsiService(self.session_key, 'nobody')
        correlation_interface = self._get_correlation_search_object()
        correlation_searches = correlation_interface.\
            get_associated_search_with_service_or_kpi(kpi_ids=change.get('changed_object_key'))

        # Update dependencies
        change_detail = change.get("change_detail", {})
        service_kpi_mapping = change_detail.get("service_kpi_mapping", {})
        all_kpis = change.get('changed_object_key', [])
        backfills_to_cancel = get_backfill_records(self.session_key, all_kpis)
        updated_services = {}
        if len(service_kpi_mapping) > 0:
            updated_services = self._get_service_dependency_updates(service_interface, service_kpi_mapping, transaction_id=transaction_id)

        # Get saved search name for kpi
        saved_searches_to_delete = []

        # Mad trending instances
        mad_trending_instance_to_delete = []
        trending_kpi_mapping = get_mad_trending_instance_kpi_mapping(self.session_key)

        # Mad cohesive instances
        mad_cohesive_instance_to_delete = []
        cohesive_kpi_mapping = get_mad_cohesive_instance_kpi_mapping(self.session_key)

        for kpi_id in change.get('changed_object_key'):
            saved_search_name = ItsiKpi.get_kpi_saved_search_name(kpi_id)
            saved_searches_to_delete.append(saved_search_name)
            if kpi_id in trending_kpi_mapping:
                for trending_instance in trending_kpi_mapping.get(kpi_id):
                    mad_trending_instance_to_delete.append(trending_instance)
            if kpi_id in cohesive_kpi_mapping:
                for cohesive_instance in cohesive_kpi_mapping.get(kpi_id):
                    mad_cohesive_instance_to_delete.append(cohesive_instance)

        impacted_objects =  {"correlation_search": correlation_searches,
                "saved_searches_to_delete": saved_searches_to_delete,
                "backfills_to_cancel": backfills_to_cancel,
                "updated_services": updated_services,
                "mad_trending_instance_to_delete": mad_trending_instance_to_delete,
                "mad_cohesive_instance_to_delete": mad_cohesive_instance_to_delete}


        if (len(impacted_objects.get('correlation_search', [])) == 0
            and len(impacted_objects.get('saved_searches_to_delete', [])) == 0
            and len(impacted_objects.get('updated_services', {})) == 0
            and len(impacted_objects.get('backfills_to_cancel', [])) == 0
            and len(impacted_objects.get('mad_trending_instance_to_delete', [])) == 0
            and len(impacted_objects.get('mad_cohesive_instance_to_delete', [])) == 0):
            return True  # Noop

        service_interface = ItsiService(self.session_key, 'nobody')

        status_ok = True
        # update service dependencies first and attempt updating saved searches and others as best effort
        updated_services = impacted_objects.get('updated_services', {})
        if len(updated_services) > 0:
            status_ok = service_interface.batch_save_backend('nobody', updated_services.values(), transaction_id=transaction_id) and status_ok

        correlation_interface = self._get_correlation_search_object()
        correlation_searches = impacted_objects.get('correlation_search', [])
        try:
            correlation_interface.\
                    update_service_or_kpi_in_correlation_search('kpiid', ids=change.get('changed_object_key'),
                                                                searches=correlation_searches)
        except Exception:
            message = _('Cannot disable/delete all impacted correlation searches. ' \
                    'We recommend that you update the impacted correlation searches by ' \
                    'the UI. Correlation search names are: {0}').format(
                        [search.get('name', '') for search in correlation_searches]
                    )
            self.logger.exception(message)
            post_splunk_user_message(message=message, session_key=self.session_key)
            status_ok = False

        cancel_or_delete_backfill_records(impacted_objects.get('backfills_to_cancel', []), self.logger)

        # Delete MAD instances
        mad_trending_instances_list = impacted_objects.get('mad_trending_instance_to_delete', [])
        delete_mad_trending_instances(self.session_key, mad_trending_instances_list)

        mad_cohesive_instances_list = impacted_objects.get('mad_cohesive_instance_to_delete', [])
        delete_mad_cohesive_instances(self.session_key, mad_cohesive_instances_list)

        # Delete saved searches for kpis as a best effort
        if not service_interface.delete_kpi_saved_searches(impacted_objects.get("saved_searches_to_delete", [])):
            message = _('Cannot delete all KPI saved searches. We recommend that you manually delete them. ' \
                    'Saves search names are: {0}').format(
                impacted_objects.get("saved_searches_to_delete", [])
            )
            self.logger.error(message)
            post_splunk_user_message(message=message, session_key=self.session_key)
            status_ok = False

        return status_ok

    def _get_service_dependency_updates(self, service_interface, service_kpi_mapping, transaction_id=None):
        """
        Find which services need to be updated based on kpi deletion
        @param service_interface: The itoa_object instance to fetch services
        @param service_kpi_mapping: dict of service key to list of kpis that have been deleted
        @return: dict of service key to services that need to be updated
        """
        updated_services = {}
        for service_key, deleted_kpi_list in service_kpi_mapping.iteritems():
            # get service from updated_services if it was already updated in an earlier iteration
            if service_key in updated_services:
                service = updated_services.get(service_key)
            # otherwise fetch from kvstore
            else:
                service = service_interface.get('nobody', service_key, transaction_id=transaction_id)
            # if service had no dependent services then we can skip it
            depending_on_me = service.get('services_depending_on_me')
            if depending_on_me is None or len(depending_on_me) == 0:
                continue
            # loop through all dependent services, check for intersection of
            for dependency in depending_on_me:
                depending_kpis = dependency.get('kpis_depending_on')
                # this will return only items in depending_kpis that are not in deleted_kpi_list
                changed_depending_kpis = list(set(depending_kpis) - set(deleted_kpi_list))
                # Nothing in depending_kpis is in deleted_kpi_list, we can skip this dependency
                if len(depending_kpis) == len(changed_depending_kpis):
                    continue
                # update this service with the deleted_kpi_list kpis removed
                dependency['kpis_depending_on'] = changed_depending_kpis
                updated_services[service_key] = service
                # need to update target service as well
                target_service_key = dependency.get('serviceid')
                if target_service_key in updated_services:
                    target_service = updated_services.get(target_service_key)
                else:
                    target_service = service_interface.get('nobody', target_service_key, transaction_id=transaction_id)
                target_service_depends_on = target_service.get('services_depends_on')
                matched_dependencies = [d for d in target_service_depends_on if d.get('serviceid') == service_key]
                if len(matched_dependencies) > 0:
                    # There can be only one! - The Highlander
                    if len(matched_dependencies) > 1:
                        self.logger.error('Service "%s" referenced more than once in services_depends_on', service_key)
                    target_service_kpis_depending_on = matched_dependencies[0].get('kpis_depending_on')
                    # remove any kpis referenced in deleted_kpi_List
                    target_service_kpis_depending_on = list(set(target_service_kpis_depending_on) - set(deleted_kpi_list))
                    matched_dependencies[0]['kpis_depending_on'] = target_service_kpis_depending_on
                    updated_services[target_service_key] = target_service
                else:
                    self.logger.error('Could not find service %s to update', service_key)

        # remove service dependencies if kpis_depending_on me is empty after above changes
        for updated_service in updated_services.values():
            depends_on = updated_service.get('services_depends_on', [])
            depending_on_me = updated_service.get('services_depending_on_me', [])
            depends_on = [d for d in depends_on if len(d.get('kpis_depending_on')) > 0]
            updated_service['services_depends_on'] = depends_on
            depending_on_me = [d for d in depending_on_me if len(d.get('kpis_depending_on')) > 0]
            updated_service['services_depending_on_me'] = depending_on_me

        return updated_services
