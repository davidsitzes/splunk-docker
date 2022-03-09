# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from .itoa_change_handler import ItoaChangeHandler
from ITOA.storage.itoa_storage import ITOAStorage
import ITOA.itoa_common as utils
from .backfill_cleanup_utils import cancel_or_delete_backfill_records, get_backfill_records
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from itsi.mad.itsi_mad_utils import (delete_mad_trending_instances,
                                     delete_mad_cohesive_instances,
                                     get_mad_trending_instance_kpi_mapping,
                                     get_mad_cohesive_instance_kpi_mapping)
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_kpi import ItsiKpi
from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_deep_dive import ItsiDeepDive
from itsi.objects.itsi_service_template import ItsiBaseServiceTemplate


class ServiceDeleteHandler(ItoaChangeHandler):
    """
    Source:
        this job is being created only by single service delete or bulk service delete

    This handler does the following
        - Find unnamed deep dives for services, and delete them
        - Find entities which has static link to deleted services, delete them
        - Find correlation searches which contains deleted services
            - If correlation searches contains only deleted services then delete otherwise disable
        - Find dependent services and update them
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
        Getting impacted objects and then updating them
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: String identifier of the object type in the changed_object
                change_type: The type of change that occurred
                object_type: 'refresh_job'
                change_detail:
            }
        @return: Boolean indicating overall success or failure
        """
        self.logger.debug("Accessing impacted object of job='%s'", change)
        deleted_service_ids = change.get("changed_object_key")
        changed_object_type = change.get("changed_object_type")

        if deleted_service_ids is None or len(deleted_service_ids) == 0:
            self.logger.error("No deleted service objects changed_object_key=%s", deleted_service_ids)
            return True

        owner = "nobody"  # Ideally should be passed by modular input
        service_object = ItsiService(self.session_key, owner)
        service_template_object = ItsiBaseServiceTemplate(self.session_key, owner)

        # Grab them saved searches and Mad instances for KPIs
        saved_searches_to_delete = []

        # Mad trending instances
        mad_trending_instance_to_delete = []
        trending_kpi_mapping = get_mad_trending_instance_kpi_mapping(self.session_key)

        # Mad cohesive instances
        mad_cohesive_instance_to_delete = []
        cohesive_kpi_mapping = get_mad_cohesive_instance_kpi_mapping(self.session_key)

        for kpi_id in change.get("change_detail", {}).get("deleted_kpis", []):
            # ignore the helath score KPI, no saved search presence
            if not kpi_id.startswith("SHKPI-"):
                saved_search_name = ItsiKpi.get_kpi_saved_search_name(kpi_id)
                # Avoid duplicate saved search name
                if saved_search_name not in saved_searches_to_delete:
                    saved_searches_to_delete.append(saved_search_name)
                if kpi_id in trending_kpi_mapping:
                    for trending_instance in trending_kpi_mapping.get(kpi_id):
                        mad_trending_instance_to_delete.append(trending_instance)
                if kpi_id in cohesive_kpi_mapping:
                    for cohesive_instance in cohesive_kpi_mapping.get(kpi_id):
                        mad_cohesive_instance_to_delete.append(cohesive_instance)

        impacted_objects = {}
        # Get backfill records
        kpiids = change.get("change_detail", {}).get("deleted_kpis", [])
        impacted_objects["backfill_records"] = get_backfill_records(self.session_key, kpiids)

        # Get Mad trensding and cohesive instances
        impacted_objects["mad_trending_instance_to_delete"] = mad_trending_instance_to_delete
        impacted_objects["mad_cohesive_instance_to_delete"] = mad_cohesive_instance_to_delete

        impacted_objects["saved_searches"] = saved_searches_to_delete
        self.logger.debug("Impacted saved_searches:%s", saved_searches_to_delete)

        self.logger.info("Successfully accessed impacted objects of deleted services:%s", deleted_service_ids)

        ret = False

        try:
            is_deep_dives_updated = self._delete_deep_dives(deleted_service_ids, owner, transaction_id=transaction_id)

            is_cs_updated = self._update_correlation_searches(deleted_service_ids, transaction_id=transaction_id)

            is_services_updated = self._update_services_dependencies(deleted_service_ids, owner, service_object, transaction_id=transaction_id)

            is_entities_updated = self._update_entities(deleted_service_ids, owner, transaction_id=transaction_id)

            is_service_template_updated = self._update_base_service_template(deleted_service_ids, owner, service_template_object, transaction_id=transaction_id)

            is_saved_searches_deleted = service_object.delete_kpi_saved_searches(impacted_objects.get("saved_searches", []))

            is_backfill_cancelled = cancel_or_delete_backfill_records(impacted_objects.get("backfill_records", []), self.logger)

            is_mad_trending_instance_deleted = delete_mad_trending_instances(self.session_key, impacted_objects.get("mad_trending_instance_to_delete", []))

            is_mad_cohesive_instance_deleted = delete_mad_cohesive_instances(self.session_key, impacted_objects.get("mad_cohesive_instance_to_delete", []))

            ret = (is_deep_dives_updated
                   and is_cs_updated
                   and is_services_updated
                   and is_entities_updated
                   and is_saved_searches_deleted
                   and is_backfill_cancelled
                   and is_mad_trending_instance_deleted
                   and is_mad_cohesive_instance_deleted
                   and is_service_template_updated)
        except Exception as e:
            self.logger.exception("Failed to update impacted object:%s", e.message)
        finally:
            self.logger.info("Completed updated impacted objects of deleted services:%s, with return code:%s", deleted_service_ids, ret)
            return ret

    def _update_correlation_searches(self, deleted_service_ids, transaction_id=None):
        '''
        Update impacted correlation searches
        :return: boolean
        '''
        try:
            # Get correlation searches
            correlation_object = self._get_correlation_search_object()
            correlation_searches = correlation_object.get_associated_search_with_service_or_kpi(service_ids=deleted_service_ids)
            self.logger.info("Updated correlation searches tid=%s count=%s", transaction_id, len(correlation_searches))
            if not correlation_searches:
                return True
            self.logger.debug("Impacted correlation searches:%s",
                              [{'name': cs.get('name')} for cs in correlation_searches])
            correlation_object.update_service_or_kpi_in_correlation_search('serviceid', deleted_service_ids,
                                                                           searches=correlation_searches)
        except Exception as e:
            self.logger.exception("Failed to updated impacted correlation searches, error:%s", e.message)
            return False
        return True

    def _update_entities(self, deleted_service_ids, owner, transaction_id=None):
        """
        Update entities which contains static links to deleted services
        :param deleted_service_ids: list of deleted service
        :param owner: owner
        :return: True|False
        """
        if len(deleted_service_ids) == 0:
            return True
        # Get entities
        filter_data = {
            '$or': [{'services._key': service_id} for service_id in deleted_service_ids]
        }

        entity_object = ItsiEntity(self.session_key, 'nobody')
        entities = entity_object.get_bulk(owner,
                                          filter_data=filter_data,
                                          req_source="ServiceDeleteHandler",
                                          transaction_id=transaction_id)
        self.logger.info("Delete of services=%s entity_update_count=%s", deleted_service_ids, len(entities))
        self.logger.debug("Impacted entities:%s", entities)

        try:
            if len(entities) == 0:
                return True
            # Update entity object
            for entity in entities:
                entity["services"] = [
                    service for service in entity.get("services", [])
                    if (isinstance(service, dict) and (not any(
                        service_id_to_remove == service['_key']
                        for service_id_to_remove in deleted_service_ids
                    )))
                ]

                self.logger.debug("Updated services of entity title:%s, _key:%s,  updated_services_list:%s",
                                  entity.get('title'), entity.get('_key'), entity.get('services'))
            # update it now
            entity_object.batch_save_backend(owner, entities, transaction_id=transaction_id)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False

    def _delete_deep_dives(self, deleted_service_ids, owner, transaction_id=None):
        """
        Delete unnamed deep dives which has focus id is one of deleted service ids
        :param owner: owner
        :return: True|False
        """
        if len(deleted_service_ids) == 0:
            return True
        try:
            # If we get rid of the number of deep dives deleted, we can just remove them
            filter_data = {'is_named': False, '$or': [{'focus_id': service_id} for service_id in deleted_service_ids]}

            deep_dive = ItsiDeepDive(self.session_key, 'nobody')
            deep_dives = deep_dive.get_bulk(owner,
                                            filter_data=filter_data,
                                            fields=['_key', 'focus_id', 'title'],
                                            req_source="ServiceDeleteHandler",
                                            transaction_id=transaction_id)
            self.logger.info("Number of impacted unnamed deep dives objects are:%s", len(deep_dives))
            if len(deep_dives) == 0:
                return True
            info = [{'title': dd.get('title'), 'focus_id': dd.get('focus_id')} for dd in deep_dives]
            self.logger.debug("Impacted unnamed deep dives are:%s", info)

            if len(deep_dives):
                filter_data = {'$or': [{'_key': dd.get('_key')} for dd in deep_dives]}

                # Storage interface to perform operation directly
                storage_interface = ITOAStorage(collection='itsi_pages')
                storage_interface.delete_all(self.session_key, owner, "deep_dive", filter_data=filter_data)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False

    def _update_services_dependencies(self, deleted_service_ids, owner, service_object, transaction_id=None):
        """
        Update services dependencies link
        :param deleted_service_ids: deleted services
        :param owner: owner
        :return: True|False
        """
        if len(deleted_service_ids) == 0:
            return True
        # Get dependent services to remove link
        filter_values = [{'services_depending_on_me.serviceid': service_id} for service_id in deleted_service_ids]
        filter_values.extend([{'services_depends_on.serviceid': service_id} for service_id in deleted_service_ids])
        filter_data = {
            '$or': filter_values
        }
        services = service_object.get_bulk(owner,
                                           filter_data=filter_data,
                                           req_source="ServiceDeleteHandler",
                                           transaction_id=transaction_id)
        self.logger.info("Number of impacted dependent services:%s", len(services))
        if len(services) == 0:
            return True

        info = [{'title': ds.get("title"), "_key": ds.get("_key")} for ds in services]
        self.logger.debug("Impacted dependent services:%s", info)

        try:
            for service in services:
                depends_on = service.get('services_depends_on', [])
                if len(depends_on) > 0:
                    updated_depends_on = []
                    for ds in depends_on:
                        if ds.get('serviceid') not in deleted_service_ids:
                            updated_depends_on.append(ds)
                    service['services_depends_on'] = updated_depends_on
                    self.logger.debug("Updated service dependency of service:%s, _key:%s, update service_depends_on:%s",
                                      service.get('title'), service.get('_key'), service.get('services_depends_on'))
                depends_on_me = service.get('services_depending_on_me', [])
                if len(depends_on_me) > 0:
                    updated_depends_on_me = []
                    for ds_on in depends_on_me:
                        if ds_on.get('serviceid') not in deleted_service_ids:
                            updated_depends_on_me.append(ds_on)
                    service['services_depending_on_me'] = updated_depends_on_me
                    self.logger.debug(
                        "Updated service dependency of service:%s, _key:%s, update services_depending_on_me:%s",
                        service.get('title'), service.get('_key'), service.get('services_depending_on_me'))
            service_object.batch_save_backend(owner, services, transaction_id=transaction_id)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False


    def _update_base_service_template(self, deleted_service_ids, owner, service_template_object, transaction_id=None):
        """
        Update service template link
        :param deleted_service_ids: deleted services
        :param owner: owner
        :param service_template_object: service template object
        :return: True|False
        """
        if len(deleted_service_ids) == 0:
            return True

        # Get linked service templates to remove link
        filter_values = [{'linked_services': service_id} for service_id in deleted_service_ids]
        filter_data = {
            '$or': filter_values
        }
        service_templates = service_template_object.get_bulk(owner,
                                                             filter_data=filter_data,
                                                             req_source="ServiceDeleteHandler",
                                                             transaction_id=transaction_id)

        self.logger.debug("Number of impacted service templates:%s", len(service_templates))
        if len(service_templates) == 0:
            return True

        info = [{'title': template.get("title"), "_key": template.get("_key")} for template in service_templates]
        self.logger.debug("Impacted service templates:%s", info)

        try:
            for template in service_templates:
                linked_services = template.get('linked_services', [])
                if len(linked_services) > 0:
                    updated_linked_services = []
                    for service_id in linked_services:
                        if service_id not in deleted_service_ids:
                            updated_linked_services.append(service_id)
                    template['linked_services'] = updated_linked_services
                    template['total_linked_services'] = len(template['linked_services'])
                    self.logger.info("Updated service linkage of service template:%s, _key:%s, update linked services:%s",
                                      template.get('title'), template.get('_key'), template.get('linked_services'))
            service_template_object.batch_save_backend(owner, service_templates, transaction_id=transaction_id)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False
