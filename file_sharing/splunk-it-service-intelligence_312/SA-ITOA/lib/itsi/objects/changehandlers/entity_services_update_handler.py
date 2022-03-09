from ITOA.storage.statestore import StateStoreError
from .itoa_change_handler import ItoaChangeHandler
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity
from itsi.searches.itsi_filter import ItsiFilter
from time import time


class EntityServicesUpdateChangeHandler(ItoaChangeHandler):
    """
    Handler for a change where a services list of static entities that are members of the
    service is either created, deleted, or updated.
    The consequences for this change are:
        - the deletion of the service reference for entities that are no longer a member of the service but once were
        - the addition of the service reference for the entities that are now a member of the service
        - the refresh of services whose entity membership will have changed
    """

    def __init__(self, *args):
        super(EntityServicesUpdateChangeHandler, self).__init__(*args)
        self.owner = "nobody"

    def get_entity_rules_base_search_to_update(self, service):
        '''
        When we're in here, we should have detected that the entities have changed
        Per the entity rules in the service.  This means that we should issue a base search update job.
        Therefore, we can be very specific about when we want an update
        '''
        base_searches_to_update = set()
        for kpis in service.get('kpis'):
            if kpis.get('search_type') != 'shared_base' or not kpis.get('base_search_id'):
                continue
            if kpis.get('enabled') == 1:
                base_searches_to_update.add(kpis.get('base_search_id'))
        return base_searches_to_update

    def deferred(self, change, transaction_id=None):
        """
        @type  change: dictionary
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: should be "service"
                change_type: should be "entity_services_update"
                change_detail:
                    boolean with key 'is_services_associated_by_rules_need_refresh' indicating if services need to be updated
                        entity membership by rules
                object_type: 'refresh_job'
            }

        @rtype: boolean
        @return: True if all updates were successful, false otherwise
        """
        existing_ids = []
        is_services_associated_by_rules_need_refresh = \
            change.get("change_detail", {}).get("is_services_associated_by_rules_need_refresh", False)

        deleted_entity_service_refresh = change.get("change_detail", {}).get("deleted_entity_services", [])

        self.logger.debug("ChangeDetail %s", change.get("change_detail"))

        if not is_services_associated_by_rules_need_refresh:
            return True # No updates are needed - job finished

        entity_keys = change.get('changed_object_key')
        if len(entity_keys) == 0:
            return True

        # We should refresh all services since their rules may evaluate in ways that change entity memberships
        # Entity membership changes affect service KPI searches which need to be refreshed and post service
        # updates, will trigger updates to affected entities for service membership
        start_time = time()

        filter_data = {'$or': [{'_key': k} for k in entity_keys]} if len(entity_keys) else None
        entity_object = ItsiEntity(self.session_key, self.owner)
        existing_entities = entity_object.get_bulk(self.owner, transaction_id=transaction_id,
                                                   fields=['_key', 'services', 'sec_grp'], filter_data=filter_data)
        existing_service_relationships = {}
        for ent in existing_entities:
            services = ent.get('services')
            if services is None or len(services) == 0:
                continue
            for s in services:
                if s['_key'] not in existing_service_relationships:
                    existing_service_relationships[s['_key']] = [ent['_key']]
                else:
                    existing_service_relationships[s['_key']].append(ent['_key'])

        service_object = ItsiService(self.session_key, self.owner)
        services = service_object.get_bulk(self.owner, transaction_id=transaction_id, fields=['_key', 'entity_rules',
                                'kpis.base_search_id', 'kpis.search_type', 'kpis.enabled', 'sec_grp'])
        save_services = []
        base_searches_to_update = set()
        for svc in services:
            #These are the services that used to match the deleted entities
            if svc['_key'] in deleted_entity_service_refresh:
                base_searches_to_update.update(self.get_entity_rules_base_search_to_update(svc))
                save_services.append(svc['_key'])
                continue

            # Do some additional filtering so that we don't need to save more services than necessary
            # It makes the worst case longer, but the best and the average cases shorter
            entity_rules = svc.get("entity_rules", [])
            if entity_rules is None or len(entity_rules) == 0:
                continue
            #Get the entities that currently match
            filtered_entities = ItsiFilter(entity_rules).get_filtered_objects(
                self.session_key, self.owner, fields=['_key'])
            filtered_entities = [ent['_key'] for ent in filtered_entities]
            if set(filtered_entities).isdisjoint(entity_keys):
                # In this specific case if it was an existing relationship but no longer a relationship,
                # then we should update that service
                if svc['_key'] in existing_service_relationships and len(set(filtered_entities).symmetric_difference(existing_service_relationships[svc['_key']])) > 0:
                    save_services.append(svc['_key'])
                    base_searches_to_update.update(self.get_entity_rules_base_search_to_update(svc))
                # If it falls through the previous check, then the service does not need updating
                continue
            save_services.append(svc['_key'])
            base_searches_to_update.update(self.get_entity_rules_base_search_to_update(svc))

        for associated_service in deleted_entity_service_refresh:
            #This is for the rare case if we have a deleted service, really really rare
            #I'm assuming that the service update will take care of base searches
            if associated_service not in save_services:
                save_services.append(associated_service)

        end_time = time()
        prep_time = end_time - start_time
        self.logger.debug("Saving updated services='%s' prep_time=%s", [s for s in save_services], prep_time)
        # Save the services => Refresh the saved service searches and propagate change to entity
        #   The entity rules would be evaluated leading to:
        #       * Searches updating for entities
        #       * Further update of entities for the Services field for new membership changes
        updated_ret_services = []
        for svc_key in save_services:
            try:
                # NOTE: This will shrink the window where we can end up accidently overwriting a service change
                s = service_object.get(self.owner, svc_key, req_source='entity_services_update_handler', transaction_id=transaction_id)
                if s is None:
                    continue
                # set a temp flag indicating that a search regen is needed.
                # this temp flag will be removed from the service collection in itsi_service code
                s['need_update_search'] = True
                service_object.update(self.owner, svc_key, s, transaction_id=transaction_id)
                updated_ret_services.append(svc_key)
            except StateStoreError:
                self.logger.exception("StateStoreError while saving service - logging and continuing key=%s tid=%s" % (svc_key, transaction_id))
                continue
            except Exception:
                self.logger.exception("General Exception saving service - logging and continuing key=%s tid=%s" % (svc_key, transaction_id))
        self.logger.debug("Successfully saved and refreshed objects='%s'", updated_ret_services)

        self.logger.debug("Entity issued base search updates objects='%s'", base_searches_to_update)
        jobs = []
        existing_ids = list(base_searches_to_update)
        for base_search in base_searches_to_update:
            #Using ITOA object methods here because its whats avaiable
            #Note that its convluted that we have to use the service object here to get and create the jobs
            jobs.append( service_object.get_refresh_job_meta_data(
                    'update_shared_base_search',
                    [base_search],
                    'kpi_base_search',
                    change_detail = {'existing_ids': existing_ids},
                    transaction_id=transaction_id
                ))
        service_object.create_refresh_jobs(jobs)


        # We were successful, delete all of the other refresh queue jobs
        # NOTE: This applies only when we're doing a blanket update.
        # In that case we do want to remove the old changehandlers
        # For this one though, we don't
        # This could indicate that we want another type of changehandler
        # for when we do a bulk update - vs having one for single entities
        # self.remove_additional_changehandlers(self.session_key,
        # self.owner, change.get('change_type'), change.get('_key'))

        return True
