# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from ITOA.storage import statestore
from ITOA import itoa_common as utils
from .itoa_change_handler import ItoaChangeHandler
from itsi.searches.itsi_filter import ItsiFilter
from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_service import ItsiService


class ServiceEntitiesUpdateChangeHandler(ItoaChangeHandler):
    """
    Handler for a change where a services list of static entities that are members of the
    service is either created, deleted, or updated.
    The consequences for this change are:
        - the deletion of the service reference for entities that are no longer a member of the service but once were
        - the addition of the service reference for the entities that are now a member of the service
    """

    def __init__(self, *args):
        super(ServiceEntitiesUpdateChangeHandler, self).__init__(*args)
        self.statestore = statestore.StateStore(collection='itsi_services')
        self.statestore.lazy_init(self.session_key)
        self.owner = 'nobody'
        self.entity_service_mutate_map = {}

    def deferred(self, change, transaction_id=None):
        """
        Determine the list of impacted objects from a specific change event
        And then update them

        @type  change: dictionary
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: should be "service"
                change_type: should be "service_entities_update"
                change_detail: dict of service info and method preserving the entity rules to evaluate
                    to determine entity membership updates
                object_type: 'refresh_job'
            }

        @rtype: Boolean
        @return: True if all operations were successful, False otherwise
            services to add/remove from each entity as values
        """
        # Preprocess all of the changes so that we can rapidly update entities later

        impacted_entities = {}

        def append_entity_updates(entity_key, add_services, remove_services, modify_services):
            if impacted_entities.get(entity_key) is None:
                impacted_entities[entity_key] = {
                    'add_services': [],
                    'remove_services': [],
                    'modify_services': []
                }
            impacted_entities[entity_key]['add_services'].extend(add_services)
            impacted_entities[entity_key]['remove_services'].extend(remove_services)
            impacted_entities[entity_key]['modify_services'].extend(modify_services)

        def get_entities_matching_service_rules(entity_rules):
            '''
            Get entities matching given entity rules

            @type entity_rules: list of dictionaries
            @param entity_rules: entity rules to match entities for

            @type sec_grp: basestring
            @param sec_grp: security group that the entity rule applies to

            @rtype: set of strings
            @return: set of entity ids
            '''
            entity_rules_filter = ItsiFilter(entity_rules)
            return set([
                entity.get('_key') for entity in entity_rules_filter.get_filtered_objects(
                    self.session_key,
                    self.owner,
                    fields=['_key', 'sec_grp']
                )])

        entity_service_references = []

        def get_entities_with_service_references(service_keys):
            '''
            Get entities which are associated with given service ids

            @type service_keys: list of strings
            @param service_keys: ids for the services being looked up

            @rtype: list of dictionaries
            @return: list of entities associated with the services
            '''
            if isinstance(service_keys, list) and len(service_keys) > 0:
                service_keys_filter = {
                    '$or': [{'services._key': service_key_ref} for service_key_ref in service_keys]
                }
                return self.statestore.get_all(
                    self.session_key,
                    self.owner,
                    'entity',
                    filter_data=service_keys_filter,
                    fields=['_key', 'services', 'sec_grp']
                    )
            else:
                return []

        def pick_entities_with_service_reference(service_key):
            '''
            Pick entities which are associated with a given service id

            @type service_key: string
            @param service_key: id for the service being looked up

            @rtype: set of strings
            @return: set of entity ids for entities associated with the service
            '''
            matching_entity_keys = []

            if isinstance(entity_service_references, list) and len(entity_service_references) > 0:
                matching_entity_keys = [
                    e.get('_key') for e in entity_service_references
                    if any(
                        isinstance(s, dict) and s.get('_key') == service_key
                        for s in e.get('services', [])
                    )
                ]

            return set(matching_entity_keys)

        change_detail = change.get('change_detail', {})
        method_causing_change = change_detail.get('method')

        services_to_access = change_detail.get('service_info', {})

        # Querying entities currently evaluated as associated to a service could be collected all at once
        # Collect this information first to efficiently query the persisted store and post process in-memory as required
        entity_service_references = get_entities_with_service_references(services_to_access.keys())

        if len(services_to_access) > 0:
            filter_data = {
                '$or': [{'_key': service_key} for service_key in services_to_access.iterkeys()]
            }
            #Get the latest from the kvstore - whatever gets passed in besides the key is irrelevent
            service_object = ItsiService(self.session_key, self.owner)
            services = service_object.get_bulk(self.owner, filter_data=filter_data,
                                               fields=['_key', 'title', 'entity_rules', 'sec_grp'],
                                               transaction_id=transaction_id)
        else:
            services = []

        for service in services:
            if method_causing_change == 'DELETE':
                # Service delete implies, any entity associated with the service via inclusion by rules
                # must be updated
                entities_matched = pick_entities_with_service_reference(service['_key'])
                for entity_key in entities_matched:
                    service_detail = {'_key': service['_key'], 'title': service.get('title', '')}
                    append_entity_updates(entity_key, [], [service_detail], [])
            else:
                entities_matched = get_entities_matching_service_rules(service.get('entity_rules', []))
                persisted_entities_matched = pick_entities_with_service_reference(service['_key'])

                # Identify any change in membership of all entities included by rules
                added_entities = entities_matched.difference(persisted_entities_matched)
                removed_entities = persisted_entities_matched.difference(entities_matched)
                modified_entities = persisted_entities_matched.intersection(entities_matched)

                # Create change details for added/removed entities included by rules
                service_detail = {'_key': service['_key'], 'title': service.get('title', '')}
                for entity_key in added_entities:
                    append_entity_updates(entity_key, [service_detail], [], [])
                for entity_key in removed_entities:
                    append_entity_updates(entity_key, [], [service_detail], [])
                for entity_key in modified_entities:
                    append_entity_updates(entity_key, [], [], [service_detail])
                # Now there will also be the case where we have entities that are neither added nor removed
                # But where something was modified, i.e. the service title updates and we need to change the entity

        self.logger.debug('Impacted entities identified for service updates - {0}'.format(impacted_entities))

        if not impacted_entities:
            self.logger.debug('empty impacted entities list, nothing to update')
            return True

        entity_key_or = [{'_key': entity_key} for entity_key in impacted_entities.keys()]

        entity_object = ItsiEntity(self.session_key, self.owner)

        if len(entity_key_or) > 0:
            entities = entity_object.get_bulk(self.owner, filter_data={'$or': entity_key_or}, transaction_id=transaction_id)
        else:
            entities = []

        if len(entities) < len(entity_key_or):
            self.logger.warning(
                'Some entities requiring update have not been created or underwent changes, ignore for now'
            )

        for entity in entities:
            entity_update_info = impacted_entities[entity.get('_key', '')]
            if len(entity_update_info) > 0:
                entity['services'] = [
                    service for service in entity.get('services', [])
                    if isinstance(service, dict)
                ]
                entity['services'].extend([
                    service_to_add for service_to_add in entity_update_info.get('add_services', [])
                    if not any(
                        (isinstance(service, dict)) and service_to_add['_key'] == service.get('_key')
                        for service in entity['services']
                    )
                ])

                entity['services'] = [
                    service for service in entity['services']
                    if not any(
                        (isinstance(service, dict)) and service_to_remove.get('_key') == service.get('_key')
                        for service_to_remove in entity_update_info.get('remove_services', [])
                    )
                ]
                modified_services = entity_update_info.get('modify_services', [])
                for service in entity['services']:
                    key = service.get('_key')
                    if key is None:
                        continue
                    for mod in modified_services:
                        if mod['_key'] == key:
                            service['title'] = mod['title']

        entity_object.save_batch(self.owner, entities, validate_names=False, transaction_id=transaction_id)
        self.logger.debug('Impacted entities updated - %s', entities)

        return True

