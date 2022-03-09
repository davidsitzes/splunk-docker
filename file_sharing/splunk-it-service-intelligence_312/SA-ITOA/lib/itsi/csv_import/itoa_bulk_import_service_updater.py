# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import filtblnk, stripall
from itsi.itsi_utils import ITOAInterfaceUtils


# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_service import ImportedService  # noqa: F401
#     from itoa_bulk_import_itoa_handle import ItoaHandle  # noqa: F401
#     from itoa_bulk_import_service_cache import ServiceCache  # noqa: F401
#     from itoa_bulk_import_new_service import ServiceSource  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


#################
# FETCH utilities
#################


def _repair_existing_service(service):
    # type: (Dict[Text, Any]) -> Dict[Text, Any]
    # PRIVATE
    # Fixes known deficiencies in older Storage service instances.  Probably redundant
    # after _update_entity_rules, but repairs services even if no new entities are due to
    # be added.
    if 'entity_rules' not in service:
        service['entity_rules'] = []
    return service


######################
# DEPENDENCY utilities
######################


def _connect_shkpi(service, target):
    # type: (Dict[Text, Any], Dict[Text, Any]) -> Dict[Text, Any]
    # PRIVATE
    return {
        'serviceid': service['_key'],
        'kpis_depending_on': [ITOAInterfaceUtils.fetch_shkpi_id(target)]
    }


# REFACTOR TARGET: This is just another way of saying "Is other_other service's SHKPI
# in the set of KPIs this service depends on?"

def _service_depends_on_another_shkpi(service, other_service):
    # type: (Dict[Text, Any], Dict[Text, Any]) -> bool
    # PRIVATE
    other_shkpi = ITOAInterfaceUtils.fetch_shkpi_id(other_service)
    other_key = other_service.get('_key')

    def is_dependent(entry):
        # type: (Dict[Text, Any]) -> bool
        return (other_key == entry.get('serviceid') and
                other_shkpi in entry.get('kpis_depending_on'))

    for entry in service.get('services_depends_on', []):
        if is_dependent(entry):
            return True
    return False


###############################################################
# ENTITY RULES: Merge or construct a title-based entity ruleset
###############################################################


def _update_entity_rules(local_service, entities):
    # type: (Dict[Text, Any], Set[Text]) -> Dict[Text, Any]
    # PRIVATE
    #
    # Routing used to merge entity rules computed for title based association of entities
    # with services for CSV import with the entity rules that may exist in a persisted
    # instance of a service
    #
    # @param local_service: the service to be updated
    # @param entities: A list of entity names to be included in the rule
    #
    # An entity rule looks like this:
    # { 'rule_condition': 'AND',
    #   'rule_items': { 'field': 'title', 'rule_type': 'matches', 'value': '', 'field_type': 'title' }
    # }
    # Where the 'value' is a comma-separated list of the entity titles which will be used to
    # find the entity later.

    def is_title_based_rule(items):
        # type: (List[Dict[Text, Any]]) -> bool
        return (isinstance(items, list) and
                (len(items) == 1) and
                (items[0]['rule_type'] == 'matches') and
                (items[0]['field_type'] == 'title') and
                (items[0]['field'] == 'title'))

    def find_title_based_rule_group(entity_rules):
        # type: (List[Dict[Text, Any]]) -> Dict[Text, Any]
        # @param entity_rules: a collection of entity rules
        # @return: The title based rule in the entity_rules collection, if any
        title_based_rules = [group for group in entity_rules if is_title_based_rule(group.get('rule_items', []))]
        return (title_based_rules and title_based_rules.pop()) or None

    def update_title_based_rule_group(rule_group, new_entity_titles):
        # type: (Dict[Text, Any], List[Text]) -> Dict[Text, Any]
        #
        # Given a rule group (assuming it's title-based!) and a collection of entity titles to
        # add, update the rule with a merged and de-duplicated list of current titles and new
        # titles.
        #
        # This function works via mutation: as long as we don't *assign* to the rule_group
        # variable above, it refers to the same memory object as that which was passed in,
        # and modifying it here modifies it for the calling function. The technical term
        # for this is "spooky."
        #
        # @param rule_group: the rule group to merge
        # @param new_entity_titles
        # @return: rule_group

        rule = rule_group['rule_items'][0]
        rule['value'] = ','.join(set(filtblnk(stripall(rule['value'].split(',')) + new_entity_titles)))
        return rule_group

    def title_based_rule_group_template(entities=[]):
        # type: (List[Text]) -> Dict[Text, Any]
        return {
            'rule_condition': 'AND',
            'rule_items': [
                {
                    'field': 'title',
                    'rule_type': 'matches',
                    'value': ','.join(list(entities)),
                    'field_type': 'title'
                }
            ]
        }

    # Do nothing if the inbound service has no associated entities.
    if not entities:
        return local_service

    title_based_rule_group = find_title_based_rule_group(local_service.get('entity_rules', []))
    if not title_based_rule_group:
        # Title based entity rule group doesnt exist, just create a new one.
        local_service['entity_rules'].append(title_based_rule_group_template(list(entities)))
        return local_service

    # This uses Python's pass-by-reference.  See the associated function.
    update_title_based_rule_group(title_based_rule_group, list(entities))
    return local_service


def serviceUpdater(service_cache, itoa_handle, service_source, linked_services=None):
    # type: (ServiceCache, ItoaHandle, ServiceSource) -> List[Dict[Text, Any]]
    """
    The interface between a service cache and KV Store.  This function accepts one or more
    services from the service cache, finds the corresponding objects in KV store, and merges
    them according to the rules we've set.

    @param service_cache: The cache of services to be upserted.
    @param itoa_handle: A function that returns an ITOA Interface for a specific class of ITSI object.
    @param service_source: A function that returns a new (or cloned) service.
    @param linked_services: List of Services being linked to a Service Template
    @returns: A list of dictionaries with new or upserted services to be sent to Storage.
    """

    def get_existing_services(service_titles):
        # type: (List[Text]) -> Dict[Text, Dict[Text, Any]]
        if not service_titles:
            return {}

        identifiers = [{'identifying_name': t.lower()} for t in service_titles]
        found_services = [
            _repair_existing_service(service)
            for service in itoa_handle.service.get_bulk(itoa_handle.owner,
                                                        filter_data={'$or': identifiers})]
        return dict([(service['identifying_name'], service) for service in found_services])

    def generate_new_services(services, skip_these_keys):
        # type: (List[ImportedService], List[Text]) -> Dict[Text, Dict[Text, Any]]
        generated_services = [
            service_source(service.title, '. '.join(list(service.description)), clone_service_id=service.clone_service_id)
            for service in services
            if service.identifying_name not in skip_these_keys]
        return dict([(service['identifying_name'], service) for service in generated_services])

    # Existing services are expected to have a working shkpi_dict, and new services are
    # deliberately generated with them.
    working_services = get_existing_services(service_cache.keys())
    working_services.update(generate_new_services(service_cache.values(), working_services.keys()))

    # This is probably the most complicated bit of business logic in the entire module; it
    # ensure two-way relationships between services, and it ensures that all entities in
    # which a service is interested are included in the entity search rule.  Both rules
    # are overly complex due to the lack of a proper relationship management system.
    def merge_services(imported_service, local_service):
        # type: (ImportedService, Dict[Text, Any]) -> Dict[Text, Any]

        # Establish the two-way relationship between a service and its dependencies.  The
        # basic rule is that higher services (in the same sense as "higher functions"),
        # those dependent upon an aggregation of lower services for their shkpi, must list
        # those lower services' SHKPIs as dependencies, and inform those lower services
        # that the higher service is dependent upon those KPIs.

        new_d = (' .'.join(stripall(filtblnk(list(imported_service.description))))).strip()
        loc_d = local_service.get('description', '').strip()
        if (new_d != '' and loc_d != '' and new_d != loc_d):
            local_service['description'] = new_d

        for receiver in imported_service.depends_on_me:
            receiver_service = working_services[receiver]
            if not _service_depends_on_another_shkpi(receiver_service, local_service):
                local_service['services_depending_on_me'] = local_service.get('services_depending_on_me', []) + [_connect_shkpi(receiver_service, local_service)]
                receiver_service['services_depends_on'] = receiver_service.get('services_depends_on', []) + [_connect_shkpi(local_service, local_service)]

        for sender in imported_service.i_depend_upon:
            sender_service = working_services[sender]
            if not _service_depends_on_another_shkpi(local_service, sender_service):
                local_service['services_depends_on'] = local_service.get('services_depends_on', []) + [_connect_shkpi(sender_service, sender_service)]
                sender_service['services_depending_on_me'] = sender_service.get('services_depending_on_me', []) + [_connect_shkpi(local_service, sender_service)]

        if local_service['title'] not in linked_services:
            _update_entity_rules(local_service, imported_service.entities)

        # The imported service is the raw material of the change; it is the resulting dictionary that we
        # ultimately care about.
        return local_service

    return [merge_services(service, working_services[service.identifying_name]) for service in service_cache.values()]
