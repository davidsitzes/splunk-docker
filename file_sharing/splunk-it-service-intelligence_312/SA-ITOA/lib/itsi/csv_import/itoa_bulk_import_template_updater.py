# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from itoa_bulk_import_common import logger
from copy import deepcopy

class TemplateUpdater(object):
    """
    Updates the template cache objects by validating that the service template exists
    and filling in required fields from the service template object.
    """
    def __init__(self, template_cache):
        """
        @param template_cache: A cache of templates
        @type: object
        """
        self.template_cache = template_cache

    def _lookup_service(self, service, services):
        """
        Finds a given service in the services list.

        @param service: The service to be found
        @type: dict

        @param services: The list of services
        @type: list

        @return: The found service
        @type: dict
        """
        for svc in services:
            if svc['title'] == service:
                return svc

        return None

    def _iterate_entity_rules(self, entity_rules):
        """
        Provides an iterator for the entity_rules field.

        @param entity_rules: Entity rules to iterate through
        @type: list

        @return: An entity rules iterator
        @type: generator
        """
        for rule in entity_rules:
            rule_items = rule.get('rule_items', [])
            for item in rule_items:
                yield item

    def _update_incomplete_entity_rules(self, service_title, entity_rules):
        """
        If a service inherits incomplete entity rules from a service template, change the rule type so
        the user can manually fix.

        @param service_title: Title of the service
        @type: string

        @param entity_rules: The service's entity rules
        @type: list

        @return: The updated entity rules for the service
        @type: list
        """
        updated_entity_rules = deepcopy(entity_rules)
        incomplete_entity_rules = False

        for rule_item in self._iterate_entity_rules(updated_entity_rules):
            if not rule_item['value']:
                rule_type = rule_item['rule_type']
                if rule_type == 'matchesblank':
                    rule_item['rule_type'] = 'matches'

                if rule_type == 'notmatchesblank':
                    rule_item['rule_type'] = 'not'

                incomplete_entity_rules = True

        if incomplete_entity_rules:
            logger.warning('Entity rules are incomplete for service: {0}'.format(service_title))

        return updated_entity_rules

    def _update_service_entity_rules(self, entity_rules, entity_rules_values):
        """
        Updates a service's entity rules with values aggregated from the CSV file.

        @param entity_rules: The service's entity_rules
        @type: list

        @param entity_rules_values: The values to be used to populate the entity rules
        @type: dict
        """
        for rule_item in self._iterate_entity_rules(entity_rules):
            rule_type = rule_item['rule_type']
            value_field = rule_item['value']

            if rule_type == 'matchesblank' and value_field in entity_rules_values:
                rule_item['rule_type'] = 'matches'
                rule_item['value'] = ",".join(entity_rules_values[value_field])

            if rule_type == 'notmatchesblank' and value_field in entity_rules_values:
                rule_item['rule_type'] = 'not'
                rule_item['value'] = ",".join(entity_rules_values[value_field])

    def _check_empty_templates(self):
        """
        Validates that there are no templates in the template cache without services.
        """
        for template_title, template in self.template_cache.items():
            if not template.services:
                self.template_cache.pop(template_title)

    def _check_duplicate_template_links(self):
        """
        Validates that a service is being linked to only one service template. If there are conflicting service template
        links, the service will be linked to the first template.
        """
        for service in self.template_cache.service_relationships:
            service_templates = self.template_cache.service_relationships[service]
            if len(service_templates) > 1:
                template_iterator = iter(service_templates)
                linked_template = next(template_iterator, None)
                for template in template_iterator:
                    import_template = self.template_cache.get(template, None)
                    if not import_template:
                        # import_template may not exist in the template cache because there is no
                        # validation for this service's templates in service_relationships
                        continue

                    import_template.services.pop(service, None)

                logger.warning(
                    'Service with title: {0} has conflicting service template links: {1}. Only linking to template: {2}'.format(
                        service, ', '.join(set(service_templates)), linked_template
                    )
                )

    def validate_templates(self):
        """
        Validate that templates have services to link to and that services aren't being linked to more than
        one template.
        """
        self._check_duplicate_template_links()
        self._check_empty_templates()

    def update(self, services):
        """
        Updates each ImportTemplate's service object with the service's key.

        @param services:
        @type: list

        @return: List of updated ImportTemplate objects
        @type: list
        """
        for template in self.template_cache.values():
            for service in template.services:
                maybe_service = self._lookup_service(service, services)

                if maybe_service:
                    template.services[service]['key'] = maybe_service['_key']
                    service_entity_rules = template.services[service].get('entity_rules', [])
                    service_entity_rules_values = template.services[service].get('entity_rules_values', {})
                    self._update_service_entity_rules(service_entity_rules, service_entity_rules_values)

                service_entity_rules = template.services[service].get('entity_rules', [])
                if template.entity_rules and not service_entity_rules:
                    template.services[service]['entity_rules'] = self._update_incomplete_entity_rules(service, template.entity_rules)

        return self.template_cache.templates()