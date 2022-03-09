# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import _ItsiObjectCache, logger

class TemplateCache(_ItsiObjectCache):
    """
    A dictionary like object for storing ImportTemplate objects.
    """
    def __init__(self):
        super(TemplateCache, self).__init__()
        self.service_relationships = {}

    def __setitem__(self, template_name, template):
        """
        Add or update an ImportTemplate object in the cache.

        @param template_name: The service template's identifying name
        @type: string

        @param template: The template to be added or updated
        @type: object
        """
        if template_name not in self._cache:
            self._cache[template_name] = template
        else:
            self._cache[template_name].update(template)

    def templates(self):
        """
        Coverts the template cache from a dict of templates to a list

        @return: List of ImportTemplate objects from the template cache
        @type: list
        """
        return [template.__dict__ for template in self._cache.values()]

    def services(self):
        """
        Creates a list of Service titles being linked to Service Templates

        @return: List of Services titles
        @type: list
        """
        return [service for template in self._cache.values() for service in template.services]

    def _add_service_relationship(self, service, template):
        """
        Adds a service relationship to keep track of which services are being linked to which service templates. Used to
        determine if a service is being linked to more than one service template.

        @param service: The service title
        @type: string

        @param template: The template title
        @type: string
        """
        service_templates = self.service_relationships.setdefault(service, [])
        if template in service_templates:
            return

        service_templates.append(template)

    def _update_cache(self, template):
        """
        Add or updates an ImportTemplate object in the cache and then updates that template's services list

        @param template: The template to be added or updated
        @type: object
        """
        service_title = template.services.keys()[0]
        self._add_service_relationship(service_title, template.identifying_name)

        if template.identifying_name not in self._cache:
            self._cache[template.identifying_name] = template
        else:
            self._cache[template.identifying_name].add_service(template.services)

    def _validate_service_templates(self, template_names, itoa_handle):
        """
        Looks up a service template in the KVStore by title and returns the ID of the template.

        @param template_names: List of service templates identifying names
        @type: list

        @param itoa_handle: The interface to the ITOAObject store
        @type: object

        @return: The service template object from the KVStore
        @type: object
        """
        identifiers = [{'identifying_name': name} for name in template_names]

        maybe_templates = None

        if identifiers:
            maybe_templates = itoa_handle.service_template.get_bulk(
                itoa_handle.owner,
                filter_data={'$or': identifiers}
            )

        if maybe_templates:
            return maybe_templates
        else:
            return []

    def validate_cache(self, itoa_handle):
        """
        Validates that service templates in the template cache exist in the KVStore.

        @param itoa_handle: The interface to the ITOAObject store
        @type: object
        """
        templates = self._cache.keys()
        template_objects = {
            template['identifying_name']: {'key': template['_key'], 'entity_rules': template['entity_rules']}
            for template in self._validate_service_templates(templates, itoa_handle)
        }

        for template in self._cache.keys():
            if template in template_objects:
                self._cache[template].key = template_objects[template]['key']
                self._cache[template].entity_rules = template_objects[template]['entity_rules']
            else:
                logger.warning('Service template with title: {0} does not exist'.format(template))
                self._cache.pop(template, None)

        self.clean_up_service_relationships()

    def clean_up_service_relationships(self):
        """
        Removes invalid templates from service relationships

        @return:
        """
        for service in self.service_relationships:
            self.service_relationships[service] = list(
                filter(
                    lambda template_name: self._cache.get(template_name),
                    self.service_relationships[service]))

    def update_with(self, template):
        """
        Updates the template cache with the given service and service template.

        @param template: The service template to link the service to
        @type: object
        """
        if template:
            self._update_cache(template)
