# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from copy import deepcopy

import json

class ImportTemplate(object):
    """
    Data container to keep track of which services will be linked
    to a given service template and other necessary fields.
    """
    def __init__(self, title):
        self.title = title
        self.identifying_name = self.title.lower().strip()
        self.key = None
        self.services = {}
        self.entity_rules = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def add_service(self, service):
        """
        Convenience method to add a service to a service template's services field.

        @param service: Service
        @type: dict
        """
        service_title = service.keys()[0]
        if service_title in self.services:
            self.update_service(service)
        else:
            self.services.update(service)

    def update_service(self, service):
        """
        Update a template's existing service

        @param service: Service
        @type: dict
        """
        service_title = service.keys()[0]
        service_entity_rules_values = service[service_title].get('entity_rules_values', None)
        entity_rules_values = None

        if service_title:
            entity_rules_values = self.services[service_title].get('entity_rules_values', None)

        if entity_rules_values:
            entity_rules_values = deepcopy(entity_rules_values)

        if service_entity_rules_values:
            for column_value in service_entity_rules_values:
                if column_value in entity_rules_values:
                    entity_rules_values[column_value] = entity_rules_values[column_value] + service_entity_rules_values[column_value]

        self.services[service_title]['entity_rules_values'] = entity_rules_values