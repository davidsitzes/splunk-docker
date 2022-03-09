# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import SERVICE, TEMPLATE, logger
from itoa_bulk_import_template import ImportTemplate

from copy import deepcopy


class TemplateParser(object):
    """
    Parses the service template field for a given row out of the CSV file.
    """

    def __init__(self, bulk_import_spec, headers):
        """
        @param bulk_import_spec: The bulk import specification object
        @type: object

        @param headers: A mapping of row positions to import specification tokens
        @type: dictionary
        """

        if SERVICE in bulk_import_spec:
            self.service_spec = bulk_import_spec.service

        if TEMPLATE in bulk_import_spec:
            self.template_spec = bulk_import_spec.template

        self.headers = headers

    def __call__(self, row):
        """
        @param row: The CSV row to parse
        @type: list

        @return: The ImportTemplate object created with the parsed data
        @type: object
        """
        return self.parse(row)

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

    def _parse_service_template(self, row):
        """
        Parses the service template name out of the CSV data row.

        @param row: CSV data row
        @type: list

        @return: The ImportTemplate object
        @type: object
        """
        template_title = None
        template_title_column = self.service_spec.get('serviceTemplate', None)
        if template_title_column:
            template_title_index = self.headers.get(template_title_column, None)
            template_title = row[template_title_index]

        service_title_column = self.service_spec.get('titleField', None)
        if service_title_column:
            service_title_index = self.headers.get(service_title_column, None)
            service_title = row[service_title_index]

        if template_title:
            template = ImportTemplate(template_title)
            template.add_service({service_title: {'title': service_title, 'key': None}})

            return template
        else:
            return None

    def parse_entity_rules(self, row, template):
        """
        For a given CSV data row, extract the entity rules values and update the template's service object.

        @param row: CSV data row
        @type: list

        @param template: The ImportTemplate object to update
        @type: object
        """
        template_spec = self.template_spec.get(template.title, {})
        entity_rules = deepcopy(template_spec.get('entity_rules', []))
        entity_rules_values = {}
        service = template.services.keys()[0]

        for rule_item in self._iterate_entity_rules(entity_rules):
            value_column = rule_item.get('value', None)
            value_index = self.headers.get(value_column, None)

            if value_index is not None and isinstance(value_index, int):
                item_value = row[value_index]
            else:
                logger.warning('Invalid column index found, while setting entity rule value for service linked to '
                               'service template. Setting entity rule value to empty string. service="%s", '
                               'entity_value_column_title="%s", entity_value_column_index="%s"',
                               service, value_column, value_index)
                item_value = ''

            if value_column in entity_rules_values:
                entity_rules_values[value_column].append(item_value)
            else:
                entity_rules_values.update({value_column: [item_value]})

        template.services[service]['entity_rules'] = entity_rules
        template.services[service]['entity_rules_values'] = entity_rules_values

    def parse(self, row):
        """
        For a given CSV data row, extract the data needed to create an ImportTemplate object.

        @param row: CSV data row
        @type: list
        """
        return self._parse_service_template(row)
