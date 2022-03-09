# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import logger, CSVLoaderBadReq, ENTITY_RELATIONSHIP
from itoa_bulk_import_entity_relationship import ImportedEntityRelationship
import json


class EntityRelationshipParser(object):
    """
    Given a bulk import spec and the source headers, validate that there is sufficient
    overlap between the two to extract valid entity relationships from an import row, and initialize
    this object as a functor to do just that.
    """

    def __init__(self, bulk_import_spec, headers, user='nobody'):
        """
        @type self: object
        @param self: a new EntityRelationshipParser

        @type: object
        @param bulk_import_spec: the bulk import specification object

        @type: dictionary
        @param headers: a mapping of row positions to import specification tokens

        @type user: basestring
        @param user: user who make the request
        """
        if ENTITY_RELATIONSHIP not in bulk_import_spec:
            return

        entity_relationship_spec = bulk_import_spec.entity_relationship

        entity_relationship_fields = bulk_import_spec.fields_to_import.entity_relationship_fields

        valid_fields = [field for field in entity_relationship_fields if field in headers.keys()]
        skipped_fields = set(entity_relationship_fields) - set(valid_fields)
        if skipped_fields:
            logger.warning('Entity relationship fields "%s" are specified in import rule but not present '
                           'in source, will be skipped.', ', '.join(list(skipped_fields)))

        # Flatten entity_relationship_spec values that is a dict[list] to a list
        spec_value_lists = entity_relationship_spec.get('entity_relationship_spec', {}).values()
        spec_values = [val for sublist in spec_value_lists for val in sublist]

        found_fields = [field for field in valid_fields if
                        (field in [entity_relationship_spec['subjectField']] or field in spec_values)]

        missing_fields = set(valid_fields) - set(found_fields)
        if missing_fields:
            logger.warning('Entity relationship fields "%s" discovered as valid fields '
                           'but not present in fields to be imported, will be skipped.', ', '.join(list(missing_fields)))

        # The BIS asserts that there is a title field.  Now to see if the source agrees.
        title_at = headers.get(entity_relationship_spec['subjectField'], -1)
        if title_at == -1:
            raise CSVLoaderBadReq('No subject field for entity relationships found in source data.')

        # What we'll really need to do the parse...
        self.user = user
        self.bulk_import_spec = bulk_import_spec
        self.entity_relationship_spec = entity_relationship_spec
        self.title_at = title_at
        self.headers = headers
        self.valid_fields = found_fields

    def __call__(self, row):
        """
        Turns this object into a Python functor

        @type: list[string]
        @param row: the row to parse

        @type return: list[ImportedEntityRelationship] | []
        @return: the entity relationships

        """
        return self.parse(row)

    def parse(self, row):
        """
        Given a row of data, extract all entity relationships according to
        the import specification, and return a list of valid entity relationships if possible.

        @type row: list[string]
        @param row: The inbound data

        @rtype: list[ImportedEntityRelationship] | []
        @return: the extracted entity relationships
        """
        if len(row) <= self.title_at:
            logger.warning('Bad data in source: Row contains not enough data to process all requested fields: "%s"',
                           json.dumps(row))
            return []

        title = row[self.title_at]
        title = title.strip() if isinstance(title, basestring) else None
        if not title:
            logger.warning('Bad data in source: Row contains empty subject field: "%s"', json.dumps(row))
            return []

        field_mapping = {}
        for field in self.valid_fields:
            if self.headers[field] >= len(row):
                logger.warning('Bad data in source: Row contains not enough data to process all requested fields: "%s"',
                               json.dumps(row))
                continue
            row_value = row[self.headers[field]].strip()
            if row_value == '':
                logger.debug('Received empty value in requested field {}'.format(field))
                continue
            field_mapping[field] = row_value

        entity_relationships = []
        entity_relationship_spec = self.bulk_import_spec.entity_relationship
        subject_identifier = field_mapping[entity_relationship_spec['subjectField']]
        for predicate_spec, object_specs in entity_relationship_spec['entity_relationship_spec'].iteritems():
            for object_spec in object_specs:
                object_identifier = field_mapping.get(object_spec)
                if object_identifier is None:
                    logger.debug('Row contains no object field "%s": "%s"', object_spec, json.dumps(row))
                    continue

                new_entity_relationship = ImportedEntityRelationship(
                    {
                        'subject_identifier': subject_identifier,
                        'object_identifier': object_identifier,
                        'predicate': predicate_spec
                    },
                    self.user,
                    self.bulk_import_spec.source)

                entity_relationships.append(new_entity_relationship)

        return entity_relationships
