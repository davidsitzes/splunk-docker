# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from itoa_bulk_import_common import logger, CSVLoaderBadReq, ENTITY
from itoa_bulk_import_entity import ImportedEntity
from collections import defaultdict
import ITOA.itoa_common as utils
import json

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_specification import BulkImportSpecification  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class EntityParser(object):
    """
    Given a bulk import spec and the source headers, validate that there is sufficient
    overlap between the two to extract valid entities from an import row, and initialize
    this object as a functor to do just that.
    """

    def __init__(self, bulk_import_spec, headers, user='nobody'):
        # type: (BulkImportSpecification, Dict[str, int], str) -> None
        """
        @param self: a new EntityParser
        @type: object

        @param bulk_import_spec: the bulk import specification object
        @type: object

        @param headers: a mapping of row positions to import specification tokens
        @type: dictionary

        @return: self
        @type: object
        """
        if ENTITY not in bulk_import_spec:
            return

        entity_spec = bulk_import_spec.entity
        title_at = headers.get(entity_spec['titleField'], -1)
        if title_at == -1:
            raise CSVLoaderBadReq('No title field for entities found in source data.')

        entity_fields = bulk_import_spec.fields_to_import.entity_fields
        valid_fieldnames = [fieldname for fieldname in entity_fields if fieldname in headers.keys()]
        skipped_fields = set(entity_fields) - set(valid_fieldnames)
        if skipped_fields:
            msg = _('Entity are specified in import rule but not present in source, will be skipped: {}')
            logger.warning(msg.format(', '.join(list(skipped_fields))))

        found_fieldnames = [fieldname for fieldname in valid_fieldnames if
                            ((fieldname in entity_spec['identifierFields']) or
                             (fieldname in entity_spec['informationalFields']) or
                             (fieldname in entity_spec['descriptionColumns']) or
                             (fieldname in entity_spec['service_column']))]

        # TODO: Does this erroneously report the title field?
        missing_fieldnames = set(valid_fieldnames) - set(found_fieldnames)
        if missing_fieldnames:
            msg = _('Entity fieldnames discovered as valid fieldname but not present in fields to be imported, will be skipped: {}')
            logger.warning(msg.format(', '.join(list(missing_fieldnames))))

        # What we'll really need to do the parse...
        self.user = user
        self.bulk_import_spec = bulk_import_spec
        self.entity_spec = entity_spec
        self.title_at = title_at
        self.headers = headers
        self.valid_fieldnames = found_fieldnames

    def __call__(self, row):
        # type: (Sequence[Text]) -> Optional[ImportedEntity]
        """
        Turns this object into a Python functor

        @param row: the row to parse
        @type: list of strings

        @return: the entity
        @type: dict | None
        """
        return self.parse(row)

    def parse(self, row):
        # type: (Sequence[Text]) -> Optional[ImportedEntity]
        """
        Given a row of data, extract all of the information relevant to an entity according to
        the import specification, and return a valid entity record if possible.

        @param row: The inbound data
        @type list of string

        @return entity: The extracted entity
        @type dict | None

        """

        if len(row) <= self.title_at:
            msg = _('Bad data in source: Row contains not enough data to process all requested fields: "{}"')
            logger.warning(msg.format(json.dumps(row)))
            return None

        title = row[self.title_at]
        title = title.strip() if isinstance(title, basestring) else None
        if not (title and utils.is_valid_str(title)):
            msg = _('Bad data in source: Row contains empty title: "{}"')
            logger.warning(msg.format(json.dumps(row)))
            return None

        if not utils.is_valid_name(title):
            msg = _('Bad data in source: Names cannot contain equal or quote characters: "{}"')
            logger.warning(msg.format(json.dumps(row)))
            return None

        identifiers = defaultdict(list, {})    # type: defaultdict[Text, List[Text]]
        informational = defaultdict(list, {})  # type: defaultdict[Text, List[Text]]
        description = []                       # type: List[Text]
        services = []                          # type: List[Text]

        for fieldname in self.valid_fieldnames:
            if self.headers[fieldname] >= len(row):
                msg = _('Bad data in source: Row contains not enough data to process all requested fields: "{}"')
                logger.warning(msg.format(json.dumps(row)))
                continue
            row_value = row[self.headers[fieldname]].strip()
            if row_value == '':
                logger.debug('Received empty value in requested field: {}'.format(fieldname))
                continue
            output_fieldname = self.entity_spec['fieldMapping'].get(fieldname, fieldname)
            if fieldname in self.entity_spec['descriptionColumns']:
                description.append(row_value)
                continue
            if fieldname in self.entity_spec['informationalFields']:
                informational[output_fieldname].append(row_value)
                continue

            # The next two fields are identifiers.  Their values may refer to
            # identifying_names found elsewhere in the system.  They must be legal.
            if not utils.is_valid_name(row_value):
                msg = _('Bad data in source: Identifiers cannot contain equal or quote characters: "{}"')
                logger.warning(msg.format(row_value))
                continue
            if fieldname in self.entity_spec['identifierFields']:
                identifiers[output_fieldname].append(row_value)
                continue
            if fieldname in self.entity_spec['service_column']:
                services.append(row_value)
                continue

        return ImportedEntity(
            {
                'title': title,
                'identifiers': identifiers,
                'informational': informational,
                'description': description,
                'services': services
            },
            self.user,
            self.bulk_import_spec.source)
