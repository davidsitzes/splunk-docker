# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from itoa_bulk_import_common import logger, CSVLoaderBadReq, SERVICE, window
from itoa_bulk_import_service import ImportedService
import ITOA.itoa_common as utils
import json

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_specification import BulkImportSpecification  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class ServiceParser(object):
    """
    Given a bulk import spec and the source headers, validate that there is sufficient overlap
    between the two to extract valid services from an import row, and initialize this object
    as a functor to do just that.
    """

    def __init__(self, bulk_import_spec, headers):
        # type: (BulkImportSpecification, Dict[Text, int]) -> None
        """
        @param self: a new ServiceParser
        @type: object

        @param bulk_import_spec: the bulk import specification object
        @type: object

        @param headers: a mapping of row positions to import specification tokens
        @type: dictionary

        @return: self
        @type: object
        """

        # Give up if there's nothing in the specification that says we're working with
        # services.  Not an error.
        if SERVICE not in bulk_import_spec:
            return

        service_spec = bulk_import_spec.service
        service_fields = bulk_import_spec.fields_to_import.service_fields
        valid_fieldnames = [fieldname for fieldname in service_fields if fieldname in headers.keys()]
        skipped_fieldnames = set(service_fields) - set(valid_fieldnames)

        if skipped_fieldnames:
            logger.warning('Service fieldnames "%s" are specified in import rule but not present in source, will be skipped.',
                           ', '.join(list(skipped_fieldnames)))

        found_fieldnames = [fieldname for fieldname in valid_fieldnames
                            if (fieldname in service_spec['descriptionColumns'])]

        # TODO: Does this erroneously report the title field?
        missing_fieldnames = set(valid_fieldnames) - set(found_fieldnames)
        if missing_fieldnames:
            logger.warning(('Service fieldnames "{}" discovered as valid fieldname but not present in fields to be imported, '
                            'will be skipped.').format(', '.join(list(missing_fieldnames))))

        # The BIS asserts that there is a title field.  Now to see if the source agrees.
        title_at = headers.get(service_spec['titleField'], -1)
        if title_at == -1:
            raise CSVLoaderBadReq('No title column "{}" found for services in source data.'.format(service_spec['titleField']))

        # What we'll really need to do the parse...
        self.service_rel = bulk_import_spec.service_rel
        self.service_dependents = bulk_import_spec.service_dependents
        self.service_spec = service_spec
        self.title_at = title_at
        self.headers = headers
        self.valid_fieldnames = found_fieldnames

    def __call__(self, row):
        # type: (Sequence[Text]) -> List[ImportedService]
        """
        Turns this object into a Python functor

        @param row: the row to parse
        @type: list of strings

        @return: the service
        @type: dict | None
        """
        return self.parse(row)

    def parse(self, row):
        # type: (Sequence[Text]) -> List[ImportedService]
        """
        Given a row of data, extract all of the information relevant to any named services
        on the row according to the import specification, and return valid service records
        if possible.

        @param row: The inbound data
        @return A list of extracted services
        """
        if len(row) <= self.title_at:
            msg = _('Bad data in source: Row contains not enough data to process all requested fields: "{}"')
            logger.warning(msg.format(json.dumps(row)))
            return []

        title = row[self.title_at]
        title = title.strip() if isinstance(title, basestring) else None
        if not title:
            logger.warning('Bad data in source: Row contains empty title: "{}"'.format(json.dumps(row)))
            return []

        if not utils.is_valid_name(title):
            msg = _('Bad data in source: Names cannot contain equal or quote characters: "{}"')
            logger.warning(msg.format(json.dumps(row)))
            return []

        clone_service_id = self.service_spec.get('serviceClone', None)

        descriptions = []  # type: List[Text]
        for fieldname in self.valid_fieldnames:
            if not self.headers[fieldname] < len(row):
                msg = _('Bad data in source: Row contains not enough data to process all requested fields: "{}"')
                logger.warning(msg.format(json.dumps(row)))
                continue
            row_value = row[self.headers[fieldname]].strip()
            if row_value != '' and fieldname in self.service_spec['descriptionColumns'] and row_value not in descriptions:
                descriptions.append(row_value)
                continue

        new_main_service = ImportedService({
            'title': title,
            'description': descriptions,
            'clone_service_id': clone_service_id
        })

        # This is only used to define dependent or relationship services, so don't do clone_service_id
        def make_new_service(fieldname):
            if fieldname not in self.headers.keys():
                return None
            if not self.headers[fieldname] < len(row):
                msg = _('Bad data in source: Row contains not enough data to process all requested fields: "{}"')
                logger.warning(msg.format(json.dumps(row)))
                return None
            row_value = row[self.headers[fieldname]].strip()
            if row_value == '':
                return None
            return ImportedService({
                'title': row_value,
                'description': []
            })

        new_services = []  # type: List[ImportedService]
        for fieldname in self.service_rel:
            maybe_imported_service = make_new_service(fieldname)
            if maybe_imported_service:
                new_services.append(maybe_imported_service)

        # Establish a linear relationships among the services, in a left-to-right order.
        all_services = new_services + [new_main_service]

        def may_depend(svc, dep):
            # type: (ImportedService, ImportedService) -> Set[Text]
            if dep and dep.identifying_name != svc.identifying_name:
                return set([dep.identifying_name])
            return set([])

        # Work-around because '+' can't be overriden for heterogenous list types.
        windowed = []  # type: List[Any]
        windowed.append(None)
        windowed.extend(all_services)
        windowed.append(None)

        for (prv, svc, nxt) in window(windowed, 3):
            svc.depends_on_me = svc.depends_on_me.union(may_depend(svc, prv))
            svc.i_depend_upon = svc.i_depend_upon.union(may_depend(svc, nxt))

        dep_services = []
        for fieldname in self.service_dependents:
            maybe_imported_service = make_new_service(fieldname)
            if maybe_imported_service:
                dep_services.append(maybe_imported_service)

        all_names = [svc.identifying_name for svc in all_services]
        for svc in dep_services:
            if svc.identifying_name == new_main_service.identifying_name:
                continue
            new_main_service.i_depend_upon = new_main_service.i_depend_upon.union([svc.identifying_name])
            svc.depends_on_me = svc.depends_on_me.union([new_main_service.identifying_name])
            if svc.identifying_name not in all_names:
                all_services.append(svc)
                all_names = [svc.identifying_name for svc in all_services]

        return all_services
