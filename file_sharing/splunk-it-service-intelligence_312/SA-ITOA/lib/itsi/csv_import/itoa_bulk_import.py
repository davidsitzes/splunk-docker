# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import time  # Used because datetime sucks at giving back data to calculate deltas from
from collections import namedtuple
import json

from itoa_bulk_import_specification import BulkImportSpecification

from itoa_bulk_import_entity_parser import EntityParser
from itoa_bulk_import_entity_cache import EntityCache
from itoa_bulk_import_entity_updater import EntityUpdater

from itoa_bulk_import_service import ImportedService
from itoa_bulk_import_service_parser import ServiceParser
from itoa_bulk_import_service_cache import ServiceCache
from itoa_bulk_import_service_updater import serviceUpdater

from itoa_bulk_import_template_parser import TemplateParser
from itoa_bulk_import_template_cache import TemplateCache
from itoa_bulk_import_template_updater import TemplateUpdater

from itoa_bulk_import_entity_relationship_cache import EntityRelationshipCache
from itoa_bulk_import_entity_relationship_parser import EntityRelationshipParser
from itoa_bulk_import_entity_relationship_updater import EntityRelationshipUpdater

from itoa_bulk_import_common import (logger,
                                     SERVICE,
                                     ENTITY,
                                     TEMPLATE,
                                     SERVICE_IMPORT,
                                     ENTITY_IMPORT,
                                     CSVLoaderBadReq,
                                     ImportConfig,
                                     ENTITY_RELATIONSHIP)
from itoa_bulk_import_new_service import ServiceSource
from itoa_bulk_import_itoa_handle import ItoaHandle
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
from itsi.service_template.service_template_utils import ServiceTemplateUtils


# try:  # noqa: F401
#     from typing import Iterator, Sequence, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_service import ImportedService  # noqa: F401
#     from itoa_bulk_import_entity import ImportedEntity  # noqa: F401
#     from itoa_bulk_import_entity_relationship import ImportedEntityRelationship  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401

# An object to help keep track of data in a single row, providing unique access names to
# the entity and service and entity relationship information derived from the row.
DataRow = namedtuple('DataRow', ['entity', 'services', 'entity_relationships', 'template'])

# An object to help keep track of data in a single row, providing unique access names to
# the entity and service and entity relationship collection information derived from a batch of rows.  This is a
# rather nasty way of hiding the fact that 'entities' and 'services' are abstract; in
# some cases, they return values, in others just IDs.
DataPair = namedtuple('DataPair', ['entities', 'services', 'entity_relationships', 'templates'])

LOG_CHANGE_TRACKING = '[change_tracking] '
DEFAULT_BATCH_SIZE = 750  # Number of rows to process before attempting save to Storage


def _unicodify(obj):
    # type: (str) -> Text
    # Attempt to unicodify one element
    #
    # @param obj: the object to unicodify
    # @type: string (hopefully)
    #
    # @return obj: the object, unicodified if successful, or unchanged if not
    # @type unicode if successful, else the object's original type
    try:
        return unicode(obj, errors='replace')
    except Exception, e:
        logger.exception('Skipping unicode normalizing of column "%s". Error: %s', obj, str(e))
    return obj


def unicodify_source(source):
    # type: (Iterator[Sequence[str]]) -> Iterator[Sequence[Text]]
    """
    An iterator that returns a row of strings after they've been converted to python unicode format.

    @param source: an iterator of rows
    @type: iterator(seq)

    @return: an iterator of rows, each element of row converted to unicode.
    @type: iterator(seq)
    """
    for row in source:
        yield [_unicodify(i) for i in row]

def _process_templates(templates):
    """
    Creates a service link map and entity rules map for a given list of ImportTemplates.

    @param templates: List of ImportTemplate objects
    @type: list

    @return: Tuple of service_links dict and entity_rules dict
    @type: tuple
    """
    service_links = {}
    entity_rules = {}

    for template in templates:
        for service in template['services'].values():
            if template['key'] in service_links:
                service_links[template['key']].append(service['key'])
            else:
                service_links[template['key']] = [service['key']]

            if service['key'] not in entity_rules and 'entity_rules' in service:
                entity_rules[service['key']] = service['entity_rules']

    return service_links, entity_rules

class SkippedRowCounter(object):
    """
    A simple functor to track not only when rows should be skipped, but how often and why.
    """
    def __init__(self, import_type):
        # type: (int) -> None
        """
        @param import_type: the type we should be scanning for
        @type: flag

        @return: self
        @type: object
        """
        self.import_type = import_type
        self.entities_skipped = 0
        self.services_skipped = 0
        self.entity_relationships_skipped = 0

    def __call__(self, entity=None, service=None, entity_relationship=None):
        # type: (Optional[ImportedEntity], Optional[ImportedService], Optional[ImportedEntityRelationship]) -> bool
        """
        For a given row, report if it should be skipped, and count whether
        an entity or service was skipped

        @param row: An object containing entity and/or service data
        @type: DataRow

        @return: whether or not to skip this row
        @type: bool
        """

        # Only record a skipped type if the specification says we're trying to find
        # objects of that type.
        if not (entity or service):
            if (self.import_type & ENTITY_IMPORT):
                self.entities_skipped += 1
                self.entity_relationships_skipped += 1
            if (self.import_type & SERVICE_IMPORT):
                self.services_skipped += 1
            return True

        failed_e = False
        failed_s = False

        if (self.import_type & ENTITY_IMPORT) and not entity:
            failed_e = True
            self.entities_skipped += 1
            self.entity_relationships_skipped += 1

        if (self.import_type & SERVICE_IMPORT) and not service:
            failed_s = True
            self.services_skipped += 1

        return failed_e and failed_s


class DataHandler(object):
    def __init__(self, handle=None):
        # type: (Union[None, ItoaHandle]) -> None
        pass

    def __call__(self, datapair, transaction_id):
        # type: (DataPair, Text) -> DataPair
        raise NotImplementedError(_('This class cannot be called directly.'))


class DataPersistence(DataHandler):
    def __init__(self, itoa_handle):
        DataHandler.__init__(self, itoa_handle)
        """
        One of several outcomes of our functionality, in this case, writing the data to the back-end.
        """
        self.itoa_handle = itoa_handle
        self.services_written = 0
        self.entities_written = 0
        self.entity_relationships_written = 0
        self.service_template_utils = ServiceTemplateUtils(self.itoa_handle.session_key, self.itoa_handle.current_user)

    def _persist_data(self, object_type, objects, transaction_id):
        # type: (str, Sequence[dict], Text) -> List[Union[Text, Dict[Text, Any]]]
        # Given a collection of objects of a given type, save them to KVStore
        #
        # @param object_type: the type to save
        # @type: enum ENTITY or SERVICE
        #
        # @param objects: the types we wish to save to KVStore
        # @type: list of dicts
        #
        # @return: ids corresponding to saved objects
        # @type: list of strings
        LOG_CHANGE_TRACKING = '[itoa_bulk_import:persist_data]'
        logger.info('{} user={} method=batch_save object type={} itoa object_count={}'.format(
            LOG_CHANGE_TRACKING, self.itoa_handle.current_user, object_type, len(objects)))
        return self.itoa_handle(object_type).save_batch(self.itoa_handle.owner, objects, True, req_source='load_csv')

    def __call__(self, datapair, transaction_id):
        # type: (DataPair, Text) -> DataPair
        """
        Convenience method for persisting this data
        @param datapair: A named tuple of entity and service objects to write
        @returns: A named tuple of the ids corresponding to the saved objects.
        """
        service_ids = []  # type: List[Text]
        entity_ids = []  # type: List[Text]
        entity_relationship_ids = []  # type: List[Text]
        template_ids = [] #type: List[Text]
        if datapair.services:
            service_ids = self._persist_data(SERVICE, datapair.services, transaction_id)
        if datapair.entities:
            entity_ids = self._persist_data(ENTITY, datapair.entities, transaction_id)
        if datapair.entity_relationships:
            entity_relationship_ids = self._persist_data(ENTITY_RELATIONSHIP,datapair.entity_relationships, transaction_id)
        if datapair.templates:
            template_ids = [template['key'] for template in datapair.templates]
            service_links, entity_rules = _process_templates(datapair.templates)
            self.service_template_utils.bulk_link_services_to_templates(
                owner='nobody',
                service_link_map=service_links,
                entity_rules=entity_rules,
                transaction_id=transaction_id,
                update_if_linked=True
            )

        self.services_written += len(service_ids)
        self.entities_written += len(entity_ids)
        self.entity_relationships_written += len(entity_relationship_ids)

        return DataPair(entities=entity_ids, services=service_ids, entity_relationships=entity_relationship_ids, templates=template_ids)


class ServicePreviewBuilder(DataHandler):
    """
    Collects and extracts from the importer routine a collection of services to be provided
    for preview.
    """
    def __init__(self, handler=None):
        self._services = {}  # type: Dict[Text, Dict[Text, Any]]

    @property
    def services(self):
        # type: () -> Dict[Text, Dict[Text, Any]]
        return self._services

    def __call__(self, datapair, transaction_id):
        # type: (DataPair, Text) -> DataPair
        if not len(datapair.services):
            return datapair
        for service in datapair.services:
            self._services.setdefault(service['title'], service)
        return datapair


class EntityPreviewBuilder(DataHandler):
    """
    Collects and extracts from the importer routine a collection of entities to be provided
    for preview.
    """

    def __init__(self, handler=None):
        self._entities = []  # type: List[Dict[Text, Any]]

    @property
    def entities(self):
        # type: () -> List[Dict[Text, Any]]
        return self._entities

    def __call__(self, datapair, transaction_id):
        # type: (DataPair, Text) -> DataPair
        if not len(datapair.entities):
            return datapair
        for entity in datapair.entities:
            self._entities.append(entity)
        return datapair


class TemplatePreviewBuilder(DataHandler):
    """
    Collects and extracts a collection of templates from the importer routine to provide a preview.
    """
    def __init__(self):
        self._templates = {} # type: List[Dict[Text, Any]]

    @property
    def templates(self):
        # type: () -> Dict[Text, Dict[Text, Any]]
        return self._templates

    def simplify_template(self, template):
        return {
            'services': [service['title'] for service in template['services'].values()],
            'entity_rules': template['entity_rules'],
            'key': template['key']
        }

    def __call__(self, datapair, transaction_id):
        # type: (DataPair, Text) -> DataPair
        if not datapair.templates:
            return datapair

        for template in datapair.templates:
            self._templates.setdefault(template['title'], self.simplify_template(template))

        return datapair


class BulkImporter(object):
    """
       Defines a parser that takes bulk import information for ITSI Entities and Services, and
       loads that information into KVStore as efficiently as possible.

       A bulk import event consists of three elements: (1) A Bulk Import Specification,
       which specifies a list of tokens mapped to their roles.  See the
       itoa_bulk_import_specification object for more details.  (2) An iterator of ordered
       tuples of data, each datum of which may fulfill one and only one rule according to
       the Bulk Import Specification (for example, a row of CSV-derived data), (3) An
       ordered tuple that maps the positions in the ordered data tuple from #2 to the
       roles in the Bulk Import Specification.

    """

    ###############
    # Instance methods
    ###############

    def __init__(self, specification, session_key, current_user, owner):
        # type: (Dict[Text, Any], str, str, str) -> None
        """
        The init method
        @param owner: owner; for permissions
        @type: string

        @param import_spec: valid import specification
        @type: dict

        @param session_key : splunkd session key
        @type: string

        @param current_user: current user
        @type: string

        @param preview: Boolean indicating if its preview only, or if caller wants to commit
        @type: bool

        @return: self
        @type: object
        """
        self.itoa_handle = ItoaHandle(owner, session_key, current_user)
        self.itoa_config = ImportConfig(session_key, owner)
        self.import_spec = BulkImportSpecification(specification, current_user)
        sec_grp = GLOBAL_SECURITY_GROUP_CONFIG.get('key')

        enable_service = False
        backfill_enabled = False
        if 'service' in self.import_spec:
            if self.import_spec.service.get('serviceEnabled', '0') == '1':
                enable_service = True

            if self.import_spec.service.get('backfillEnabled', '0') == '1':
                backfill_enabled = True

            # the UI makes sure that there is always a default value
            # default_itsi_security_group
            sec_grp = self.import_spec.service.get('serviceSecurityGroup')


        self.service_source = ServiceSource(self.itoa_handle, enable_service, sec_grp, self.import_spec.source, backfill_enabled)

    @property
    def import_specification(self):
        return self.import_spec

    def _derive_header_positions(self, header):
        # type: (Sequence) -> Dict
        # Given the ordered tuple that maps tokens to their positions in the inbound data tuples,
        # create a an actual map of the tokens and their positions.
        #
        # @param header: A tuple of header tokens
        # @type: list of strings
        #
        # @return: A dictionary of header tokens and their positions in the tuple
        # @type: dict {string: number}

        header_positions = {}
        for index, name in enumerate(header):
            if name.strip() in header_positions:
                raise CSVLoaderBadReq('Duplicate fieldname in row assignment: {0}'.format(name.strip()))

            header_positions[name.strip()] = index

        return header_positions

    def _process_batch(self, rows):
        # type: (Sequence[DataRow]) -> DataPair
        # Given a collection of rows, merge all entities with the same key in the collection into
        # an entity_cache, and do the same with services and entity relationships.  Then get all
        # the entities, services and entity relationships with corresponding keys from KVStore,
        # and merge with those.  Finally, save the data.
        #
        # @param rows: an iterator of entities and services and entity relationships
        # @type iterator of DataRow
        #
        # @return: the services and entities OR the service_ids and entity_ids
        # @type: tuple of list of (dict OR string)

        # The Entity Cache and Service Cache and Entity Relationship Cache are specialized for their respective inbound
        # data.

        logger.debug('Processing batch of size %s', len(rows))

        entity_cache = EntityCache()
        service_cache = ServiceCache()
        entity_relationship_cache = EntityRelationshipCache()
        template_cache = TemplateCache()

        # If an entity does not have a specific service, it will be bound to the services
        # listed in the Block Import Specification's selectedServices list.

        for service in self.import_spec.selectedServices:
            if service not in service_cache:
                service_cache[service] = ImportedService({'title': service})

        for row in rows:
            # 1. Entities can occur multiple times within a data source.  The entity cache
            #    automatically merges row entity information as needed.  Although the
            #    caches are constructed as dictionaries, 'update_with' is used here
            #    because the services mentioned in a row cannot (and should not!) be
            #    instantiated weakly.

            if row.entity:
                entity_cache.update_with(row.entity)

            if row.services:
                service_cache.update_with(row.services)
                template_cache.update_with(row.template)

            if row.entity_relationships:
                entity_relationship_cache.update_with(row.entity_relationships)

        # Validate that the service templates in the cache exist
        template_cache.validate_cache(self.itoa_handle)

        # Validate that services are only being linked to one template
        template_updater = TemplateUpdater(template_cache)
        template_updater.validate_templates()

        # For services, the entity list goes into the rules collection, and is keyed by
        # identifying_name.
        services = serviceUpdater(service_cache, self.itoa_handle, self.service_source, template_cache.services())

        # For entities, however, the list of services that an entity impacts is keyed by
        # both the title and _key, so the services must be sent to the updater.

        entity_updater = EntityUpdater(self.itoa_handle, self.import_spec.update_type, services)
        entities = entity_updater.update(entity_cache)

        entity_relationship_updater = EntityRelationshipUpdater(self.itoa_handle, self.import_spec.update_type)
        entity_relationships = entity_relationship_updater.update(entity_relationship_cache)

        # Update the template objects with their services IDs
        templates = template_updater.update(services)

        return DataPair(entities=entities, services=services, entity_relationships=entity_relationships, templates=templates)

    ###########################################################
    # Main CSV loading method
    ###########################################################

    def _bulk_import(self, source, handler, transaction_id):
        # type: (Iterator[Sequence[str]], DataHandler, Text) -> Tuple[DataHandler, SkippedRowCounter]
        """
        Given a source of data tuples, loading and save the entities and services found therein.

        @param source: a source of data tuples
        @type: iterator(seq)

        @param transaction_id: unique ID for current bulk import operation
        @type: string

        @return: the services and entities OR the service_ids and entity_ids
        @type: tuple of list of (dict OR string)

        @raise indirectly CSVLoaderError/Exception from Statestore
        """
        start_time = time.time()
        logger.info('CSV data load initializing mark start=%s', start_time)

        # The first row of the source contains the header tokens as a list.  The *whole
        # point* of this function is to take the BulkImportSpecification (BIS), and
        # successive rows from the source, and map each row's contents to a service, an
        # entity, or both, using the BIS as guidance for *how* that should happen, while
        # performing merge/replace/append operations on the entities, and consistency
        # checks on the services, and so on.

        unicoded_source = unicodify_source(source)
        skip_row = SkippedRowCounter(self.import_spec.import_type)

        try:
            first_line = next(unicoded_source)
        except StopIteration:
            return (handler, skip_row)

        header_positions = self._derive_header_positions(first_line)
        entity_parser = EntityParser(self.import_spec, header_positions, self.itoa_handle.current_user)
        service_parser = ServiceParser(self.import_spec, header_positions)
        entity_relationship_parser = EntityRelationshipParser(self.import_spec, header_positions,
                                                              self.itoa_handle.current_user)
        template_parser = TemplateParser(self.import_spec, header_positions)

        logger.info('Starting CSV parsing. skipping empty rows/rows with'
                    ' no title fields for either services or entities')

        batch_size = self.itoa_config.get('import_batch_size', DEFAULT_BATCH_SIZE)
        rows = []  # type: List[DataRow]
        for row in unicoded_source:
            if len(row) == 0:
                logger.warning('Bad data in source: Row contains not enough data to process all requested fields: %s', json.dumps(row))
                continue

            entity = None
            if ENTITY in self.import_spec:
                entity = entity_parser(row)

            # The truth is that there are multiple named services on a single row. We must be able to handle
            # all of them correctly.
            services = []  # type: List[ImportedService]
            template = None
            if SERVICE in self.import_spec:
                services = service_parser(row)
                template = template_parser(row)

            if TEMPLATE in self.import_spec and template:
                template_parser.parse_entity_rules(row, template)

            service = None
            if services:
                # "The" service is the LAST service returned.  -1 is an acceptable index
                # for LAST even in cases where the services list is only one object.
                # 'services' is False-y when empty, so the test correctly handles this.
                service = services[-1]

            # Establish relationships between the entity and the services.
            if entity and services:
                for svc in services:
                    if svc.identifying_name not in entity.services:
                        entity.services = entity.services.union([svc.identifying_name])
                    if entity.identifying_name not in svc.entities:
                        svc.entities = svc.entities.union([entity.identifying_name])

            entity_relationships = []  # type: List[ImportedEntityRelationship]
            if ENTITY_RELATIONSHIP in self.import_spec:
                entity_relationships = entity_relationship_parser(row)

            entity_relationship = None
            if entity_relationships:
                entity_relationship = entity_relationships[-1]

            # Special case not currently exposed in the UI
            if entity and not services:
                entity.services = entity.services.union(self.import_spec.selectedServices)

            # Only skip if the *main* service is invalid, so... singular.
            if skip_row(entity, service, entity_relationship):
                continue

            # Services are currently in dependency order, and their relationships are
            # properly encoded already.

            rows.append(DataRow(entity, services, entity_relationships, template))
            if len(rows) >= batch_size:
                handler(self._process_batch(rows), transaction_id)
                if hasattr(source, 'log'):
                    source.log()
                rows = []

        if len(rows):
            handler(self._process_batch(rows), transaction_id)
            if hasattr(source, 'log'):
                source.log()
            rows = []

        end_time = time.time()
        logger.info('csv data load initializing mark start=%s end=%s duration=%s', start_time, end_time, (end_time - start_time))
        return (handler, skip_row)

    def bulk_import(self, source, transaction_id):
        # type: (Iterator[Sequence[Text]], Text) -> Dict[Text, Any]
        """
        The routine to call when you actually want to save the import content to KVSTore

        @param source: An iterator of rows of text data to be imported, usually rows of CSV data.

        @param transaction_id: unique ID for current bulk import operation

        @returns: A report on the count of actions were performed
        """
        # type: (Iterator[Sequence[str]]) -> Dict[Text, Any]
        handler = DataPersistence(self.itoa_handle)
        (handler, skip_row) = self._bulk_import(source, handler, transaction_id)

        return {
            'services': handler.services_written,
            'entities': handler.entities_written,
            'services_skip_count': skip_row.services_skipped,
            'entities_skip_count': skip_row.entities_skipped,
            'entity_relationships': handler.entity_relationships_written,
            'entity_relationships_skip_count': skip_row.entity_relationships_skipped
        }

    def get_service_preview(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, List[Dict[Text, Any]]]
        """
        The routine to call when you want to see what services will be imported for a given dataset.

        @param source: An iterator of rows of text data to be imported, usually rows of CSV data.

        @returns: A report on the count of actions were performed
        """
        # type: (Iterator[Sequence[str]]) -> Dict[Text, Any]
        handler = ServicePreviewBuilder()
        (handler, skip_row) = self._bulk_import(source, handler, transaction_id)
        return {
            'services': handler.services
        }

    def get_entity_preview(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> List[Dict[Text, Text]]
        """
        Here we have a very specific case, we take entities that are "new" - as of yet unassigned to an entity id

        @param source - complete entity definitions.  We will attempt to preview the merge using match entity
        @return: entities after merging
        """
        handler = EntityPreviewBuilder()
        (handler, skip_row) = self._bulk_import(source, handler, transaction_id)

        def get_existing_entities(titles):
            # type: (List[Text]) -> Sequence[dict]
            if not titles:
                return []
            filter_data = {'$or': [{'identifying_name': title.lower()} for title in titles]}
            return self.itoa_handle.entity.get_bulk(self.itoa_handle.owner, filter_data=filter_data)

        entity_titles = [e['identifying_name'] for e in handler.entities]
        existing = dict([(e['identifying_name'], e) for e in get_existing_entities(entity_titles)])
        return [(existing.get(e['identifying_name'], None), e) for e in handler.entities]

    def get_template_preview(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, List[Dict[Text, Any]]]
        """
        Generates a preview of which services will be linked to which service templates.

        @param source: An iterator of rows of text data to be imported, usually rows of CSV data.
        @type: iterator

        @param transaction_id: The ID of the CSV import transaction
        @type: string
        """
        handler = TemplatePreviewBuilder()
        (handler, skip_row) = self._bulk_import(source, handler, transaction_id)

        return {'templates': handler.templates}
