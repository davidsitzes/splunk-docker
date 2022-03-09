# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from collections import namedtuple, Counter
from itoa_bulk_import_common import (CSVLoaderError, CSVLoaderBadReq, TypeSpec, stripall, filtblnk,
                                     SERVICE, ENTITY, TEMPLATE, SERVICE_IMPORT, ENTITY_IMPORT,
                                     SUPPORTED_UPDATE_TYPES, DEFAULT_UPDATE_TYPE,
                                     logger, ENTITY_RELATIONSHIP)

from itsi.itsi_const import ITOAObjConst
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
import ITOA.itoa_common as utils
from ConfigParser import SafeConfigParser
import json
import copy

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


SpecFields = namedtuple('SpecFields', ['entity_fields', 'service_fields', 'entity_relationship_fields'])
SourceTarget = namedtuple('SourceTarget', ['source', 'target'])
RESERVED_WORDS = ITOAObjConst.ENTITY_INTERNAL_KEYWORDS

ENTITY_REQUIRED_FIELDS = [TypeSpec(*i) for i in
                          [('titleField', basestring),
                           ('identifierFields', list),
                           ('informationalFields', list),
                           ('descriptionColumns', list),
                           ('service_column', list)]]

SERVICE_REQUIRED_FIELDS = [TypeSpec(*i) for i in
                           [('titleField', basestring),
                            ('criticality', basestring),
                            ('serviceClone', basestring),
                            ('serviceEnabled', basestring),
                            ('serviceSecurityGroup', basestring),
                            ('descriptionColumns', list)]]

ENTITY_RELATIONSHIP_REQUIRED_FIELDS = [TypeSpec(*i) for i in
                                       [('subjectField', basestring),
                                        ('entity_relationship_spec', dict)]]


def flatten_fieldnames(spec, required_fields):
    results = []
    for f in required_fields:
        if (f.type == list):
            results.extend(spec[f.name])
        else:
            results.append(spec[f.name])
    return results

"""
The current expected layout of the Bulk Import specification looks like this.  Note
that the mulitiple normalization passes in the BulkImportSpecification constructor
do change some of these field names, normalizing them to the current in-KVStore
representation.

{
    "service" : {
        "titleField" : "",           # REQUIRED if service specification present
        "description_column" : []    # list of column names for descriptions
    },
    "entity" : {
        "titleField" : "",           # REQUIRED if entity specification present
        "description_column: [],     # list of column names for descriptions
        "identifyingFields" : [],    # list of column names for aliases
        "informationalFields" : [],  # list of column names for informational fields
        "service_column" : []        # services that this entity is applicable to
    },
    "entity_relationship" : {
        "subjectField" : "",            # REQUIRED if entity relationship specification present
        "entity_relationship_spec: {},  # REQUIRED. dict of relationships and fields list, e.g., {"hosts": ["vm"]}
    },
    "selectedServices" : [],         # services that imported entity/services belong to (must already be present in KVStore)
    "service_rel" : [],              # service relationship; [col1, col2, col3] implies col3 depends on col2,
                                     #     and col2 depends on col1, establishing a heirarchy, from left- > right
    "service_dependents": []         # alternative service relationships; all of these are immediate children ['depends_upon']
                                     # of the service specified above.  No positional hierarchy is implied.
    "updateType" : "",               # ADD, UPSERT or APPEND
    "source" : "",                   # source name for this import
}

"""


class BulkImportSpecification(object):
    """
    Bulk Import has two features: a data *source* (an iterator that returns a single row as
    a tuple), and a specification that describes how that row is to be interpreted as
    an entity, service, or both.  BulkImportSpecification represents the latter.

    After initialization, Bulk Import Specification is a read-only object, enforced
    by @property.

    FIELDS:
        service - the service definition object, if present
        entity  - the entity definition object, if present
        selectedServices - services specified by user to be associated with entities
        service_rel - list of service dependencies
        updateType  - IGNORE, REPLACE, UPDATE
        source      - name of the data source. If not provided, defaults to "unknown"
        fields_to_import - A named tuple of: (entity_fields.[fieldname, ...], service_fields.[fieldnames, ...])
        import_type - A binary flag for SERVICE | ENTITY
    """

    def __init__(self, specification_record, uploaded_by='nobody'):
        # type: (Dict[Text, Any], str) -> None
        """
        @param specification_record: the import spec as derived from an external source
        @type dict

        @return self
        @type: object
        """
        self._validate_inbound_specification(specification_record)
        specification = self._normalize(specification_record)
        self._validate_normalized_specification(specification)
        self._specification = self._maybe_duplicate_entity_title(specification)

        # The values of this object
        self._fields_to_import = self._get_fields_to_import()
        self._import_type = (((SERVICE in specification and SERVICE_IMPORT) or 0) |
                             ((ENTITY in specification and ENTITY_IMPORT) or 0))
        self._source = specification.get('source', 'unknown')
        self._uploaded_by = uploaded_by
        if not self._import_type:
            message = _('Invalid specification - No object specification found in input. Received - {0}').format(str(specification_record))
            raise CSVLoaderBadReq(message)

    @property
    def fields_to_import(self):
        # type: () -> SpecFields
        return self._fields_to_import

    @property
    def import_type(self):
        # type: () -> int
        return self._import_type

    @property
    def update_type(self):
        # type: () -> Text
        return self._specification.get('updateType').lower()

    @property
    def source(self):
        # type: () -> Text
        return self._source

    def __contains__(self, t):
        # type: (Text) -> bool
        return (t in self._specification) or (t in ['import_type', 'source', 'fields_to_import'])

    def get(self, t, default=None):
        # type: (Text, Any) -> Any
        return self._specification.get(t, default)

    def _get_fields_to_import(self):
        # type: () -> SpecFields
        # During construction, get and memoize the list of fields that
        # a particular type (service or entity) cares about.
        def get_entity_fields(entity_specification):
            # type: (Dict[Text, Any]) -> List[Text]
            return list(set([entity_specification['titleField']] +
                            entity_specification['informationalFields'] +
                            entity_specification['identifierFields'] +
                            entity_specification['service_column'] +
                            entity_specification['descriptionColumns']))

        def get_service_fields(service_specification):
            # type: (Dict[Text, Any]) -> List[Text]
            return list(set([service_specification['titleField']] +
                            service_specification['descriptionColumns'] +
                            [service_specification['serviceTemplate']] +
                            self._specification.get('service_rel') +
                            self._specification.get('service_dependents')))

        def get_entity_relationship_fields(entity_relationship_specification):
            # Flatten entity_relationship_spec values that is a dict[list] to a list
            spec_value_lists = entity_relationship_specification.get('entity_relationship_spec', {}).values()
            spec_values = [val for sublist in spec_value_lists for val in sublist]

            return list(set([entity_relationship_specification['subjectField']] + spec_values))

        specfields = SpecFields(
            (ENTITY in self._specification and get_entity_fields(self._specification[ENTITY]) or []),
            (SERVICE in self._specification and get_service_fields(self._specification[SERVICE]) or []),
            (ENTITY_RELATIONSHIP in self._specification and
             get_entity_relationship_fields(self._specification[ENTITY_RELATIONSHIP]) or [])
        )
        logger.info('Fields to Import: {}'.format(specfields))
        return specfields

    def __getattr__(self, name):
        # type: (Text) -> Any
        if name not in self._specification:
            raise KeyError(name)
        return self._specification[name]

    def __str__(self):
        # type: () -> str
        return str(self._specification)

    @staticmethod
    def _validate_inbound_specification(specification):
        # type: (Dict[Text, Any]) -> None
        # Enforces the contract for what the inbound specification record look like.
        # It must be a record; it must have at least a service or an entity, those
        # objects if present must have a few required fields.
        #
        # Raises an exception on failure.
        service_required_fields = ['titleField']
        entity_required_fields = ['titleField', 'identifyingFields', 'informationalFields']
        entity_relationship_required_fields = ['subjectField', 'entity_relationship_spec']

        # Enforce type requirement.
        if (not isinstance(specification, dict)) or len(specification) == 0:
            message = _('Invalid/empty specification as input. Received - {0}').format(str(specification))
            raise CSVLoaderBadReq(message)

        # Ensure a working update type
        update_type = specification.get('updateType', DEFAULT_UPDATE_TYPE)
        if not ((isinstance(update_type, str) or isinstance(update_type, unicode)) and
                update_type.strip().lower() in SUPPORTED_UPDATE_TYPES):
            message = _('Expecting valid update type. Received "{}"').format(update_type)
            raise CSVLoaderBadReq(message)

        # Ensure there is AT LEAST one of these
        if not (SERVICE in specification or ENTITY in specification):
            msg = _('missing both - "{}" & "{}" from your request. At least one is expected')
            raise CSVLoaderBadReq(msg.format(SERVICE, ENTITY))

        # AT LEAST one of ENTITY or SERVICE is present. Ensure they are consistent and correct.
        if ENTITY in specification:
            missing_keys = [key for key in entity_required_fields if key not in specification[ENTITY]]
            if missing_keys:
                message = _('missing key(s) "{}" from required entity fields - {}')
                raise CSVLoaderBadReq(message.format(missing_keys, entity_required_fields))
            if not specification[ENTITY]['titleField'].strip():
                message = _('Empty title field for entity in import specification')
                raise CSVLoaderBadReq(message)

        if ENTITY_RELATIONSHIP in specification:
            missing_keys = [key for key in entity_relationship_required_fields
                            if key not in specification[ENTITY_RELATIONSHIP]]
            if missing_keys:
                message = _('missing key(s) "{}" from required entity relationship fields - {}')
                raise CSVLoaderBadReq(message.format(missing_keys, entity_relationship_required_fields))
            if not specification[ENTITY_RELATIONSHIP]['subjectField'].strip():
                message = _('Empty subject field for entity relationship in import specification')
                raise CSVLoaderBadReq(message)

        if SERVICE in specification:
            missing_keys = [key for key in service_required_fields if key not in specification[SERVICE]]
            if missing_keys:
                message = _('missing key(s) "{}" from required service fields - {}')
                raise CSVLoaderBadReq(message.format(missing_keys, service_required_fields))
            if not specification[SERVICE]['titleField'].strip():
                message = _('Empty title field for service in import specification')
                raise CSVLoaderBadReq(message)
        return

    @staticmethod
    def _normalize(specification_record):
        # type: (Dict[Text, Any]) -> Dict[Text, Any]
        # The names of things have changed over time.  We need to ensure the names we put into
        # KVStore are the final names chosen, regardless of the age of the upload source.
        #
        # @param specification: the specification record as recevied from an external source
        # @type: dict
        #
        # @return: the specification, but normalized with current names and structure
        # @type: dict

        # The specification as passed in should be returned to the user unmodified.
        specification = copy.deepcopy(specification_record)

        baseType = [TypeSpec(*i) for i in [('selectedServices', list), ('service_rel', list), ('service_dependents', list)]]
        # This only works because lists can instantiate. Basestrings can't, so be wary if
        # you change this.
        for bt in baseType:
            if bt.name not in specification:
                specification[bt.name] = (bt.type)()
            if not isinstance(specification[bt.name], bt.type):
                message = _('Specification expects {} to be a {}, but it was not.')
                raise CSVLoaderError(message.format(bt.name, str(bt.type)))
            specification[bt.name] = filtblnk(stripall(specification[bt.name]))

        # The updateType can survive initial validation by not being present.  If that's
        # the case, make sure it *is* set here so it can be (a) used now, and (b) written
        # to conf.
        specification['updateType'] = specification.get('updateType', DEFAULT_UPDATE_TYPE).strip().lower()

        def normalize_specification(spec_subtype, replace_fields={}, replace_fields_types={}, add_fields={}):
            # type: (Dict[Text, Any], Dict[Text, Any], Dict[Text, Any], Dict[Text, Any]) -> Tuple[bool, str]
            return ITOAInterfaceUtils.replace_append_info(
                spec_subtype,
                replace_fields=replace_fields,
                replace_fields_types=replace_fields_types,
                add_fields=add_fields)

        # Normalize the SERVICE section, if present
        if SERVICE in specification:
            service_spec = specification[SERVICE]
            success, msg = normalize_specification(
                service_spec,
                {'description_column': 'descriptionColumns'},
                {'descriptionColumns': list},
                {'criticality': str, 'serviceClone': str, 'serviceEnabled': str, 'serviceSecurityGroup': str, 'serviceTemplate': str, 'backfillEnabled': str})
            if not success:
                message = _('Unable to create service info for invalid import_info- {0}.')
                raise CSVLoaderError(message.format(json.dumps(specification)))

            for fieldname in ['descriptionColumns']:
                service_spec[fieldname] = filtblnk(stripall(specification[SERVICE][fieldname]))

            service_spec['serviceEnabled'] = service_spec.get('serviceEnabled', '') or '0'
            service_spec['backfillEnabled'] = service_spec.get('backfillEnabled', '') or '0'
            service_spec['serviceSecurityGroup'] = service_spec.get('serviceSecurityGroup', '') or \
                                                   GLOBAL_SECURITY_GROUP_CONFIG.get('key')
            service_rel = specification.get('service_rel', [])
            if service_spec['titleField'] in service_rel:
                specification['service_rel'] = [s for s in service_rel if s != service_spec['titleField']]

        # Normalize the ENTITY section, if present
        if ENTITY in specification:
            success, msg = normalize_specification(
                specification[ENTITY],
                {'identifyingFields': 'identifierFields',
                 'description_column': 'descriptionColumns'},
                {'identifierFields': list, 'descriptionColumns': list},
                {'fieldMapping': dict, 'service_column': list})

            if not success:
                message = _('Unable to create entity info for invalid import_info- {0}.')
                raise CSVLoaderError(msg.format(json.dumps(specification)))

            for fieldname in ['identifierFields', 'descriptionColumns', 'service_column']:
                specification[ENTITY][fieldname] = filtblnk(stripall(specification[ENTITY][fieldname]))

        return specification

    @staticmethod
    def _validate_normalized_specification(specification):
        # type: (Dict[Text, Any]) -> None
        # After the data has been normalized, it still must be verified to ensure that the post-processing
        # mapping of field names is valid.
        #
        # @param specification: the specification AFTER it's been modified
        # @type: dict
        #
        # @return: None

        entity_relationship_required_fields = [TypeSpec(*i) for i in
                                               [('subjectField', basestring),
                                                ('entity_relationship_spec', dict)]]

        def validate_subtype(spec_subtype, fields, name):
            # type: (Dict[Text, Any], List[TypeSpec], Text) -> None
            for field in fields:
                if not isinstance(spec_subtype.get(field.name), field.type):
                    message = _('Expecting "{}" in {} to be of type "{}". Received "{}" instead.')
                    raise CSVLoaderError(message.format(field.name, name, field.type, type(spec_subtype.get(field.name))))

        if SERVICE in specification:
            validate_subtype(specification[SERVICE], SERVICE_REQUIRED_FIELDS, 'service')

        if ENTITY_RELATIONSHIP in specification:
            validate_subtype(specification[ENTITY_RELATIONSHIP],
                             ENTITY_RELATIONSHIP_REQUIRED_FIELDS,
                             'entity_relationship')

        if ENTITY_RELATIONSHIP in specification:
            validate_subtype(specification[ENTITY_RELATIONSHIP],
                             entity_relationship_required_fields,
                             'entity_relationship')

        if ENTITY in specification:
            entity_info = specification[ENTITY]
            validate_subtype(entity_info, ENTITY_REQUIRED_FIELDS, 'entity')

            overlap = set(RESERVED_WORDS).intersection(set([s.lower() for s in entity_info['fieldMapping'].values()]))
            if overlap:
                raise CSVLoaderBadReq('Invalid field mapping "{}"; reserved word.'.format(','.join(list(overlap))))

            # Check the metadata fields for conflicts.
            metafields = set([s.lower() for s in ([] +
                                                  entity_info['identifierFields'] +
                                                  entity_info['informationalFields'] +
                                                  [entity_info['titleField']])])

            overlap = set(RESERVED_WORDS).intersection(metafields) - set([s.lower() for s in entity_info['fieldMapping'].keys()])
            if overlap:
                message = _('A reserved word is being used as column title for '
                           'either "Entity Title", "Entity Alias" or "Entity Informational" column. '
                           'Rename the following column titles: {0}.'
                           '\n Alternatively, field map them to non-reserved words.'
                           '\n Reserved words are: {1}').format(
                               ', '.join(overlap), RESERVED_WORDS)
                logger.error(message + '\nAffected blob: {0}'.format(specification))
                raise CSVLoaderBadReq(message)

        # Ensure there is no overlap at all between all the fieldnames as we're expecting
        # them from inbound specification.  From the UI, this should never happen, but
        # it's good to make sure.

        fieldnames = (specification['selectedServices'] +
                      specification['service_rel'] +
                      specification['service_dependents'])
        if ENTITY in specification:
            fieldnames.extend(flatten_fieldnames(specification[ENTITY], ENTITY_REQUIRED_FIELDS))
            fieldnames = [i for i in fieldnames if i != specification[ENTITY]['titleField']]

        if SERVICE in specification:
            fieldnames.extend(flatten_fieldnames(specification[SERVICE], SERVICE_REQUIRED_FIELDS))

        fieldnames = filtblnk(stripall(fieldnames))
        if len(fieldnames) != len(set(fieldnames)):
            message = _('Duplicate fieldname role assignments in Bulk Import Specification: {}')
            raise CSVLoaderBadReq(message.format(', '.join([f for (f, c) in Counter(fieldnames).items() if c > 1])))

        if ENTITY in specification:
            fieldnames += [specification[ENTITY]['titleField'].strip()]
        invalid_fieldnames = [i for i in fieldnames if not utils.is_valid_name(i)]
        if invalid_fieldnames:
            message = _('Invalid fieldnames in Bulk Import Specification. Fieldnames cannot contain quotes or equals: {}')
            raise CSVLoaderBadReq(message.format(', '.join(invalid_fieldnames)))

    @staticmethod
    def _maybe_duplicate_entity_title(specification):
        if ENTITY not in specification:
            return specification

        fieldnames = filtblnk(stripall(
            specification['selectedServices'] +
            specification['service_rel'] +
            specification['service_dependents'] +
            flatten_fieldnames(specification[ENTITY], ENTITY_REQUIRED_FIELDS)))

        fieldnames = [i for i in fieldnames if i == specification[ENTITY]['titleField']]
        if len(fieldnames) > 2:
            message = _('Invalid specification: The title field is specified multiple times.')
            raise CSVLoaderBadReq(message)

        if len(fieldnames) == 2:
            invalid_fieldnames = [i for i in ENTITY_REQUIRED_FIELDS if i.name not in
                                  ['identifierFields', 'informationalFields', 'titleField']]
            fieldnames = filtblnk(stripall(
                specification['selectedServices'] +
                specification['service_rel'] +
                specification['service_dependents'] +
                flatten_fieldnames(specification[ENTITY], invalid_fieldnames)))
            fieldnames = [i for i in fieldnames if i == specification[ENTITY]['titleField']]
            if fieldnames:
                message = _('Invalid specification: The title field is specified as a duplicate of {}')
                raise CSVLoaderBadReq(message.format(', '.join(fieldnames)))

        entity = specification[ENTITY]
        titleField = entity['titleField']

        if titleField in (entity['identifierFields'] +
                          entity['informationalFields']):
            return specification

        specification[ENTITY]['identifierFields'].append(titleField)
        return specification

    def toConf(self, extras={}):
        # type (Dict[Text, Text]) -> SafeConfigParser
        """
        Convert the configuration here into something that can be understood by .conf parsers.
        @param extras: other fields to add that aren't normally part of a bulk import specification.  Used mostly for transaction IDs.
        """
        config = SafeConfigParser()
        config.add_section('import')

        for k, v in extras.items():
            config.set('import', k, v)

        if ENTITY in self:
            entity = self.entity
            config.set('import', 'entity_title_field', entity['titleField'])
            for i in [SourceTarget('identifierFields', 'entity_identifier_fields'),
                      SourceTarget('informationalFields', 'entity_informational_fields'),
                      SourceTarget('descriptionColumns', 'entity_description_column')]:
                config.set('import', i.target, ','.join(entity[i.source]))
            config.set('import', 'entity_field_mapping', ','.join(['{}={}'.format(k, v) for k, v in entity['fieldMapping'].items()]))

        if SERVICE in self:
            service = self.service
            config.set('import', 'service_title_field', service['titleField'])
            config.set('import', 'service_description_column', ','.join(service['descriptionColumns']))
            config.set('import', 'service_rel', ','.join(self.service_rel))
            config.set('import', 'service_dependents', ','.join(self.service_dependents))
            config.set('import', 'service_enabled', service.get('serviceEnabled', ''))
            config.set('import', 'service_clone_id', service.get('serviceClone', ''))
            config.set('import', 'service_security_group', service.get('serviceSecurityGroup',
                                                                       GLOBAL_SECURITY_GROUP_CONFIG.get('key')))
            config.set('import', 'service_template_field', service.get('serviceTemplate', ''))

        if ENTITY_RELATIONSHIP in self:
            entity_relationship = self.entity_relationship
            config.set('import', 'entity_relationship_spec', json.dumps(entity_relationship['entity_relationship_spec']))

        if TEMPLATE in self:
            try:
                template = json.dumps(self.template)
            except TypeError as err:
                template = ''

                logger.warning(
                    'Failed to save service template specification to config: {0} with error: {1}'.format(self.template, err)
                )

            config.set('import', 'template', template)

        config.set('import', 'update_type', self.updateType)
        if len(self.selectedServices) != 0:
            config.set('import', 'entity_service_columns', ','.join(self.selectedServices))
        config.set('import', 'uploaded_by', self._uploaded_by)

        return config
