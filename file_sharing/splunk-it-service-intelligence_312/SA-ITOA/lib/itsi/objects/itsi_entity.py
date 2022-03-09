# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import re
import time
import itertools

import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_const import ITOAObjConst
from ITOA.itoa_exceptions import ItoaValidationError

logger = utils.get_itoa_logger('itsi.object.entity')

class ItsiEntity(ItoaObject):
    """
    Implements ITSI entity
    """

    log_prefix = '[ITSI Entity] '
    COLLECTION_NAME = 'itsi_services'
    ITOA_OBJECT_TYPE = 'entity'
    _entity_internal_keywords = ITOAObjConst.ENTITY_INTERNAL_KEYWORDS
    regex_invalid_chars = re.compile('^\$|[=.,"\']+')

    def __init__(self, session_key, current_user_name):
        super(ItsiEntity, self).__init__(session_key,
                                         current_user_name,
                                         'entity',
                                         collection_name=self.COLLECTION_NAME,
                                         is_securable_object=True,
                                         title_validation_required=False)

    def do_object_validation(self, owner, objects, validate_name=True, dupname_tag=None, transaction_id=None):
        ItoaObject.do_object_validation(self, owner, objects, validate_name, dupname_tag, transaction_id)

        # we do not want to validate uniqueness for entities, but still want valid titles
        # the title_validation_required flag is too broad so copy this logic here
        # It would be nice if this could be cleaned up at some point
        for json_data in objects:
            if not utils.is_valid_name(json_data.get('title', None)):
                self.raise_error_bad_validation(logger, 'Invalid title specified for the object_type: %s. \
                Must be non-empty and cannot contain = " or \'' % self.object_type)

    def _validate_identifier_and_info_field_names(self, field_name):
        """
        Validate alias and info fields
        Guard against usage of problematic field names:
            Disallow field names starting with $ since KV store lookups (MongoDB) doesnt support field names
            starting with a $
            Disallow fields containing . since KV store lookups (MongoDB) doesnt support field names
            with dots
            Disallow " and ' which are used for escaping field names - preventing these allows searches to escape
            easily
            Disallow internal keywords to be used as alias and informational fields. A list of the internal keywords
            are listed in entity_internal_keywords list
            UI controls like MultiInputControl use comma as separator to specify multiple fields. So disallow them.
            Disallow = character since SPL does not seem to support fully. Eg. index=_internal | eval 'field='="value"
            fails on syntax

        @type field_name: basestring
        @param field_name: alias or info field name
        @return: None
        """
        if not utils.is_valid_str(field_name):
            self.raise_error_bad_validation(
                logger,
                _('Invalid field name specified, fields cannot be empty.')
            )
        if re.search(self.regex_invalid_chars, field_name):
            self.raise_error_bad_validation(
                logger,
                _('Invalid field names specified, Eg. ') + field_name +
                _('. Fields cannot contain special characters not supported by SPL.')
            )
        if field_name in self._entity_internal_keywords:
            self.raise_error_bad_validation(
                logger,
                _('Invalid field names specified, ') + field_name + _('. Fields can not be an internal keywords: ')
                + str(self._entity_internal_keywords)
            )

    def _populate_identifier_and_info_fields_blob(self, entity):
        """
        Always populate identifier.values and informational.values again, by going through the fields
        in identifier.fields and informational.fields respectively and finding their values at top-level
        in entity object.
        @type entity: dict
        @param entity: entity object
        @return: None
        """
        field_types = ['identifier', 'informational']
        for field_type in field_types:
            field_blob = entity.get(field_type, {})
            if not isinstance(field_blob, dict):
                logger.warning('Incorrect format of %s field in entity object. Resetting it to empty dictionary. '
                               'entity_title="%s"' % (field_type, entity.get('title')))
                field_blob = {}
            if 'fields' not in field_blob or not isinstance(field_blob['fields'], list):
                field_blob['fields'] = []
            field_blob['values'] = []

            # Alias fields and its values are present at two places in entity object: at top level as alias field and
            # value, and in identifier.fields and identifier.values lists. To maintain consistency across entity
            # object, always clean up identifier.values and, re-populate it by going through identifier.fields and
            # getting values for those fields from top-level alias fields in entity object. If alias field values are
            # not present in identifier.values list, lookup of entity by alias field value would return null.
            # Perform the same handling for informational fields as well, as they follow the same structure as
            # identifier field. For more info, check ITSI-356.
            for field_name in field_blob.get('fields', []):
                self._validate_identifier_and_info_field_names(field_name)
                if field_name not in entity:
                    self.raise_error_bad_validation(
                        logger,
                        _('%s field specified in %s.fields attribute, not found in entity object. '
                          'entity_title="%s", %s_field="%s"')
                        % (field_type, field_type, entity.get('title'), field_type, field_name)
                    )
                else:
                    if not isinstance(entity.get(field_name), list):
                        self.raise_error_bad_validation(
                            logger,
                            _('Incorrect format of %s field, in entity object. Expected list, found %s, '
                              'entity_title="%s", %s_field="%s"') %
                            (field_type, type(entity.get(field_name)).__name__, entity.get('title'),
                             field_type, field_name)
                        )
                    # In order to enable KV Store case insensitive matching we need to
                    # convert identifier/info values to lower case
                    for field_value in entity.get(field_name):
                        if field_value.lower() not in field_blob.get('values'):
                            field_blob['values'].append(field_value.lower())
            entity[field_type] = field_blob

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        for json_data in objects:
            # Assume json_data is valid

            self._populate_identifier_and_info_fields_blob(json_data)

            # validate there are no common fields between identifier and info fields
            identifier_fields_set = set(json_data.get('identifier', {}).get('fields', []))
            info_fields_set = set(json_data.get('informational', {}).get('fields', []))
            common_fields_set = identifier_fields_set.intersection(info_fields_set)
            if common_fields_set:
                self.raise_error_bad_validation(
                    logger,
                    _('Invalid informational field(s) specified for entity . Some of the info fields conflict with '
                      'identifier fields. entity_title="%s". conflicting_info_fields="%s"') %
                    (json_data.get('title'), list(common_fields_set))
                )

    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        persisted_entities = []
        if ((method == CRUDMethodTypes.METHOD_UPDATE) or
            (method == CRUDMethodTypes.METHOD_UPSERT) or
            (method == CRUDMethodTypes.METHOD_DELETE)):

            # if delete, then we know objects are real persisted objects, no need to fetch again
            if method == CRUDMethodTypes.METHOD_DELETE:
                persisted_entities = objects
            else:
                persisted_entities = self.get_persisted_objects_by_id(
                    owner,
                    object_ids = [entity.get('_key') for entity in objects],
                    req_source = req_source
                    )

        entities_needing_service_refresh = set()
        is_services_associated_by_rules_need_refresh = False
        force_service_refresh = set()

        for entity in objects:
            # Assume entity is a valid json
            if method == CRUDMethodTypes.METHOD_CREATE:
                if not utils.is_valid_str(entity.get('_key')):
                    # Generate a key here on create to facilitate setting up refresh objects
                    entity['_key'] = ITOAInterfaceUtils.generate_backend_key()
            if method == CRUDMethodTypes.METHOD_DELETE:
                old_ent = self.get(owner, entity['_key'], req_source=req_source, transaction_id=transaction_id)
                services = old_ent.get('services')
                if services is not None and len(services) > 0:
                    for s in services:
                        if not isinstance(s, dict):
                            logger.error("Invalid services structure received - skipping entity=%s", old_ent)
                            continue
                        service_key = s.get('_key')
                        if service_key:
                            force_service_refresh.add(service_key)
            # First identify if relevant fields have changed
            # If entity is created or deleted, all services in the system may need to be updated
            # If identifiers and informational fields have changed, then all services in the system
            # may need to be updated
            # Services need to be updated since the rules in the services may need to include/exclude
            # the entity with new settings which affects KPI searches
            is_identifiers_changed = False
            is_entity_created_or_deleted = False
            if ((method == CRUDMethodTypes.METHOD_CREATE) or
                (method == CRUDMethodTypes.METHOD_DELETE)):
                is_entity_created_or_deleted = True
            elif ((method == CRUDMethodTypes.METHOD_UPDATE) or
                (method == CRUDMethodTypes.METHOD_UPSERT)):
                entity_identifier = entity.get('identifier', {})
                entity_informational = entity.get('informational', {})

                entity_found = False
                for persisted_entity in persisted_entities:
                    if entity['_key'] == persisted_entity['_key']:
                        entity_found = True

                        # First identify if identifiers and informational fields have changed
                        persisted_identifier = persisted_entity.get('identifier', {})
                        persisted_informational = persisted_entity.get('informational', {})
                        if (len(entity_identifier) != len(persisted_identifier)):
                            is_identifiers_changed = True
                        else:
                            if not (utils.is_equal_lists(
                                entity_identifier.get('values', []),
                                persisted_identifier.get('values', [])
                                )):
                                is_identifiers_changed = True
                            if not (utils.is_equal_lists(
                                entity_identifier.get('fields', []),
                                persisted_identifier.get('fields', [])
                                )):
                                is_identifiers_changed = True

                            if not (utils.is_equal_lists(
                                entity_informational.get('values', []),
                                persisted_informational.get('values', [])
                                )):
                                is_identifiers_changed = True
                            if not (utils.is_equal_lists(
                                entity_informational.get('fields', []),
                                persisted_informational.get('fields', [])
                                )):
                                is_identifiers_changed = True

                        break
                is_entity_created_or_deleted = (
                    (method == CRUDMethodTypes.METHOD_UPSERT) and
                    (not entity_found)
                    )
            else:
                raise AttributeError(_('Invalid method name {0} received').format(method))

            if is_entity_created_or_deleted:
                # If entity is created or deleted, related services need updates
                is_identifiers_changed = True

            # Based on which relevant fields have changed, identify dependencies to update
            if is_identifiers_changed:
                # Add a refresh request to update the services for entity membership
                if '_key' in entity:
                    entities_needing_service_refresh.add(entity['_key'])
                is_services_associated_by_rules_need_refresh = is_identifiers_changed

        required_refresh_jobs = []
        if len(entities_needing_service_refresh) > 0:
            required_refresh_jobs.extend([
                self.get_refresh_job_meta_data(
                    'entity_services_update',
                    list(entities_needing_service_refresh),
                    self.object_type,
                    change_detail = {
                        "is_services_associated_by_rules_need_refresh": is_services_associated_by_rules_need_refresh,
                        "deleted_entity_services": list(force_service_refresh)
                    },
                    transaction_id=transaction_id)
                ])
        return len(required_refresh_jobs) > 0, required_refresh_jobs


#  ___     _   _ _          ___      _ _     _____               _
# | __|_ _| |_(_) |_ _  _  | _ )_  _| | |__ |_   _|_ _ __ _ __ _(_)_ _  __ _
# | _|| ' \  _| |  _| || | | _ \ || | | / /   | |/ _` / _` / _` | | ' \/ _` |
# |___|_||_\__|_|\__|\_, | |___/\_,_|_|_\_\   |_|\__,_\__, \__, |_|_||_\__, |
#                    |__/                             |___/|___/       |___/

TAGTYPES = ['informational', 'identifier']


def _update_entities(entities, new_common_tagset, logger, tagtype='informational'):
    """
    Analyzes the requested changes against the requested entities, and
    either returns updated entities or throws an exception

    @param entities: A list of itsi_entity objects
    @param new_common_tagset: An object consisting of requeted updates
        - fields: A list of unique fieldnames (type: string) to be added or changed
        - values: A list of unique values (type: string) found in the update
        - attributes: An object of { field: [values] }
    @param logger: A splunk logger instance (opaque)
    @param tagtype: The tagset to change (type: string, "informational" or "identifier")
    @return: A list of itsi_entity objects to be batch saved
    """
    # Using set() creates an iterable of all unique fieldnames.  If
    # the list of unique fieldnames is not the same length as the list
    # of submitted fieldnames, then there must have been a duplicate
    # fieldname.
    keys_to_update = set(new_common_tagset['fields'])
    if len(keys_to_update) != len(new_common_tagset['fields']):
        raise ItoaValidationError(_('Integrity failure: Duplicate field names.'), logger)

    if set(new_common_tagset['attributes'].keys()) != set(keys_to_update):
        raise ItoaValidationError(_("Data corruption: field names and attribute names do not match."), logger)

    if keys_to_update.intersection(ITOAObjConst.ENTITY_INTERNAL_KEYWORDS):
        raise ItoaValidationError(_('Integrity failure: Attempt to overwrite reserved word.'), logger)

    attribute_values = set(itertools.chain.from_iterable(new_common_tagset['attributes'].values()))
    if "" in attribute_values:
        raise ItoaValidationError(_("Data corruption: blank values are not permitted."), logger)

    if attribute_values != set(new_common_tagset['values']):
        raise ItoaValidationError(_('Integrity failure: Values collections are not congruent.'), logger)

    def checkValuesAreAlsoEqual(fieldname):
        """
        For entities in this scope, determine that they all share the same value.
        @param fieldname: the fieldname to compare across entities.
        """
        try:
            values = iter([set([s.lower() for s in entity[fieldname]]) for entity in entities])
            first = next(values)
            return all(first == rest for rest in values)
        except StopIteration:
            return True

    # The intersection of all fieldnames of a tagtype for all entities
    # is the set of common fieldnames.
    tag_fieldname_sets = [set(entity[tagtype]['fields']) for entity in entities]
    common_tag_nameset = set([fieldname for fieldname in tag_fieldname_sets[0].intersection(*tag_fieldname_sets)
                              if checkValuesAreAlsoEqual(fieldname)])

    # Generate a list of all fieldname sets in the INFORMATIONAL and
    # IDENTIFIER sets in all the entities requested.
    other_fieldnames = [set(entity[other_tagtype]['fields'])
                        for entity in entities
                        for other_tagtype in TAGTYPES]

    if other_fieldnames:
        # Union of all other_fieldname sets creates a unique set of
        # all fieldnames for existing entities.
        all_fieldnames = other_fieldnames[0].union(*other_fieldnames)
        # Difference with common_tag_nameset produces a set of all
        # fieldnames NOT in common for the existing entities.
        other_fieldnames = all_fieldnames.difference(common_tag_nameset)
        # A non-empty intersection with keys_to_update indicates a
        # fieldname in the list of fields the user cannot update:
        # either because it's an identifier, or it's not held in
        # common, for existing entities.
        other_fieldname_overlap = other_fieldnames.intersection(keys_to_update)
        if other_fieldname_overlap:
            warning = 'Integrity Failure: Attempt to overwrite restricted set key. Overlap: {}'
            raise ItoaValidationError(warning.format(other_fieldname_overlap), logger)

    fields_to_delete = common_tag_nameset - keys_to_update
    fields_to_add = keys_to_update - common_tag_nameset
    fields_to_change = common_tag_nameset - fields_to_delete

    for entity in entities:
        for field in fields_to_delete:
            entity.pop(field)
            pos = entity[tagtype]['fields'].index(field)
            del entity[tagtype]['fields'][pos]

        for field in fields_to_change:
            entity[field] = new_common_tagset['attributes'][field]

        for field in fields_to_add:
            entity[field] = new_common_tagset['attributes'][field]
            entity[tagtype]['fields'].append(field)

        for k in ['values', 'fields']:
            entity[tagtype][k] = list(set(new_common_tagset[k] + entity[tagtype][k]))

    return entities


def bulk_entity_update_tags(session_key, current_user, owner, data, logger):
    """
    Given a payload of entities and information fields, update the entities.

    @param session_key: The user's session key (opaque)
    @param current_user: The current user (opaque)
    @param owner: the owner of the object set (opaque)
    @param data: data sent by the client  An object of:
        - entities: A list of entities to be updated
        - update: A data object representing the update delta
    @param logger: Our splunk logging instance. (opaque)
    @return: List of IDs of the itsi_entity objects saved.
    """
    if ('entities' not in data) or ('update' not in data):
        warning = 'Data error. `entities` and `update` mandatory keys. Received: {}'
        logger.error(warning.format(data))
        raise ItoaValidationError(_("No data received"), logger)

    if len(data['entities']) == 0:
        warning = 'At least one entity must be supplied for editing. Received: {}'
        logger.error(warning.format(data))
        raise ItoaValidationError(_("No entities supplied for editing."), logger)

    sent_entities_lookup = dict([[entity['_key'], entity] for entity in data['entities']])
    filter_data = {"$or": [{'_key': key} for key in sent_entities_lookup.keys()]}

    entities_handle = ItsiEntity(session_key, current_user)
    matching_entities = entities_handle.get_bulk(owner, filter_data=filter_data)

    if len(matching_entities) != len(sent_entities_lookup.keys()):
        raise ItoaValidationError(_("Update race: One or more entities deleted during editing. Please reload the page."), logger)

    for entity in matching_entities:
        if hasattr(entity, 'mod_timestamp') and sent_entities_lookup[entity['_key']]['mod_timestamp'] != entity['mod_timestamp']:
            raise ItoaValidationError(_("Update race: One or more entities changed during editing. Please reload the page."), logger)

    updated_entities = _update_entities(matching_entities, data['update'], logger)
    entities_handle = ItsiEntity(session_key, current_user)
    return entities_handle.save_batch(owner, updated_entities, True,
                                      req_source='bulk_entity_update')

