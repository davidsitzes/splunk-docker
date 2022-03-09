# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from ITOA.itoa_exceptions import ItoaValidationError
from ITOA.controller_utils import ITOAError
from itsi_entity import ItsiEntity
from ITOA.setup_logging import InstrumentCall

logger = utils.get_itoa_logger('itsi.object.entity_relationship')


class ItsiEntityRelationship(ItoaObject):
    """
    Implements ITSI entity relationship
    """

    collection_name = 'itsi_entity_relationships'
    itoa_object_type = 'entity_relationship'
    triple_fields = ['subject_identifier', 'object_identifier', 'predicate']

    def __init__(self, session_key, current_user_name):
        super(ItsiEntityRelationship, self).__init__(
            session_key,
            current_user_name,
            self.itoa_object_type,
            collection_name=self.collection_name,
            title_validation_required=False
        )

    def ensure_required_fields(self, objects):
        """
        Modify the objects passed in by reference to ensure they have the system generated required fields
        Update the specific fields for create, update and batch_save

        @type objects: list[dict]
        @param objects: list of dict
        @return: None
        """

        # By default, itoa object has mod_source and mod_timestamp fields.
        # But for entity relationship data type, we want to have them as a dict nested inside a list named as "mod",
        # for example:
        # {
        #   "mod": [{
        #       "mod_source": <string>,
        #       "mod_timestamp": <time>
        #   }]
        # }
        for json_data in objects:
            if 'mod' not in json_data:
                json_data['mod'] = []

            # If there is no match mod_source field, create a new dict with mod_source and mod_timestamp,
            # and append it to the list
            if not any('mod_source' in d and d['mod_source'] == self.mod_method for d in json_data['mod']):
                json_data['mod'].append({
                    'mod_source': self.mod_method,
                    'mod_timestamp': utils.get_current_timestamp_utc()
                })
            else:
                # Find match mod_source field, update its corresponding mod_timestamp to latest time.
                match = next((d for d in json_data['mod'] if d['mod_source'] == self.mod_method), None)
                if match is not None:
                    match['mod_timestamp'] = utils.get_current_timestamp_utc()

            json_data.pop('mod_source', None)

            json_data['_version'] = self._version

    def _get_triple_set_from_list(self, triple_list):
        """
        Given a list of triple dict, get a set of triple dict where
        duplicated triple is removed

        @type triple_list: list[dict]
        @param triple_list: list of triple dict

        @return: set[dict]

        For example, triple_list is:
        [{
        'subject_identifier': 'entityA - 69228',
        'object_identifier': 'entityB - 64864',
        'predicate': 'hosts'
        },
        {
        'subject_identifier': 'entityA - 69228',
        'object_identifier': 'entityB - 64864',
        'predicate': 'hosts'
        }]

        return:
        set([(
        ('subject_identifier', 'entityA - 69228'),
        ('object_identifier', 'entityB - 64864'),
        ('predicate', 'hosts')
        )])
        """
        return set(tuple(x.iteritems()) for x in triple_list)

    def _get_triple_list_from_set(self, triple_set):
        """
        Given a set of triple tuple, get a list of triple dict.

        @type triple_set: set[tuple]
        @param triple_set: set of triple tuple

        @return: list[dict]

        For example, triple_set is:
        set([(
        ('subject_identifier', 'entityA - 69228'),
        ('object_identifier', 'entityB - 64864'),
        ('predicate', 'hosts')
        )])

        return
        [{
        'subject_identifier': 'entityA - 69228',
        'object_identifier': 'entityB - 64864',
        'predicate': 'hosts'
        }]
        """
        return [dict(x) for x in triple_set]

    def _get_triples_in_data(self, objects):
        """
        Get triples in objects.

        @type objects: list
        @param objects: list of objects

        @return: tuple(list, list, list).
        The lists are triples with invalid name, triples with valid name, and triples with valid name and its key,
        """

        invalid_names_triple_list = []
        valid_names_triple_list = []
        valid_triple_plus_key_list = []

        for json_data in objects:
            if any(k not in json_data for k in self.triple_fields):
                self.raise_error_bad_validation(logger, 'The triple ({0}) is not completely specified in {1}'.format(
                    ', '.join(self.triple_fields), json_data
                ))

            triple = {k: json_data[k] for k in self.triple_fields}

            for field_name, field_value in triple.iteritems():
                if not utils.is_valid_name(field_value):
                    invalid_names_triple_list.append(dict(triple))
                    break

            # If all field values in a triple are valid
            valid_names_triple_list.append(dict(triple))

            # Need _key with a triple to build filter later
            triple_plus_key = dict(triple)
            triple_plus_key.update({'_key': json_data.get('_key', '')})
            valid_triple_plus_key_list.append(triple_plus_key)

        return invalid_names_triple_list, valid_names_triple_list, valid_triple_plus_key_list

    def _build_filter_from_triple_key_list(self, valid_triple_plus_key_list):
        """
        Build a list of dict as filter data, given a list of dict that contains triple and key.

        @type valid_triple_plus_key_list: list[dict]
        @param valid_triple_plus_key_list: a list of dict that contains triple and its key

        @return: list[dict], as filter data
        """
        triple_filter = []
        for triple_plus_key in valid_triple_plus_key_list:
            filter_dict = {k: triple_plus_key[k] for k in self.triple_fields}
            filter_dict.update({'_key': {'$ne': triple_plus_key.get('_key', '')}})
            triple_filter.append({'$and': [filter_dict]})

        return triple_filter

    def _validate_triples(self, owner, objects, transaction_id=None):
        """
        Check for valid and unique triples for the objects, stored in the triple_fields.

        @type owner: string
        @param owner: user who is performing this operation

        @type objects: list
        @param objects: list of objects

        @return: None, throws exceptions on validations failing
        """

        # Guard against valid and duplicates within passed in objects

        invalid_names_triple_list, valid_names_triple_list, valid_triple_plus_key_list = \
            self._get_triples_in_data(objects)

        if len(invalid_names_triple_list) > 0:
            invalid_names_triple_set = self._get_triple_set_from_list(invalid_names_triple_list)
            self.raise_error_bad_validation(
                logger,
                'Names cannot contain equal and quote characters. List of triples with invalid names: {0}'
                .format(self._get_triple_list_from_set(invalid_names_triple_set))
            )
        del invalid_names_triple_list

        if len(valid_names_triple_list) == 0:
            self.raise_error_bad_validation(
                logger,
                'There is no triple ({0}) with valid names'.format(', '.join(self.triple_fields))
            )

        valid_names_triple_set = self._get_triple_set_from_list(valid_names_triple_list)
        if len(valid_names_triple_set) < len(valid_names_triple_list):
            self.raise_error_bad_validation(
                logger,
                'Triple must be unique. There are duplicate triples in {0}'.format(valid_names_triple_list)
            )
        del valid_names_triple_list
        del valid_names_triple_set

        triple_filter = self._build_filter_from_triple_key_list(valid_triple_plus_key_list)

        # Now guard against duplicates against saved objects
        persisted_objects = self.get_bulk(
            owner,
            filter_data={'$or': triple_filter},
            fields=['_key'] + self.triple_fields,
            transaction_id=transaction_id
        )
        logger.debug(
            'filter_data=%s, persisted_objects=%s',
            {'$or': triple_filter},
            persisted_objects
        )

        duplicate_triple_list = []
        for persisted_object in persisted_objects:
            triple = {k: persisted_object[k] for k in self.triple_fields}
            duplicate_triple_list.append(dict(triple))

        duplicate_triple_set = self._get_triple_set_from_list(duplicate_triple_list)
        del duplicate_triple_list

        if len(duplicate_triple_set) > 0:
            self.raise_error_bad_validation(
                logger,
                'New triple specified already exist. Please use new unique triple. Duplicate triple found: {0}'.format(
                    self._get_triple_list_from_set(duplicate_triple_set)))
        del duplicate_triple_set

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT,
                            transaction_id=None):
        """
        Any additional setup that is required to be done
        before a write operation (create or update) is invoked on this object

        @type owner: basestring
        @param owner: request owner. "nobody" or some username.

        @type objects: list
        @param objects: list of objects being written

        @type req_source: basestring
        @param req_source: Source requesting this operation.

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.

        @return: None, throws exceptions on errors
        """

        self._validate_triples(owner, objects, transaction_id)

        # Can add more validation later


def _create_filtered_entity(entity):
    """
    Create a new entity based on given entity.

    @type entity: dict
    @param objects: dict of entity. An example:
    {
        title: "entityA",
        _key: "49156d54-ea95-4d41-990b-6f62d700afd3",
        identifier: {
            values: ['entityA', 'b']
        ....
    }

    @rtype: dict
    @return: A new dict that has _key, title, identifier.values
    """
    result_entity = {'_key': entity['_key'],
                     'title': entity['title'],
                     'identifier.values': entity.get('identifier', {}).get('values', [])}
    return result_entity


def _get_entity_from_identifier_key(owner, itsi_entity_obj, entity_key, entity_identifier, fields, logger):
    """
    Resolve entity given entity key or identifier

    @type owner: basestring
    @param owner: owner making the request

    @type itsi_entity_obj: object
    @param itsi_entity_obj: ItsiEntity object for query KV Store

    @type entity_key: basestring
    @param entity_key: key for an entity

    @type entity_identifier: basestring
    @param entity_identifier: identifier for an entity

    @type fields: list
    @param fields: list of fields to retrieve from KV Store

    @type logger: object
    @param logger: The logger to use

    @rtype: dict
    @return: A entity after resolution. Raise error if more than one record is returned.
    """

    # Build filter data
    entity_filters = []
    if entity_key:
        entity_filters.append({'_key': entity_key})
    if entity_identifier:
        entity_filters.append({'identifier.values': entity_identifier})
    filter_data = {'$or': entity_filters}

    # Query KV Store for matching entities.
    matching_entities = itsi_entity_obj.get_bulk(owner, filter_data=filter_data, fields=fields)

    logger.debug('Query entities using filter_data=%s, fields=%s. The result is: %s',
                 filter_data, fields, matching_entities)

    # Check matching entities returned from KV Store. Treat it as a error if more than one entity is returned
    common_error_message = _('Must provide entity identifier or key in order to resolve to a unique existing entity')
    if len(matching_entities) == 0:
        message = _('There is no matching entity. {}').format(common_error_message)
        logger.error(message)
        raise ItoaValidationError(message, logger)
    elif len(matching_entities) > 1:
        message = _('There are more than one matching entity. {}').format(common_error_message)
        logger.error(message)
        raise ItoaValidationError(message, logger)

    # Create new entity with filtered fields, for the matching entity.
    match_entity = _create_filtered_entity(matching_entities[0])
    logger.debug('Resolve entity_identifier=%s, entity_key=%s. The result is: %s',
                 entity_identifier, entity_key, match_entity)

    return match_entity


def _prepare_nodes_edges_result(results, edges_set, entity_key_index):
    """
    Prepare nodes and edges in right format from BFS result.

    @type results: list[dict, [list[dict]], ...]
    @param results: list of nodes in level order

    @type edges_set: set
    @param edges_set: A set of edges

    @type logger: object
    @param logger: The logger to use

    @rtype: dict
    @return: A dict that has nodes, edges
    """

    def prepare_nodes_result():
        current_level = 0
        new_results = []
        new_results_set = set()

        def update_node_dict(node, level):
            if node.get('_key') not in new_results_set:
                node.pop('identifier.values', None)
                node.update({'level': level})
                new_results.append(node)
                new_results_set.add(node.get('_key'))

        for each_result in results:
            if isinstance(each_result, dict):
                update_node_dict(each_result, current_level)
                current_level += 1
            elif isinstance(each_result, list):
                for one_item in each_result:
                    if isinstance(one_item, dict):
                        update_node_dict(one_item, current_level)
                current_level += 1

        return new_results

    def prepare_edges_result():
        new_results = [dict(x) for x in edges_set]
        for each_result in new_results:
            if isinstance(each_result, dict):
                each_result.update({
                    'subject_title': entity_key_index.get(each_result.get('subject_key')).get('title'),
                    'object_title': entity_key_index.get(each_result.get('object_key')).get('title')
                })

        return new_results

    final_result = {'nodes': prepare_nodes_result(), 'edges': prepare_edges_result()}
    return final_result


def _get_neighbors_one_level(owner, itsi_entity_obj, itsi_entity_relationship_obj, current_entity,
                             entity_fields, entity_relationship_fields,
                             entity_key_index, entity_title_index, entity_identifier_value_index,
                             logger):
    """
    Get neighbors for a given entity at one level distance. It is represented as a list of nodes with key only,
    and a list of edges.

    @type owner: basestring
    @param owner: owner making the request

    @type itsi_entity_obj: object
    @param itsi_entity_obj: ItsiEntity object for query KV Store

    @type itsi_entity_relationship_obj: object
    @param itsi_entity_relationship_obj: ItsiEntityRelationship object for query KV Store

    @type entity: dict
    @param entity: An entity to get its neighbors at one level

    @type entity_fields: list
    @param entity_fields: list of entity fields to retrieve from KV Store

    @type entity_relationship_fields: list
    @param entity_relationship_fields: list of entity relationship fields to retrieve from KV Store

    @type entity_key_index: dict
    @param entity_key_index: index that has entity's key as key and entity itself as value

    @type entity_title_index: dict
    @param entity_title_index: index that has entity's title as key and entity's key as value

    @type entity_identifier_value_index: dict
    @param entity_identifier_value_index: index that has entity's identifier value as key and entity's key as value

    @type logger: object
    @param logger: The logger to use

    @rtype: tuple(list, list)
    @return: A list of nodes with key only, and a list of edges.
    """

    def get_entity_relationship_for_entity():
        # First build filter before query entity relationship KV Store
        filters = []
        for current_key, current_value in current_entity.iteritems():
            if current_key == 'identifier.values':
                for v in current_value:
                    filters.append({'subject_identifier': v})
                    filters.append({'object_identifier': v})

        entity_relationship_filter_data = {'$or': filters}
        logger.debug('Build entity relationship filter data: entity_relationship_filter_data=%s',
                     entity_relationship_filter_data)

        # Query entity relationship KV Store
        matching_records = \
            itsi_entity_relationship_obj.get_bulk(owner, filter_data=entity_relationship_filter_data,
                                                  fields=entity_relationship_fields)

        logger.debug('Query entity relationship for current_entity=%s. The result is: %s',
                     current_entity, matching_records)

        return matching_records

    def get_entities_for_identifiers():
        # Build a set of all identifiers from matching entity relationships records
        all_identifiers_set = set()
        for matching_one in matching_entity_relationships:
            all_identifiers_set.add(matching_one.get('subject_identifier'))
            all_identifiers_set.add(matching_one.get('object_identifier'))

        # Build filter before query entity KV Store for the identifiers.
        # Even if a identifier might exist in entity_title_index or entity_identifier_value_index,
        # we still need query it in order to find if there is any duplicate identifier.
        identifiers_to_resolve = list(all_identifiers_set)
        entity_filters = []
        for identifier in identifiers_to_resolve:
            entity_filters.append({'identifier.values': identifier})
        entity_filter_data = {'$or': entity_filters}

        # Query entity KV Store for these identifiers
        matching_records = itsi_entity_obj.get_bulk(owner, filter_data=entity_filter_data,
                                                    fields=entity_fields)

        logger.debug('Query entity for identifiers=%s. The result is: %s',
                     identifiers_to_resolve, matching_records)

        return matching_records

    def build_indexes_for_entities():
        # Build/update entity_key_index, entity_title_index, entity_identifier_value_index from matching entity
        # records

        duplicate_identifiers_set = set()

        for matching_one in matching_entities:
            entity_key = matching_one.get('_key')
            entity_title = matching_one.get('title')

            if entity_key not in entity_key_index:
                entity_key_index.update({entity_key: _create_filtered_entity(matching_one)})

            if entity_title not in entity_title_index:
                entity_title_index.update({entity_title: entity_key})

            identifier_values = matching_one.get('identifier', {}).get('values', [])
            for identifier_value in identifier_values:
                if identifier_value not in entity_identifier_value_index:
                    entity_identifier_value_index.update({identifier_value: entity_key})
                elif identifier_value in entity_identifier_value_index and \
                        entity_identifier_value_index.get(identifier_value) != entity_key:
                    # If identifier already exists in the index but key is different, we run into duplicated identifier
                    # situation and will error out in the end.
                    existing_entity_key = entity_identifier_value_index.get(identifier_value)
                    duplicate_identifiers_set.add((identifier_value, entity_key))
                    duplicate_identifiers_set.add((identifier_value, existing_entity_key))

        logger.debug('Build the following indexes: entity_key_index=%s, entity_title_index=%s,'
                     'entity_identifier_value_index=%s',
                     entity_key_index, entity_title_index, entity_identifier_value_index)

        if len(duplicate_identifiers_set) > 0:
            message = _('Duplicate identifiers with keys found among %s') % list(duplicate_identifiers_set)
            logger.error(message)
            raise ITOAError(status='500', message=message)

    def dedupe_entity_relationship():
        # Convert matching_entity_relationships from subject_identifier and object_identifier to the
        # corresponding keys and de-dupe them.

        for matching_one in matching_entity_relationships:
            # Resolve subject_identifier to subject_key
            subject_identifier = matching_one.get('subject_identifier')
            subject_key = None
            if subject_identifier in entity_title_index:
                subject_key = entity_title_index.get(subject_identifier)
            elif subject_identifier in entity_identifier_value_index:
                subject_key = entity_identifier_value_index.get(subject_identifier)

            # Resolve object_identifier to object_key
            object_identifier = matching_one.get('object_identifier')
            object_key = None
            if object_identifier in entity_title_index:
                object_key = entity_title_index.get(object_identifier)
            elif subject_identifier in entity_identifier_value_index:
                object_key = entity_identifier_value_index.get(object_identifier)

            new_entity_relationship = {'subject_key': subject_key,
                                       'object_key': object_key,
                                       'predicate': matching_one.get('predicate')
                                       }

            if tuple(new_entity_relationship.iteritems()) not in new_entity_relationship_set:
                new_entity_relationship_set.add(tuple(new_entity_relationship.iteritems()))

        logger.debug('The set of entity relationships after de-dupe: %s', new_entity_relationship_set)

    def normalize_entity_relationship():
        # Then normalize the set of entity relationships.
        # For entity relationship that has predicate as host or hostedBy, will add its pair if missing

        # additional_pair_set = set()
        normalize_predicates = ['hosts', 'hostedBy']
        for matching_one_tuple in new_entity_relationship_set:
            matching_one = dict(matching_one_tuple)
            predicate = matching_one.get('predicate')
            if predicate in normalize_predicates:
                new_entity_relationship = {'subject_key': matching_one.get('object_key'),
                                           'object_key': matching_one.get('subject_key')
                                           }
                new_predicate = 'hosts' if predicate == 'hostedBy' else 'hostedBy'
                new_entity_relationship.update({'predicate': new_predicate})

                new_tuple = tuple(new_entity_relationship.iteritems())
                if new_tuple not in new_entity_relationship_set:
                    additional_pair_set.add(new_tuple)

        logger.debug('The set of entity relationships after normalization: %s', additional_pair_set)

    def prepare_nodes_edges_from_entity_relationship():
        # Create the set of nodes that only has key, and the set of entity relationships
        nodes_key_set = set()
        edges_set = set()
        for matching_one in total_entity_relationship_set:
            new_entity = dict(matching_one)
            if new_entity.get('subject_key') is not None:
                nodes_key_set.add(new_entity.get('subject_key'))

            if new_entity.get('object_key') is not None:
                nodes_key_set.add(new_entity.get('object_key'))

            if new_entity.get('subject_key') is not None and new_entity.get('object_key') is not None:
                edges_set.add(matching_one)

        nodes_key = list(nodes_key_set)
        edges = [dict(x) for x in edges_set]
        logger.debug('Get nodes with key: %s. Get edges: %s', nodes_key, edges)
        return nodes_key, edges

    # Get all matching entity relationships that start or from any identifier value of current entity
    matching_entity_relationships = get_entity_relationship_for_entity()

    # For all unique identifiers in these entity relationships, get matching entities
    matching_entities = get_entities_for_identifiers()

    # Build indexes from matching entities
    build_indexes_for_entities()

    # Dedupe and normalize the matching entity relationships
    new_entity_relationship_set = set()
    additional_pair_set = set()
    dedupe_entity_relationship()
    normalize_entity_relationship()
    total_entity_relationship_set = new_entity_relationship_set.union(additional_pair_set)
    logger.debug('The total set of entity relationships: %s', total_entity_relationship_set)

    return prepare_nodes_edges_from_entity_relationship()


def _get_neighbors_on_level_order(owner, itsi_entity_obj, itsi_entity_relationship_obj,
                                  start_node, entity_fields, entity_relationship_fields,
                                  level, max_count, logger):
    """
     Get neighbors for a given entity by doing Breadth first search (BFS).
     The result is represented as a list of nodes with key only, and a list of edges.

     @type owner: basestring
     @param owner: owner making the request

     @type itsi_entity_obj: object
     @param itsi_entity_obj: ItsiEntity object for query KV Store

     @type itsi_entity_relationship_obj: object
     @param itsi_entity_relationship_obj: ItsiEntityRelationship object for query KV Store

     @type start_node: dict
     @param start_node: An entity to get its neighbors

     @type entity_fields: list
     @param entity_fields: list of entity fields to retrieve from KV Store

     @type entity_relationship_fields: list
     @param entity_relationship_fields: list of entity relationship fields to retrieve from KV Store

     @type level: Int
     @param level: The distance from start_node for neighbors

     @type max_count: Int
     @param max_count: The max number of edges allowed

     @type logger: object
     @param logger: The logger to use

     @rtype: dict
     @return: A dict that has nodes, edges, level, max_count, complete
     """
    # Dict using entity's key as key and entity itself as value
    entity_key_index = {}
    # Dict using entity's title as key and entity's key as value
    entity_title_index = {}
    # Dict using entity's identifier as key and entity's key as value
    entity_identifier_value_index = {}

    nodes_key_set = set()
    edges_set = set()

    results = []
    current_level_nodes = [start_node]
    visited_level = 0
    is_complete_on_level = True
    is_complete_on_edges = True

    while current_level_nodes:
        logger.debug('Start visiting current_level_nodes: current_level_nodes=%s, visited_level=%s,'
                     'nodes_key_set=%s, results=%s',
                     current_level_nodes, visited_level, nodes_key_set, results)

        # Check if we are done visiting the level specified
        if visited_level == level:
            results.append(current_level_nodes)
            is_complete_on_level = False
            logger.debug('End visiting current_level_nodes earlier because visited_level==level (=%s).'
                         'Append current_level_nodes=%s',
                         visited_level, current_level_nodes)
            break

        level_results = []
        next_level_nodes = []

        for current_node in current_level_nodes:
            # Visit current node
            level_results.append(current_node)

            # Mark it visited by adding it to nodes_key_set
            nodes_key_set.add(current_node.get('_key'))

            # Get its neighbors and edges one level away
            neighbor_nodes_keys, neighbor_edges = \
                _get_neighbors_one_level(owner, itsi_entity_obj, itsi_entity_relationship_obj,
                                         current_node, entity_fields, entity_relationship_fields,
                                         entity_key_index, entity_title_index, entity_identifier_value_index,
                                         logger)
            logger.debug('Get one-level neighbors for current_node=%s: '
                         'neighbor_nodes_keys=%s, neighbor_edges=%s',
                         current_node, neighbor_nodes_keys, neighbor_edges)

            # For each of its neighbor nodes, if not visited, add it to next_level_nodes to visit
            for neighbor_node_key in neighbor_nodes_keys:
                if neighbor_node_key not in nodes_key_set and neighbor_node_key in entity_key_index:
                    next_level_nodes.append(entity_key_index.get(neighbor_node_key))

            # For each of its neighbor edges, add it to edges_set to ensure uniqueness.
            # If the number of them is over max_count, break.
            for neighbor_edge in neighbor_edges:
                if len(edges_set) == max_count:
                    logger.debug(
                        'End visiting current_level_nodes earlier because number of relationship '
                        'equal to max_count(=%s)', max_count)
                    is_complete_on_edges = False
                    break
                edges_set.add(tuple(neighbor_edge.iteritems()))

        results.append(level_results)
        current_level_nodes = next_level_nodes
        visited_level += 1

        logger.debug('End visiting current_level_nodes: next_level_nodes=%s, nodes_key_set=%s, results=%s',
                     next_level_nodes, nodes_key_set, results)

    # Prepare final result

    final_result = _prepare_nodes_edges_result(results, edges_set, entity_key_index)
    msg = ''
    if is_complete_on_edges and not is_complete_on_level:
        msg = _('limited by level')
    elif is_complete_on_level and not is_complete_on_edges:
        msg = _('limited by max count')
    elif not is_complete_on_level and not is_complete_on_edges:
        msg = _('limited by level and max count')

    final_result.update({
        'start_entity': start_node,
        'level': level,
        'max_count': max_count,
        'complete': {
            'result': is_complete_on_level and is_complete_on_edges,
            'reason': msg
        }})

    logger.debug('_get_neighbors_on_level_order returns final_result=%s', final_result)

    return final_result


def get_neighbors(session_key, current_user, owner, kwargs, logger):
    """
    Get related entity relationships for a given entity

    @type session_key: basestring
    @param session_key: The user's session key

    @type current_user: basestring
    @param current_user: The current user

    @type owner: basestring
    @param owner: owner making the request

    @type kwargs: dict
    @param kwargs: key word arguments extracted from request.
        Required: entity_identifier or entity_key
        Optional: level=1, max_count=100

    @type: object
    @param logger: The logger to use

    @rtype: dict
    @return: dict of related entity relationships. An example,
    {
        max_count: 100,
        level: 1,
        start_entity: {
            title: "entityD",
            _key: "49156d54-ea95-4d41-990b-6f62d700afd3",
            level: 0
        },
        complete: {
            result: false,
            reason: "limit by level"
        },
        nodes: [
            {
            title: "entityD",
            _key: "49156d54-ea95-4d41-990b-6f62d700afd3",
            level: 0
            },
            {
            title: "entityC",
            _key: "81fd2d04-1d4a-46ac-b631-263a471c7d44",
            level: 1
            }
        ],
        edges: [
            {
            object_key: "49156d54-ea95-4d41-990b-6f62d700afd3",
            subject_title: "entityC",
            object_title: "entityD",
            subject_key: "81fd2d04-1d4a-46ac-b631-263a471c7d44",
            predicate: "hosts"
            },
            {
            object_key: "81fd2d04-1d4a-46ac-b631-263a471c7d44",
            subject_title: "entityD",
            object_title: "entityC",
            subject_key: "49156d54-ea95-4d41-990b-6f62d700afd3",
            predicate: "hostedBy"
            }
        ]
    }
    """
    logger.debug('get_neighbors is called with user=%s, owner=%s, kwargs=%s', current_user, owner, kwargs)

    # Parse parameters
    entity_identifier = kwargs.get('entity_identifier')
    entity_key = kwargs.get('entity_key')
    level = int(kwargs.get('level', 1))
    max_count = int(kwargs.get('max_count', 100))

    logger.debug('Parsed parameters entity_identifier=%s, entity_key=%s, level=%s, max_count=%s',
                 entity_identifier, entity_key, level, max_count)

    # Create objects to use
    instrument_obj = InstrumentCall(logger)
    itsi_entity_obj = ItsiEntity(session_key, current_user)
    itsi_entity_relationship_obj = ItsiEntityRelationship(session_key, current_user)

    # Create KVStore fields to use
    entity_fields = ['_key', 'identifier.values', 'identifier.fields', 'title']
    entity_relationship_fields = ['_key', 'subject_identifier', 'object_identifier', 'predicate']

    # Step 1. Resolve given entity key or entity identifier to a unique existing entity
    transaction_id = instrument_obj.push('itsi_entity_relationship._get_entity_from_identifier_key', owner=owner)
    start_node = \
        _get_entity_from_identifier_key(owner, itsi_entity_obj, entity_key, entity_identifier, entity_fields, logger)
    instrument_obj.pop('itsi_entity_relationship._get_entity_from_identifier_key', transaction_id)

    # Step 2. Do Breadth first search (BFS), starting from the above resolved entity.
    instrument_obj.push('itsi_entity_relationship._get_neighbors_on_level_order',
                        transaction_id=transaction_id, owner=owner)
    final_result = \
        _get_neighbors_on_level_order(owner, itsi_entity_obj, itsi_entity_relationship_obj,
                                      start_node, entity_fields, entity_relationship_fields,
                                      level, max_count, logger)
    instrument_obj.pop('itsi_entity_relationship._get_neighbors_on_level_order', transaction_id)

    return final_result
