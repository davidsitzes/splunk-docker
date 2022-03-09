# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import APPEND_UPDATE_TYPE, ENTITY_RELATIONSHIP_TRIPLE_FIELDS
from itoa_bulk_import_entity_relationship import StorageEntityRelationship


class EntityRelationshipUpdater(object):
    """
    The interface between an entity relationship cache and KV Store.  This performs all the final steps
    necessary to transform the entity relationships into KV Store ITOA objects, now that all the data
    has been normalized.
    """
    def __init__(self, itoa_handle, update_type):
        """
        @type self: object
        @param self: a new EntityRelationshipUpdater

        @type itoa_handle: object of ItoaHandle
        @param itoa_handle: the interface to the ITOA API

        @type update_type: basestring
        @param update_type: 'append', 'upsert', or 'replace'
        """
        self.itoa_handle = itoa_handle
        self.update_type = update_type.lower()

    @staticmethod
    def build_filter_from_triple_tuple(triple_tuple):
        """
        Builder filter data based on one tuple of triple fields.

        @type triple_tuple: tuple(string, string, string)
        @param triple_tuple: a tuple of triple fields

        @rtype: basestring
        @return: filter data string
        """
        filter_dict = {k: v for k, v in zip(ENTITY_RELATIONSHIP_TRIPLE_FIELDS, triple_tuple)}

        return {'$and': [filter_dict]}

    def _get_existing_entity_relationships(self, entity_relationship_cache):
        """
        Fetch a list of existing entity relationships, given entity_relationship_cache.

        @type entity_relationship_cache: object of EntityRelationShipCache
        @param entity_relationship_cache:  dictionary of entity relationships, key'ed by tuple of each's triple fields.

        @rtype: list
        @return: existing entity relationships.
        """
        if not entity_relationship_cache:
            return []

        filter_data = {
            '$or': [EntityRelationshipUpdater.build_filter_from_triple_tuple(k)
                    for k in entity_relationship_cache.keys()]
        }

        return self.itoa_handle.entity_relationship.get_bulk(
            self.itoa_handle.owner,
            filter_data=filter_data)

    def update(self, entity_relationship_cache):
        """
        @type entity_relationship_cache: object of EntityRelationShipCache
        @param entity_relationship_cache: dictionary of entity relationships, key'ed by tuple of each's triple fields.

        @rtype: list[dict]
        @return: list of entity relationships suitable for sending to Storage.
        """
        existing_entity_relationships = self._get_existing_entity_relationships(entity_relationship_cache)
        existing_entity_relationships_dict = dict([
            (tuple([e.get('subject_identifier'), e.get('object_identifier'), e.get('predicate')]), e)
            for e in existing_entity_relationships])
        
        # RULE: For APPEND, the only entities from the cache we're going to store are
        # those that aren't already present in the store.
        if self.update_type == APPEND_UPDATE_TYPE:
            return [v.to_storage_repr() for k, v in entity_relationship_cache.iteritems()
                    if k not in existing_entity_relationships_dict]

        # RULE: For all else, perform the necessary update with the content from storage
        # in accordance with the update type.
        for key, entity_relationship in entity_relationship_cache.iteritems():
            if key in existing_entity_relationships_dict:
                entity_relationship.update_with_entity_relationship_from_storage(
                    StorageEntityRelationship(existing_entity_relationships_dict[key]), self.update_type)

        return [entity_relationship.to_storage_repr()
                for entity_relationship in entity_relationship_cache.itervalues()]
