# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import _ItsiObjectCache, ENTITY_RELATIONSHIP_TRIPLE_FIELDS


class EntityRelationshipCache(_ItsiObjectCache):

    def __setitem__(self, triple_tuple, entity_relationship):
        self._update_cache(triple_tuple, entity_relationship)
        return None

    @staticmethod
    def get_triple_tuple(entity_relationship):
        """
        Get tuple of triple fields from entity_relationship.
        Will use it as a key for dictionary.

        @type entity_relationship: object of ImportedEntityRelationship
        @param entity_relationship: a entity_relationship object

        @rtype: tuple(string, string, string)
        @return: tuple of triple fields from entity_relationship
        """
        triple_field_values = []

        for field in ENTITY_RELATIONSHIP_TRIPLE_FIELDS:
            field_val = getattr(entity_relationship, field, None)
            if field_val is None:
                return None
            triple_field_values.append(field_val)

        return tuple(triple_field_values)

    def _update_cache(self, triple_tuple, entity_relationship):
        """
        Update the dictionary with a new entity_relationship.

        @type triple_tuple: tuple(string, string, string)
        @param triple_tuple: the key of the object being inserted

        @type entity_relationship: object of ImportedEntityRelationship
        @param entity_relationship: the entity relationship to be inserted into the dictionary

        @return: None
        """
        if triple_tuple not in self._cache:
            self._cache[triple_tuple] = entity_relationship

        return None

    def update_with(self, entity_relationships):
        """
        Update the dictionary with a list of new entity_relationship.

        @type entity_relationships: list[ImportedEntityRelationship]
        @param entity_relationships: the entity relationships to be inserted

        @return: None
        """
        if isinstance(entity_relationships, list):
            for entity_relationship in entity_relationships:
                triple_tuple = EntityRelationshipCache.get_triple_tuple(entity_relationship)
                if triple_tuple is not None:
                    self._update_cache(triple_tuple, entity_relationship)
