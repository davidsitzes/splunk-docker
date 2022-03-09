# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import _ItsiObjectCache

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_entity import ImportedEntity  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class EntityCache(_ItsiObjectCache):
    """
    Encapsulate a collection of entities, performing the update behavior as needed.
    """
    def _update_cache(self, title, entity):
        # type: (Text, ImportedEntity) -> None
        # Update the dictionary with a new entity
        #
        # @param key: the key of the object being inserted
        # @type: string
        #
        # @param value: the entity to be inserted into the dictionary
        # @type: dict
        if title not in self._cache:
            self._cache[title] = entity
            return None

        self._cache[title].update_with_imported_entity(entity)
        return None

    def __setitem__(self, title, entity):
        # type: (Text, ImportedEntity) -> None
        self._update_cache(title, entity)
        return None

    def update_with(self, entity):
        # Type: (ImportedEntity) -> None
        """
        Convenience method to add an entity
        @param entity: an entity to store in the cache
        """
        self._update_cache(entity.identifying_name, entity)

    def update_service_dependencies(self, upserted_service_cache):
        # type: (Dict[Text, Any]) -> None
        """
        For a given entity_cache which is yet to be written to statestore, update its entries with service ids
        from service upsertions

        @param entity_cache: entities which need updating in statestore, key'ed by entity title, value is entity blob
        @type: dictionary

        @param: upserted_service_cache: services which have been upserted by us after parsing csv file
            key'ed by service key, value is service blob
        @type: dictionary

        @return: updated entity_cache if applicable
        @type: dictionary
        """
        if not (upserted_service_cache and len(upserted_service_cache) > 0):
            return

        for title, entity in self._cache.iteritems():
            service_dependencies = []
            for (es_key, service_title) in entity.services:
                for service_id, service in upserted_service_cache.iteritems():
                    if service.get('title') == service_title:
                        service_dependencies.append({'_key': service_id, 'title': service_title})
                entity.services = service_dependencies
        return None
