# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import APPEND_UPDATE_TYPE
from itoa_bulk_import_entity import StorageEntity

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_entity_cache import EntityCache  # noqa: F401
#     from itoa_bulk_import_itoa_handle import ItoaHandle  # noqa: F401
#     from itoa_bulk_import_specification import BulkImportSpecification  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class EntityUpdater(object):
    """
    The interface between an entity cache and KV Store.  This performs all the final steps
    necessary to transform the entities into KVStore ITOA objects, now that all the data
    has been normalized.
    """

    def __init__(self, itoa_handle, update_type, services):
        # type: (ItoaHandle, Text, List[Dict[Text, Any]]) -> None
        """
        @param self: a new EntityUpdater
        @param itoa_handle: the interface to the ITOA API
        @param update_type: 'append', 'upsert', or 'replace'
        @param services: The services as prepared from serviceUpdater
        """
        self.itoa_handle = itoa_handle
        self.update_type = update_type.lower()
        self.services = dict([(svc['identifying_name'], svc) for svc in services])

    def _get_existing_entities(self, entity_cache):
        # type: (EntityCache) -> List[Dict[Text, Any]]
        # Given entity cache, fetch a list of existing entities
        #
        # @param entity_cache: entities, key'ed by identifying_name
        # @return existing entities

        # Do a case insensitive lookup on title for existing entities
        if not entity_cache:
            return []
        return self.itoa_handle.entity.get_bulk(self.itoa_handle.owner,
                                                filter_data={'$or': [{'identifying_name': identifying_name}
                                                                     for identifying_name in entity_cache.keys()]})

    def update(self, entity_cache):
        # type: (EntityCache) -> List[Dict[Text, Any]]
        """
        @param entity_cache: dictionary of entity objects, key'ed by entity title
        """

        existing_entities = dict([(e.get('identifying_name', e['title'].strip().lower()), e)
                                  for e in self._get_existing_entities(entity_cache)])

        # RULE: For APPEND, the only entities from the cache we're going to store are
        # those that aren't already present in the store.
        if self.update_type == APPEND_UPDATE_TYPE:
            return [entity.to_storage_repr(self.services) for entity in entity_cache.itervalues()
                    if entity.identifying_name not in existing_entities]

        # RULE: For all else, perform the necessary update with the content from storage
        # in accordance with the update type.
        for entity in entity_cache.itervalues():
            if entity.identifying_name in existing_entities:
                entity.update_with_entity_from_storage(StorageEntity(existing_entities[entity.identifying_name]), self.update_type)

        storage_repr = [entity.to_storage_repr(self.services) for entity in entity_cache.itervalues()]

        # RULE: For all entities in both the local and existing caches, merge their
        # service collections:

        def merge_services(lsv, rsv):
            lkeys = set([l['_key'] for l in lsv])
            return lsv + [r for r in rsv if r['_key'] not in lkeys]

        for entity in storage_repr:
            key = entity.get('identifying_name', entity['title'].strip().lower())
            if key in existing_entities:
                existing_services = existing_entities[key].get('services', [])
                entity['services'] = merge_services(entity['services'], existing_services)

        return storage_repr
