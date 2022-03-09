from itoa_csv_common import _ItsiObjectCache
import copy


class EntityCache(_ItsiObjectCache):
    '''
    Encapsulate a collection of entities, performing the update behavior as needed.
    '''

    # Is this rule correct?  This is a pure MERGE.  What about REPLACE?  What about APPEND?
    @staticmethod
    def merge_entity(existing_entity, update_entity):
        if not existing_entity:
            return update_entity
        merged_entity = copy.copy(existing_entity)
        merged_entity['services'] = list(set(existing_entity['services'] + update_entity['services']))
        for metaname in ['identifiers', 'informational']:
            cr = existing_entity.get(metaname, {})
            nw = update_entity.get(metaname, {})
            merged = {}
            for key in (set(cr) & set(nw)):
                merged[key] = list(set(cr.get(key, []) + nw.get(key, [])))
            merged_entity[metaname] = merged
        # TODO: Not handled: What if the descriptions aren't the same?  The existing
        # description is the one that gets returned; new descriptions are discarded.
        return merged_entity

    def _update_cache(self, key, value):
        '''
        This is the current policy: that when updating the cache, if we already have an entity
        in the cache, it gets merged with the existing entity.  I don't know that this is
        correct.'''
        # TODO: Talk to ntankersly
        self._cache[key] = self.merge_entity(self._cache.get(key, None), value)

    def __setitem__(self, key, value):
        self._update_cache(key, value)
        return None

    def update_with(self, entity):
        self._update_cache(entity['title'], entity)

    def update_service_dependencies(upserted_service_cache):
        '''
        For a given entity_cache which is yet to be written to statestore, update its entries with service ids
        from service upsertions
        @param self - the self reference
        @param entity_cache - dictionary of entities which need updating in statestore
            key'ed by entity title, value is entity blob
        @param upserted_service_cache - dictionary of services which have been upserted by us after parsing csv file
            key'ed by service key, value is service blob
        @return updated entity_cache if applicable
        '''
        if not (upserted_service_cache and len(upserted_service_cache) > 0):
            return

        for title, entity in self._cache.iteritems():
            service_dependencies = []
            for service_title in entity.get('services', []):
                for service_id, service in upserted_service_cache.iteritems():
                    if service.get('title') == service_title:
                        service_dependencies.append({'_key': service_id, 'title': service_title})
                entity['services'] = service_dependencies
        
