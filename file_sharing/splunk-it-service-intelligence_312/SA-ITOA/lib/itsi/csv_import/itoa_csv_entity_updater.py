from itoa_csv_common import logger, ENTITY
from itsi.itsi_utils import ITOAInterfaceUtils

class EntityUpdater(object):

    def __init__(self, itoa_handle, source='unknown'):
        self.itoa_handle = itoa_handle
        self.source = source

    def save(self, entity_cache, service_cache):
        '''
        import entities in entity_cache
        @param entity_cache: {string: entity} - dictionary of entity objects, key'ed by entity title
        @return list of entity ids
        '''
        self.service_cache = service_cache
        if self.update_type.lower() == CSVLoader.CSV_APPEND_UPDATE_TYPE:
            return self._append_all_entities(entity_cache)

        existing_entities = self._get_existing_entities(entity_cache)
        return self._merge_or_replace_entities(entity_cache, existing_enitities)

    def _append_all_entities(self, entity_cache):
        '''
        perform the action of 'append' on all entities in entity_cache
        @param entity_cache: cache of entities, key'ed by title
        '''
        return self._persist_data([self._init_entity(entity) for entity in entity_cache.items()])
    
    def _init_entity(self, pre_ent):
        # return a new entity object initialized with pre_ent
        # @param pre_ent: entity to initialize our new entity object with
        # @return dict: new entity object
        title = pre_ent['title']
        description = pre_ent['description']
        services = pre_ent['services']

        ent = self._get_new_entity(title, description, services)
        return self._add_metadata_to_entity(ent, pre_ent)

    def _get_new_entity(self, title, description, services):
        object_type = 'entity'
        user = self.itoa_handle.current_user
        source = self.source
        create_time = str(datetime.now())
        return {
            'object_type': object_type,
            '_type': object_type,
            '_key': ITOAInterfaceUtils.generate_backend_key(),
            'create_by': user,
            'mod_by': user,
            'create_time': create_time,
            'mod_time': create_time,
            'create_source': source,
            'mod_source': source,
            'title': title,
            'description': description,
            'services': services
        }

    def _add_metadata_to_entity(self, add_to, add_from):
        # add informational and identifier info from "add_from" to "add_to"
        # @param add_to: valid entity dict
        # @param add_from: valid entity dict
        # @return nothing
        to_update = {
            'informational': add_from['informational'],
            'identifier': add_from['identifiers']
        }

        # add the informational and identifier keys to the entity
        for k, v in to_update.iteritems():
            add_to[k] = {
                'values': list(chain(*v.values())),
                'fields': v.keys()
            }

        # now add various info and identifier fields as top-level key-val to the entity
        for k in to_update:
            for i in to_update[k]:
                add_to[i] = to_update[k][i]

    def _merge_or_replace_entities(self, entity_cache, existing_entities):
        # either merge entities in entity cache with what exists in backend
        #     or
        # replace what exists in backend with entities in entity cache
        #     (or append if entities do not exist)
        # @param entity_cache: cache of entities, key'ed by title
        # @param
        entities_to_persist = []
        for (title, entity) in entity_cache.iteritems():
            logger.debug('Processing entity %s', title)
            matching_entities = self._get_matching_entities(title, entity_cache, existing_entities)
            if matching_entities:
                entities_to_persist += self._merge_entity_with_given_entities(entity, matching_entities)
            else:
                entities_to_persist.append(self._init_entity(entity))

        return self._persist_data(entities_to_persist)

    def _get_matching_entities(self, entity_title, entity_cache, existing_entities):
        # Given an entity title, find *all* entities that match this title and
        # make sure we dont match an entity against a rule
        # @param entity_title: entity title as str
        # @param entity_cache: a dict of entity objects; key'ed by title
        # @param existing_entities: a dict of entity objects from KVStore; key'ed by title
        # @return list of matching entities
        return [i for i in existing_entities
                if i['title'].lower().strip() == entity_title.lower().strip() and not i.has_key('rules')]

    def _get_existing_entities(self, entity_cache):
        # given service cache, fetch a list of existing entities
        # @param entity_cache: cache of entities, key'ed by title
        # @param list of existing entities

        # Do a case insensitive lookup on title for existing entities
        filter_data = [
            {'title': {'$regex': '^' + re.escape(title) + '$', '$options': 'i'}} for title in entity_cache
        ]
        return self.itoa_handle(ENTITY).get(filter_data={'$or':filter_data})

    def _merge_entity_with_given_entities(self, new_entity, given_entities):
        # - merge given entities' details with entity
        # - merge new info in entity into given entities
        # @param entity: a dict; not really an entity, more of a prototype
        # @param given_entities: a list of entities we deem as matching
        # @return edited_ents: list of edited entity objects
        LOG_PREFIX = '[merge_entity_with_given_entities] '

        edited_ents = []
        for entity in given_entities:
            if self.update_type.lower() == REPLACE_UPDATE_TYPE:
                # following keys have str values. straight fwd assignment ought to do.
                # remaining keys need more work, they are handled below
                keys = ['title', 'description']
                entity = self._prep_entity_for_replace(entity)
                for k in keys:
                    if len(new_entity[k].strip()) > 0:  # TODO: What if it's an empty string?
                        entity[k] = new_entity[k]

            # handle other keys for merge...
            self._extend_info_and_id_fields(entity, new_entity)

            # Some have same behavior for both merge and replace
            ent = self._merge_update_services_for_given_entities(new_entity, ent)
            ent.update({
                'mod_by': self.itoa_handle.current_user,
                'mod_time': str(datetime.now()),
                'mod_source': self.source
            })
            edited_ents.append(ent)
        return edited_ents

    def _prep_entity_for_replace(self, entity):
        # prepare given entity for the replace operation
        # @param entity: a valid entity dict
        # @return entity

        del entity['services'][:]
        keys = ['informational', 'identifier']
        for k in keys:
            existing_fields = entity.get(k, {}).get('fields', [])
            for existing_field in existing_fields:
                if existing_field in entity:
                    del entity[existing_field]
            entity[k] = {'fields': [], 'values': []}
        return entity

    def extend_info_and_id_fields(self, extend_ent, extend_with):
        # Given two entities, extend the informational and identifier fields of 'extend_ent'
        # with those in 'extend_with'
        # @param extend: a dict indictaing an entity
        # @param extend_with: a dict indicating an entity
        # @return nothing

        # extend the existing attributes and dedup
        keys = {
            'identifier': 'identifiers', # identifier in backend, identifiers in code TODO; correct this
            'informational': 'informational' # informational in both backend and code
        }

        for k, v in keys.iteritems():
            extend_ent[k]['fields'] = list(
                set(extend_ent.get(k, {}).get('fields', []) + extend_with[v].keys())
            )
            extend_ent[k]['values'] = list(
                set(extend_ent.get(k, {}).get('values', []) + list(chain(*extend_with[v].values())))
            )
            for i in extend_with[v]:
                if not isinstance(extend_with[v][i], list):
                    extend_with[v][i] = [extend_with[v][i]]
                if extend_ent.has_key(i):
                    extend_ent[i].extend(extend_with[v][i])
                    extend_ent[i] = list(set(extend_ent[i]))
                else:
                    extend_ent[i] = extend_with[v][i]

    def _merge_update_services_for_given_entities(self, new_entity, existing_entity, service_cache):
        # given a list of entities, merge all their services and update them
        #with the updated services
        # @param list_of_entities: list of dicts, each dict a valid entity
        # @return nothing

        def get_upserted_service_ids_for_entity(entity):
            # given an entity, get a list of service ids of those services,
            # that have been freshly upserted
            # @param entity: valid entity dict
            # @return list of service ids
            return [service for service in entity['services'] if service in service_cache]

        services = []
        for e in [new_entity, existing_entity]:
            services += get_upserted_service_ids_for_entity(e)

        services = list(set(services))
        for e in [new_entity, existing_entity]:
            e['services'] = services


    def _persist_data(self, entities):
        # method that actually calls batch_save/extract_preview_info
        # @param to_persist_as_list: list of dicts we wish to upsert
        # @param object_type: ITOA object type
        # @return list of ids corresponding to to_persist_as_list

        object_type = 'entity'
        LOG_PREFIX = '[persist_data] '
        LOG_CHANGE_TRACKING = '[change_tracking] '

        logger.info('{} user={} method=batch_save object type={} itoa objects={}'.format(
            LOG_CHANGE_TRACKING, self.itoa_handler.current_user, 'service', services))
        return self.itoa_handler(ENTITY).batch_save(object_type, entities, LOG_PREFIX)

