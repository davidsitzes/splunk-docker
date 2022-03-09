# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import logging
from copy import deepcopy
import json

import splunk.Intersplunk
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk import rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import get_current_timestamp_utc

from ITOA.setup_logging import setup_logging
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_security_group import ItsiSecGrp

LOGGER = "itsi.command.storeentities"

logger = setup_logging("itsi_searches.log", LOGGER, is_console_header=True, level=logging.ERROR)

def parseArgs():
    '''
    Parse out the arguments passed into the scripted input
    entityfields is a multivalued field, where the values are separated by semicolons
    @retval: a dict of the valid arguments
    @rettype: dict
    '''
    i = 1
    required_parameters = ['title_field']
    optional_parameters = ['identifier_fields','informational_fields','description_fields','services',
                           'preview','insertion_mode','service_fields', 'sec_grp']
    valid_parameters = required_parameters + optional_parameters
    parsed_params = {}
    #We could probably list/dict comprehension the hell out of this
    #But we wont
    for arg in sys.argv[1:]: #We dont want the zeroth element
        found = False
        for param in valid_parameters:
            param_string = param+"="
            if arg.find(param_string) != -1:
                if param in parsed_params:
                    splunk.Intersplunk.parseError(_("Duplicate parameter found: %s") % param)
                parsed_params[param] = arg[arg.find(param_string)+len(param_string):]
                found = True
        if not found:
            #The arg was not found in the list of valid params - invalid key
            splunk.Intersplunk.parseError(_("Invalid key specified: %s") % arg)

    #Make sure that all of the valid parameters are there
    #And no invalid parameters are there
    for key in parsed_params.keys():
        if key in required_parameters:
            required_parameters.remove(key)
    if len(required_parameters) != 0:
        splunk.Intersplunk.parseError(_("Missing required key(s): %s") % ",".join(required_parameters))


    #Special processing for anything that could be represented as a list
    special_params = ['identifier_fields','informational_fields','description_fields','services','service_fields']
    for special in special_params:
        if special in parsed_params:
            parsed_params[special] = parsed_params[special].split(';')
    return parsed_params

def getModStamp(sessionKey):
    #username = getCurrentUser()
    resp,content = rest.simpleRequest('/authentication/current-context',getargs={"output_mode":"json"},sessionKey=sessionKey,raiseAllErrors=False)
    content = json.loads(content)
    username = content['entry'][0]["content"]["username"]
    modified_time = get_current_timestamp_utc()
    source = 'splunk_search'
    return {"mod_by":username,"mod_time":modified_time,"mod_source":source}

def appendEntity(sessionKey, owner, entity_object, entityRecord, preview):
    '''
    Appends a new entity to the collection, used by the other modes
    such as upsert and replace
    '''
    if preview:
        entityRecord['_key'] = 'New key'
    else:
        #Go throw it into the statestore
        mods = getModStamp(sessionKey)
        entityRecord["create_by"] = mods["mod_by"]
        entityRecord["create_time"] = mods["mod_time"]
        entityRecord["create_source"] = mods["mod_source"]
        entity_key = entity_object.create(owner, entityRecord)
        entityRecord['_key'] = entity_key['_key']
    return [entityRecord]


def replaceEntity(sessionKey, owner, entity_object, entityRecord, preview):
    '''
    Attempts to find the existing entity and replaces it if there is a match
    '''
    existing_entities = entity_object.get_bulk(owner, filter_data={"title":entityRecord['title']})
    #Replace ALL entities that match on the existing one
    if len(existing_entities) == 0:
        return appendEntity(sessionKey, owner, entity_object, entityRecord, preview)
    new_entities = []
    for e in existing_entities:
        #We want to make a deep copy of the entity here because we don't want
        #Information leakage between entities when creating them
        new_entity = deepcopy(entityRecord)
        #Transfer over all of the existing information that might be relevent
        for x in ['_key','create_time','create_by','create_source', 'services', '_version']:
            if x in e:
                new_entity[x] = e[x]
        new_entities.append(new_entity)
    if not preview:
        entity_object.save_batch(owner, new_entities, False, req_source = 'storeentities')
    return new_entities


def upsertEntity(sessionKey, owner, entity_object, entityRecord, preview):
    '''
    Attempts to insert an entity if there is no match, if there is, updates the existing record
    '''
    array_fields = ['services']
    existing_entities = entity_object.get_bulk(owner, filter_data={"title":entityRecord['title']})
    #Upsert on ALL entities that match on the existing one
    if len(existing_entities) == 0:
        return appendEntity(sessionKey, owner, entity_object, entityRecord, preview)
    new_entities = []
    for e in existing_entities:
        new_entity = deepcopy(entityRecord)
        for x in ['_key','create_time','create_by','create_source']:
            if x in e:
                new_entity[x] = e[x]
        for f in array_fields:
            if type(e[f]) is list:
                new_entity[f] += e[f]
            else:
                new_entity[f] += e[f].split(',')
        for n in ["identifier","informational"]:
            if len(e.get(n,{})) > 0:
                identifiers = e[n]
                fields = identifiers.get("fields",None)
                values = identifiers.get("values",None)
                if fields == None or values==None:
                    continue
                for f in fields:
                    values = e[f]
                    if type(values) is str or type(values) is unicode:
                        values = values.split(',')
                    #The new entity record should always be a list at this point
                    new_entity[f] = list(set(e[f] + new_entity.get(f,[])))
        new_entities.append(new_entity)
    if not preview:
        entity_object.save_batch(owner, new_entities, False, req_source = 'storeentities')
    return new_entities

def storeEntities(sessionKey,owner,params,records):
    '''
    Takes the records specified, and from them extracts the fields required.  The
    '''
    LOG_PREFIX = "[storeentities] "
    logger.debug(LOG_PREFIX + "begin execution")
    entity_object = ItsiEntity(sessionKey, 'nobody')
    new_records = []
    #Load all the instructions for parsing
    insertion_mode = params.get('insertion_mode','append')
    informational_fields = params.get("informational_fields",None) #If this is None, then we should grab all of the fields
    identifier_fields = params.get("identifier_fields",None) #If this is None, then we should grab all of the fields
    service_fields = params.get("service_fields",None) #If this is None, then we should grab all of the fields
    description_fields = params.get("description_fields",None) #If this is None, then we should grab all of the fields
    title_field = params.get("title_field",None)
    sec_grp = params.get('sec_grp', ItsiSecGrp.get_default_itsi_security_group_key())
    if identifier_fields == None:
        identifier_fields = []
        if len(records) > 0:
            first_record = records[0]
            identifier_fields = first_record.keys()
            identifier_fields = [field for field in identifier_fields if not field.startswith('__mv')]
        else:
            splunk.Intersplunk.parseError(_("No fields to automatically extract from results set"))
    elif type(identifier_fields) is str or type(identifier_fields) is unicode:
        identifier_fields = identifier_fields.split(";")

    if informational_fields == None:
        informational_fields = []
    elif type(informational_fields) is str or type(informational_fields) is unicode:
        informational_fields = informational_fields.split(";")
    if service_fields == None:
        service_fields = []
    elif type(service_fields) is str or type(service_fields) is unicode:
        service_fields = service_fields.split(";")
    if description_fields == None:
        description_fields = []
    elif type(description_fields) is str or type(description_fields) is unicode:
        description_fields = description_fields.split(";")

    #Fields now should be an array of associated input fields.  These are inputs
    #That are associated with each other
    logger.debug(LOG_PREFIX + "begin result analysis")
    try:
        mods = getModStamp(sessionKey)
        for result in records:
            new_entity = {}
            informational_values = set()
            informational_fields_to_remove = []
            for field in informational_fields:
                entity = result.get(field,None)
                if entity is None:
                    #This field doesn't exist in the informational fields
                    informational_fields_to_remove.append(field)
                    continue
                if type(entity) is str or type(entity) is unicode:
                    ne = entity.split(",")
                else:
                    ne = entity
                #Add each one as an array value
                new_entity[field] = ne
                informational_values.update(ne)
            #remove the informational fields that had null values
            for x in informational_fields_to_remove:
                informational_fields.remove(x)

            identifier_values = set()
            for field in identifier_fields:
                entity = result.get(field,None)
                if entity is None:
                    splunk.Intersplunk.parseError(_("storeentities error - identifying field {0} must be non-Null for all entities").format(field))
                    continue
                if type(entity) is str or type(entity) is unicode:
                    ne = entity.split(",")
                else:
                    ne = entity
                new_entity[field] = ne
                #Add each one as an array value
                identifier_values.update(ne)

            title = result.get(title_field,None)
            #NOTE: This should already be split correctly, per parseArgs above
            services = params.get('services',[])
            services_for_entity = []

            service_object = ItsiService(sessionKey, 'nobody')
            for field in service_fields:
                new_service_title = result.get(field,None)
                if new_service_title is None:
                    continue
                existing_services = service_object.get_bulk(owner, filter_data={'$and':[
                    {"title":new_service_title}, {'sec_grp': sec_grp}]})
                services_to_create = []
                #If the name doesn't exist, add it
                if len(existing_services) == 0:
                    serviceRecord = {"title":new_service_title}
                    mods = getModStamp(sessionKey)
                    serviceRecord["create_by"] = mods["mod_by"]
                    serviceRecord["create_time"] = mods["mod_time"]
                    serviceRecord["create_source"] = mods["mod_source"]
                    serviceRecord["_key"] = serviceRecord.get('_key', ITOAInterfaceUtils.generate_backend_key())
                    serviceRecord['sec_grp'] = sec_grp
                    services_to_create.extend([serviceRecord])
                    services_for_entity.append({'_key': serviceRecord['_key'], 'title': serviceRecord['title']})
                else:
                    services_for_entity.append({
                        '_key': existing_services[0]['_key'],
                        'title': existing_services[0]['title']
                    })
                service_object.save_batch(
                    owner,
                    services_to_create,
                    False,
                    req_source = 'storeentities'
                )
                if new_service_title not in services:
                    services.append(new_service_title)

            new_entity['description'] = ''
            for field in description_fields:
                entity = result.get(field,None)
                if entity is None:
                    continue
                new_entity['description'] = new_entity['description'] + ' ' + entity


            #So now we should have a set of entities and a list of fieldnames
            #These will be translated into the key-value pairs
            new_entity["identifier"] = {"fields":identifier_fields,"values":list(identifier_values)}
            new_entity["informational"] = {"fields":informational_fields,"values":list(informational_values)}
            new_entity["title"] = title
            new_entity["services"] = services_for_entity
            new_entity['sec_grp'] = sec_grp
            preview = params.get('preview',False)
            if preview == False or preview == '0' or preview.lower() == 'false' or preview.lower() == 'f':
                preview = False
            else:
                preview = True
            #Now that we're ready to update the db, update the creation fields
            new_entity['mod_time'] = mods['mod_time']
            new_entity['mod_by'] = mods['mod_by']
            new_entity['mod_source'] = mods['mod_source']
            #Okay, now to actually do the deed
            if insertion_mode.lower() == 'append':
                new_entities = appendEntity(sessionKey, owner, entity_object, new_entity, preview)
            elif insertion_mode.lower() == 'upsert':
                new_entities = upsertEntity(sessionKey, owner, entity_object, new_entity, preview)
            elif insertion_mode.lower() == 'replace':
                new_entities = replaceEntity(sessionKey, owner, entity_object, new_entity, preview)

            for ne in new_entities:
                new_result = deepcopy(result)
                if preview:
                    #Show them what would get put into the statestore at this point
                    new_result['preview_identifier_fields'] = ne['identifier']['fields']
                    new_result['preview_identifier_values'] = ne['identifier']['values']
                    new_result['preview_informational_fields'] = ne['informational']['fields']
                    new_result['preview_informational_values'] = ne['informational']['values']
                    for f in ne['informational']['fields']:
                        new_result['preview_' + f] = ne[f]
                    for f in ne['identifier']['fields']:
                        new_result['preview_' + f] = ne[f]
                    new_result['preview_title'] = ne['title']
                    new_result['preview_services'] = ",".join([s.get('title') for s in ne.get('services',[])])
                    new_result['preview_mod_time'] = ne['mod_time']
                    new_result['preview_mod_by'] = ne['mod_by']
                    new_result['preview_mod_source'] = ne['mod_source']
                    new_result['preview_insertion_mode'] = insertion_mode
                    new_result['preview_sec_grp'] = ne['sec_grp']

                new_result['key'] = ne.get('_key','ERROR RETRIEVING KEY')
                new_records.append(new_result)
    except Exception,e:
        logger.exception(e)
        splunk.Intersplunk.parseError(_("storeentities exception: %s") % str(e))
    logger.debug(LOG_PREFIX + "end")
    return new_records

def main():
    settings = {}
    records = splunk.Intersplunk.readResults(settings = settings, has_header = True)
    params = parseArgs()

    sessionKey = settings['sessionKey']
    owner = "nobody" # entities can only exist at app-level
    results = storeEntities(sessionKey,owner,params,records)
    splunk.Intersplunk.outputResults(results)

main()
