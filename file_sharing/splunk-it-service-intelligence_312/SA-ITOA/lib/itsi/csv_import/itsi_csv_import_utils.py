# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from copy import deepcopy
import os
import json

from splunk.appserver.mrsparkle.lib import i18n
from itsi.itsi_utils import ITOAInterfaceUtils
from itoa_bulk_import_common import (SERVICE_KEY, ENTITY_KEY, ENTITY_RELATIONSHIP_KEY)


def generate_entity_info_mod_input(import_info):
    '''
    Generate entity info for given import_info.
    This method is different from what exists in itoa_utils.py
    It's for modular input only...
    @param import_info - a valid dictionary sent by UI
    @return entity_info - a valid dictionary which is populated with the required fields and appropriate values
            NoneType if error
    @return msg - error message is applicable
    '''
    if import_info is None or len(import_info) == 0:
        return None, 'Expecting a valid import_info. Presently empty - {}'.format(import_info)
    if type(import_info) != dict:
        return None, 'Expecting import_info - {} to be a dictionary. Instead it is - {}'.format(json.dumps(import_info), type(import_info))

    if ENTITY_KEY not in import_info or import_info.get(ENTITY_KEY, None) is None:
        import_info[ENTITY_KEY] = {}

    entity_info = {}

    # populate entity_info
    add_fields = {
        'titleField': str,
        'descriptionColumns': list,
        'identifyingFields': list,
        'informationalFields': list,
        'fieldMapping': dict,
        'service_column': list
    }
    added, msg = ITOAInterfaceUtils.replace_append_info(entity_info, add_fields=add_fields)
    if not added:
        return False, 'Unable to populate entity info. Tried adding - {} to import_info - {}...But failed'.format(add_fields, json.dumps(import_info))

    # move values from top level to entity_info
    move_fields = {
        'entity_title_field': 'titleField',
        'entity_description_column': 'descriptionColumns',
        'entity_identifier_fields': 'identifyingFields',
        'entity_informational_fields': 'informationalFields',
        'entity_service_columns': 'service_column',
        'entity_field_mapping': 'fieldMapping'
    }
    for field in move_fields:
        if field in import_info and import_info[field] is not None:
            entity_info[move_fields[field]] = deepcopy(import_info[field])
        import_info.pop(field, None)  # delete old value...
    return entity_info, ''

def generate_entity_relationship_info_mod_input(import_info):
    """
    Generate entity relationship info for given import_info.
    It's for modular input only.

    @type import_info: dict
    @param import_info: a valid dictionary

    @rtype: tuple(dict|None, basestring)
    @return: a valid dictionary which is populated with the required fields and appropriate values, and a empty message.
            If error, None and error message.
    """
    if import_info is None or len(import_info) == 0:
        return None, 'Expecting a valid import_info. Presently empty - {}'.format(import_info)
    if type(import_info) != dict:
        return None, 'Expecting import_info - {} to be a dictionary. Instead it is - {}'.format(json.dumps(import_info), type(import_info))

    if ENTITY_RELATIONSHIP_KEY not in import_info or import_info.get(ENTITY_RELATIONSHIP_KEY, None) is None:
        import_info[ENTITY_RELATIONSHIP_KEY] = {}

    entity_relationship_info = {}

    # populate entity_relationship_info
    add_fields = {
        'subjectField': str,
        'entity_relationship_spec': dict
    }
    added, msg = ITOAInterfaceUtils.replace_append_info(entity_relationship_info, add_fields=add_fields)
    if not added:
        return False, 'Unable to populate entity relationship info. Tried adding - {} to import_info - {}...But failed'.format(
            add_fields, json.dumps(import_info))

    # move values from top level to entity_relationship_info
    move_fields = {
        'entity_relationship_spec': 'entity_relationship_spec'
    }
    for field in move_fields:
        if field in import_info and import_info[field] is not None:
            entity_relationship_info[move_fields[field]] = deepcopy(import_info[field])
        import_info.pop(field, None)  # delete old value...

    # copy values from import_info[ENTITY_KEY] since original field from top level has been deleted when
    # generate_entity_info_mod_input() is called
    copy_fields_from_entity = {
        'titleField': 'subjectField'
    }
    for field in copy_fields_from_entity:
        if field in import_info[ENTITY_KEY] and import_info[ENTITY_KEY][field] is not None:
            entity_relationship_info[copy_fields_from_entity[field]] = deepcopy(import_info[ENTITY_KEY][field])

    return entity_relationship_info, ''

def generate_entity_relationship_info_mod_input(import_info):
    """
    Generate entity relationship info for given import_info.
    It's for modular input only.

    @type import_info: dict
    @param import_info: a valid dictionary

    @rtype: tuple(dict|None, basestring)
    @return: a valid dictionary which is populated with the required fields and appropriate values, and a empty message.
            If error, None and error message.
    """
    if import_info is None or len(import_info) == 0:
        return None, 'Expecting a valid import_info. Presently empty - {}'.format(import_info)
    if type(import_info) != dict:
        return None, 'Expecting import_info - {} to be a dictionary. Instead it is - {}'.format(json.dumps(import_info), type(import_info))

    if ENTITY_RELATIONSHIP_KEY not in import_info or import_info.get(ENTITY_RELATIONSHIP_KEY, None) is None:
        import_info[ENTITY_RELATIONSHIP_KEY] = {}

    entity_relationship_info = {}

    # populate entity_relationship_info
    add_fields = {
        'subjectField': str,
        'entity_relationship_spec': dict
    }
    added, msg = ITOAInterfaceUtils.replace_append_info(entity_relationship_info, add_fields=add_fields)
    if not added:
        return False, 'Unable to populate entity relationship info. Tried adding - {} to import_info - {}...But failed'.format(
            add_fields, json.dumps(import_info))

    # move values from top level to entity_relationship_info
    move_fields = {
        'entity_relationship_spec': 'entity_relationship_spec'
    }
    for field in move_fields:
        if field in import_info and import_info[field] is not None:
            entity_relationship_info[move_fields[field]] = deepcopy(import_info[field])
        import_info.pop(field, None)  # delete old value...

    # copy values from import_info[ENTITY_KEY] since original field from top level has been deleted when
    # generate_entity_info_mod_input() is called
    copy_fields_from_entity = {
        'titleField': 'subjectField'
    }
    for field in copy_fields_from_entity:
        if field in import_info[ENTITY_KEY] and import_info[ENTITY_KEY][field] is not None:
            entity_relationship_info[copy_fields_from_entity[field]] = deepcopy(import_info[ENTITY_KEY][field])

    return entity_relationship_info, ''


def generate_service_info_mod_input(import_info):
    '''
    Generate service info for given import_info.
    This method is different from what exists in itoa_utils.py
    It's for modular input only...
    @param import_info - a valid dictionary
    @return service_info - a valid dictionary which is populated with the required fields and appropriate values
            NoneType if error
    @return msg - error message is applicable
    '''
    if import_info is None or len(import_info) == 0:
        return None, 'Expecting a valid import_info. Presently empty - {}'.format(import_info)

    if SERVICE_KEY not in import_info or import_info.get(SERVICE_KEY, None) is None:
        import_info[SERVICE_KEY] = {}

    service_info = {}

    # populate service_info
    add_fields = {
        'criticality': str,
        'descriptionColumns': list,
        'titleField': str
    }
    added, msg = ITOAInterfaceUtils.replace_append_info(service_info, add_fields=add_fields)
    if not added:
        return False, 'Unable to populate service info...Tried adding - {} to import_info - {}...But failed'.format(add_fields, json.dumps(import_info))

    # move values from top level to service_info
    move_fields = {
        'service_security_group': 'serviceSecurityGroup',
        'service_title_field': 'titleField',
        'service_description_column': 'descriptionColumns',
        'service_enabled': 'serviceEnabled',
        'service_template_field': 'serviceTemplate',
        'backfill_enabled': 'backfillEnabled'
    }
    for field in move_fields:
        if field in import_info and import_info[field] is not None:
            service_info[move_fields[field]] = deepcopy(import_info[field])
        import_info.pop(field, None)  # delete old value...
    return service_info, ''


def is_valid_obj_title(title):
    '''
    Check if title of obj is valid
    should not be None. should be non-empty
    @param title - string
    @return True if Valid; False if otherwise
    '''
    # ITOA-2012 is fixed in the UI. But keep the 'null' check to avoid
    # failing older versions of csv import stanzas although newer entries
    # wont need it.
    return (title is not None) and (len(title.strip()) != 0) and (title.strip() != 'null')


def generate_import_info_mod_input(import_spec):
    '''
    Generate import info.
    Method used to generate import_info for our modular input...
    @param import_spec - curated import specification...ensure that you have called massage_import_spec()
    @return a valid import_info which can be consumed by itoa_csv_loader.py...
    '''
    # some sanitization
    if import_spec is None or len(import_spec) == 0:
        return None, 'Expecting import_spec - "{}" to be of non-zero length'.format(import_spec)
    if type(import_spec) != dict:
        return None, 'Expecting import_spec - {} to be a dictionary. Instead type is - {}'.format(import_spec, type(import_spec))

    import_info = deepcopy(import_spec)

    # remove uncessary fields
    remove_fields = ['host', 'name', 'entity_type', 'index']
    removed_field_values = ITOAInterfaceUtils.trim_dict(import_info, remove_fields)  # noqa: F841

    # replace some fields in import_info
    replace_fields = {'update_type': 'updateType', 'selected_services': 'selectedServices', 'service_rel': 'service_rel', 'template': 'template', 'service_dependents': 'service_dependents'}
    replace_fields_types = {'updateType': str, 'selectedServices': list, 'service_rel': list, 'template': dict, 'service_dependents': list}
    success, msg = ITOAInterfaceUtils.replace_append_info(
        import_info,
        replace_fields=replace_fields,
        replace_fields_types=replace_fields_types
    )
    if success is False:
        return None, 'Unable to generate import info. Error message - {}'.format(msg)

    # create/update ENTITY_KEY and related fields...
    if 'entity_title_field' in import_spec:
        entity_info = {}
        entity_info, msg = generate_entity_info_mod_input(import_info)
        if entity_info is None:
            return None, 'Unable to generate import info while trying entity info. Error message - {}'.format(msg)
        import_info[ENTITY_KEY] = entity_info

        if 'entity_relationship_spec' in import_spec:
            entity_relationship_info = {}
            entity_relationship_info, msg = generate_entity_relationship_info_mod_input(import_info)
            if entity_relationship_info is None:
                return None, 'Unable to generate import info while trying entity info. Error message - {}'.format(msg)
            import_info[ENTITY_RELATIONSHIP_KEY] = entity_relationship_info

    # create SERVICE_KEY and related fields...
    if 'service_title_field' in import_spec and import_spec['service_title_field'].strip() != 'null':
        service_info = {}
        service_info, msg = generate_service_info_mod_input(import_info)
        if service_info is None:
            return None, 'Unable to generate import info, while trying service info. Error message - {}'.format(msg)
        import_info[SERVICE_KEY] = service_info

    return import_info, ''


def validate_csv_location(csv_location):
    if csv_location is None or len(csv_location.strip()) == 0:
        msg = _('Cannot work with "{}"').format(csv_location)
        return False, msg
    if not os.path.exists(csv_location):
        msg = _('file {} does not exist').format(csv_location)
        return False, msg
    if not os.path.isfile(csv_location):
        msg = _('"{}" is not a file').format(csv_location)
        return False, msg
    return True, ''


def _massage_import_spec_entities(import_spec):
    '''
    massage the following fields in import_spec for entity import
    Fields to import for entity import
    {
        "entity_title_field":"host",
        "entity_description_column":"host_desc1, host_desc2",                     #--> convert to list of strings
        "entity_identifier_fields":"host,ip_address,ip _address2,os,bu_desc",     #--> convert to list of strings
        "entity_informational_fields":"type",                                    #--> convert to list of strings
        "entity_service_columns":"bu,bu_parent,bu_gparent",                        #--> convert to list of strings
        "entity_field_mapping":""os"="operating_system","bu"="group","b u_parent"="group","bu_gparent"="group","bu_desc"="group_desc""
                                                                                #--> convert to dictionary
    }
    @param import_spec - a JSON object
    @return import_spec - modified JSON object
    @type dictionary
    '''
    # the following keys need to be converted to a list
    list_keys = ['entity_identifier_fields', 'entity_informational_fields',
                 'entity_description_column', 'entity_service_columns']

    # the following keys need to be converted to a dictionary
    dict_keys = ['entity_field_mapping']
    dicts_keys_from_string = ['entity_relationship_spec']
    for key in list_keys:
        if key in import_spec:
            import_spec[key] = ITOAInterfaceUtils.make_array_of_strings(import_spec.get(key, None))
    for key in dict_keys:
        if key in import_spec:
            import_spec[key] = ITOAInterfaceUtils.make_dict_from_kv_string(import_spec.get(key, None))
    for key in dicts_keys_from_string:
        if key in import_spec:
            val = ITOAInterfaceUtils.make_dict_from_string(import_spec.get(key))
            if val is not None and len(val) > 0:
                import_spec[key] = val
    return import_spec


def _massage_import_spec_services(import_spec):
    '''
    massage the following fields in import_spec for service import
     Fields to import for service import
    {
        "service_title_field":"bu",
        "service_description_column":"bu_desc"                                    #--> convert to list of strings
    }
    @param import_spec - a JSON object
    @return import_spec - modified JSON object
    @type JSON
    '''
    # the following keys need to be converted to a list
    list_keys = ['service_description_column']
    for key in list_keys:
        if key in import_spec:
            import_spec[key] = ITOAInterfaceUtils.make_array_of_strings(import_spec.get(key, None))
    return import_spec


def massage_import_spec(import_spec):
    '''
    import_spec is a dict. It has all the information we need to import information from a CSV file.

    here's an example for entity import -
    {
        "entity_title_field":"host",
        "entity_description_column" : "host_desc",
        "entity_field_mapping":"\"os\"=\"operating_system\",\"bu\"=\"group\",\"b u_parent\"=\"group\",\"bu_gparent\"=\"group\",\"bu_desc\"=\"group_desc\""
        "entity_identifier_fields":"host,ip_address,ip _address2,os,bu_desc",
        "entity_informational_fields":"type",
        "entity_service_columns":"bu,bu_parent,bu_gparent",

        "selected_services" : "s1,s2",
        "service_rel" : "serv1,serv2,bu",

        "host":"csridhar-lnx1.sv.splunk.com",
        "name":"itsi_csv_import://sample_mod_input",
        "csv_location":"/home/csridhar/ymail_ci_entities_new.csv",
        "update_type":"APPEND",
        "index":"default",
        "entity_relationship_spec":{"hosts":"vm_list", "hostedBy":"host_id"}
    }

    heres an example for service import -
    {
        "service_title_field":"bu_name",
        "service_description_column":"bu_desc1,bu_desc2",

        "selected_services":"serv1,serv2",
        "service_rel":"bu_gparent,bu_parent,bu_name",

        "host":"csridhar-lnx1.sv.splunk.com",
        "name":"itsi_csv_import://sample_mod_input",
        "csv_location":"/home/csridhar/ymail_ci_services_new.csv",
        "update_type":"APPEND",
        "index":"default"
    }

    OR...you can have an example - a combination of the two above for combined import.

    Whether we are importing entities or services, there are common fields which dont need any massaging ---
    {
        ...
        "csv_location":"/home/csridhar/ymail_ci_services_new.csv",
        "update_type":"APPEND",
        "host":"csridhar-lnx1.sv.splunk.com",
        "name":"itsi_csv_import://sample_mod_input",
        "index":"default",
        "selected_services":"s1,s2",
        "service_rel":"serv1,serv2,serv3"
        ...
    }

    For the fields that we care about, Splunk core sends us strings instead of lists/dictionaries. We work with this constraint.
    These fields therefore need massaging
    Common Fields to massage
    {
        ...
        "selected_services":"s1,s2",                                             #--> convert to list of strings
        "service_rel":"serv1,serv2,serv3"                                         #--> convert to list of strings
        ...
    }
    @param import_spec - dictionary of import specification as sent to us by Splunk Core
    @return massaged import_spec or None if error
    @return error message if applicable
    '''
    if import_spec is None:
        return None, 'import_spec - {} is None.'.format(import_spec)
    if type(import_spec) != dict:
        return None, 'import_spec - {} is not a dictionary'.format(import_spec)
    if len(import_spec) == 0:
        return None, 'import_spec i {} is empty'.format(import_spec)

    if import_spec.get('update_type', None) is None and import_spec.get('updateType', None) is None:
        import_spec['updateType'] = 'UPSERT'
    else:
        import_spec['updateType'] = deepcopy(import_spec['update_type'])
        import_spec.pop('update_type', None)

    # the following keys need to be converted to a list
    list_keys = ['selected_services', 'service_rel', 'service_dependents']
    for key in list_keys:
        import_spec[key] = ITOAInterfaceUtils.make_array_of_strings(import_spec.get(key, None))

    import_spec = _massage_import_spec_entities(import_spec)
    import_spec = _massage_import_spec_services(import_spec)
    return import_spec, ''
