# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

class ITOAObjConst(object):
    '''
    Constants used by ITOA
    '''
    TITLE = 'title'
    KEY = '_key'
    SERVICES = 'services'
    DESCRIPTION = 'description'
    INFORMATIONAL = 'informational'
    IDENTIFIER = 'identifier'
    CREATE_BY = 'create_by'
    CREATE_TIME = 'create_time'
    CREATE_SOURCE = 'create_source'
    MOD_BY = 'mod_by'
    MOD_TIME = 'mod_time'
    MOD_SOURCE = 'mod_source'
    OBJECT_TYPE = 'object_type'
    TYPE = '_type'
    OWNER = '_owner'
    USER = '_user'
    IDENTIFYING_NAME = 'identifying_name'

    ENTITY_INTERNAL_KEYWORDS = [TITLE, KEY, SERVICES, DESCRIPTION, INFORMATIONAL, IDENTIFIER,
                                CREATE_BY, CREATE_TIME, CREATE_SOURCE, MOD_BY, MOD_TIME, MOD_SOURCE,
                                OBJECT_TYPE, TYPE, OWNER, USER, IDENTIFYING_NAME]
    # Disable the constant update
    def __setattr__(self, *_):
        pass
