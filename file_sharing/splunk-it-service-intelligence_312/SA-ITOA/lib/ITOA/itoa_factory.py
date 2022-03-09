# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Contains a single helper method to dynamically instantiate classes from python files
Its still debatable how effective this technique is
"""

from .itoa_config import get_supported_objects
from .itoa_exceptions import UnsupportedObjectTypeError

def instantiate_object(session_key, current_user_name, object_type, logger=None):
    '''
    Helper method to instantiate (derived) class (of itoa_object) for an object of a type
    @type session_key: string
    @param session_key: session key to use in itoa_object for backend operations
    @type current_user_name: string
    @param current_user_name: name of current user
    @type object_type: string
    @param object_type: type of object to instantiate itoa_object for
    @type: object
    @return: instance of itoa_object of object type, throws exceptions on errors
    '''
    supported_objects = get_supported_objects()
    if object_type not in supported_objects:
        raise UnsupportedObjectTypeError(
            'instantiate_object received invalid object_type: {0}'.format(object_type),
            logger=logger
        )

    object_class = supported_objects[object_type]
    return object_class(session_key, current_user_name)
