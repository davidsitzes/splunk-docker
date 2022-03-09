# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import cherrypy
from splunk.auth import getCurrentUser

def get_session_key():
    '''
    A simple method that fetches cherrypy session key when available
    @return sessionkey: splunkd session key
    @return type: string
    @raise AttributeError: if no session is established
    '''
    try:
        return cherrypy.session["sessionKey"]
    except AttributeError:
        raise

def get_operation():
    '''
    A method that infers the desired operation from cherrypy.request.method
    @return operation_type: 'read'/'write'/'delete'
    @return type: str

    @raise AttributeError: if cherrypy isn't setup
    @raise Exception: if method isnt supported
    '''
    operation = None
    try:
        method = cherrypy.request.method
        if method == 'GET':
           operation = 'read'
        elif method == 'POST' or method == 'PUT':
            operation = 'write'
        elif method == 'DELETE':
            operation = 'delete'
        else:
            message = 'Unsupported operation - {0}'.format(self.method)
            raise Exception(message)
    except AttributeError:
        raise
    return operation

def get_current_username():
    '''
    Get current username
    @return username: current user logged into the system
    @return type: str
    @raise AttributeError: if user is not logged into system
    '''
    try:
        current_user_obj = getCurrentUser()
        return current_user_obj.get('name')
    except AttributeError:
        raise 
