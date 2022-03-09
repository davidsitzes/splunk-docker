# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import cherrypy

class UserAccessError(cherrypy.HTTPError):
    '''
    Set the status and msg on the response
    Ex: raise UserAccessError(status=500, message="Bad User name")
    '''
    def get_error_page(self, *args, **kwargs):
        kwargs['noexname'] = 'true'
        return super(UserAccessError, self).get_error_page(*args, **kwargs)

# Following classes have been defined to help us filter out the different exception types...
class BadRequest(Exception):
    '''
    class to indicate a bad request
    '''
    pass
