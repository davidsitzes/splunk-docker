# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

# Core Python Imports
import sys
import json

# CherryPy Web Controller Imports
import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk.auth import getCurrentUser

# SA-UserAccess imports
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess
from setup_logging import setup_logging
from user_access_errors import UserAccessError, BadRequest

logger = setup_logging("user_access_interface.log", "useraccess.controllers.useraccess_interface")
logger.debug("Initialized user access log")

login_required = True

class UserAccessInterface(controllers.BaseController):
    '''
    Class that exposes endpoints for enforcing user access control for various objects..
    This Class and it's methods are quite agnostic to the object types.
    '''
    def __init__(self):
        '''
        The init method
        @param self: the self param
        '''
        super(UserAccessInterface, self).__init__()

    def _get_username(self, **kwargs):
        '''
        Get the username needed.
        @param self: the self param
        @param kwargs: key value pair..optional, expected to contain "user" key
        @return username: the requested username.
            if a "user" key is present in kwargs, that or "current user"
        @return type: string

        @raise UserAccessError: on invalid username
        '''
        # query splunkd for current user OR "user" if that is present
        current_user_obj = getCurrentUser()
        current_uname = current_user_obj.get('name', 'unknown') if isinstance(current_user_obj, dict) else 'unknown'
        username = kwargs.get('user') if (isinstance(kwargs, dict) and kwargs.get('user') is not None) else current_uname
        if username == 'unknown':
            message = 'Expecting a valid username instead of "{}"'.format(username)
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status=400, message=message)
        return username

    ###################
    ## Controllers
    ###################

    @route('/:action=is_user_capable')
    @expose_page(must_login=login_required, methods=['GET', 'POST'])
    def is_user_capable(self, action, **kwargs):
        '''
        This method checks if a user is capable to access a certain ITOA object
        If a 'user' key is present in kwargs, use that else, work on "current user"
        @param self: The self param
        @param action: method name
        @param kwargs: key value arguments
            mandatory keys: 'app_name', 'operation', 'object_type'
            optional keys: 'user'
            Ex:
            {
                'user': string, # OPTIONAL
                    # username we need to work on
                'owner': string, # OPTIONAL
                    # owner of the object we'd like to use for reference
                'app_name': string, # MANDATORY
                    # app name i.e. itsi, es etc... We will use this as a key against the capability super matrix
                'object_type': string, # MANDATORY
                    # object type under consideration i.e "glass_table", "deep_dive" etc...
                'operation': string # MANDATORY
                    # 'read/write'/'delete'
            }
        '''
        LOG_PREFIX = '[is_user_capable] '

        # check if mandatory keys are present..
        mandatory_keys = ['app_name', 'object_type', 'operation']
        for key in mandatory_keys:
            obj = kwargs.get(key)
            if obj is None:
                message = 'Missing mandatory key "{0}" from "{1}"'.format(key, json.dumps(kwargs))
                logger.error('%s %s', LOG_PREFIX, message)
                raise UserAccessError(status="400", message=message)

        username = UserAccess.get_username(logger, **kwargs)
        session_key = cherrypy.session["sessionKey"]

        object_type = kwargs.get('object_type')
        operation = kwargs.get('operation')
        app_name = kwargs.get('app_name')
        object_owner = kwargs.get('owner')

        try:
            app_capabilities = json.loads(UserAccess.get_app_capabilities(app_name, session_key, logger))
        except BadRequest as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status='400', message=str(e))

        if not app_capabilities:
            message = '{0} has not registered itself yet...make sure your app calls UserAccess.register_app_capabilities()'.format(app_name)
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status="400", message=message)

        # given object type and requested op, fetch capability name
        capability_name, message = UserAccess.fetch_capability_name(app_capabilities, object_type, operation, logger)
        if capability_name is None:
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status='400', message=message)
        try:
            user_is_capable = UserAccess.is_user_capable(username, capability_name, session_key, logger, owner=object_owner)
        except BadRequest as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status="400", message=str(e))
        except Exception as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status="500", message=str(e))
        render_msg = {
            'username':username,
            'is_capable':True,
            'operation':operation,
            'object_type':object_type,
            'message':'User "{0}" has the capability "{1}" on object type "{2}"'.format(username, operation, object_type)
            }
        if user_is_capable:
            render_msg['is_capable'] = True
            render_msg['message'] = 'User "{0}" has the capability "{1}" on object type "{2}"'.format(username, operation, object_type)
        else:
            message = 'User "{0}" does not have the capabilitity "{1}" on object type "{2}"'.format(username, operation, object_type)
            render_msg['is_capable'] = False
            render_msg['message'] = message

        return self.render_json(render_msg)

    @route('/:action=is_user_capable_all_ops')
    @expose_page(must_login=login_required, methods=['GET', 'POST'])
    def is_user_capable_all_ops(self, action, **kwargs):
        '''
        This method checks if a user is capable to access a certain ITOA object
        If a 'user' key is present in kwargs, use that else, work on "current user"
        @param self: The self param
        @param action: method name
        @param kwargs: key value arguments
            mandatory keys: 'app_name', 'object_type'
            optional keys: 'user'
            Ex:
            {
                'user': string, # OPTIONAL
                    # username we need to work on
                'owner': string, # OPTIONAL
                    # owner of the object we'd like to use for reference
                'app_name': string, # MANDATORY
                    # app name i.e. itsi, es etc... We will use this as a key against the capability super matrix
                'object_type': string, # MANDATORY
                    # object type under consideration i.e "glass_table", "deep_dive" etc...
            }
        '''
        LOG_PREFIX = '[is_user_capable_all_ops] '

        # check if mandatory keys are present..
        mandatory_keys = ['app_name', 'object_type']
        for key in mandatory_keys:
            obj = kwargs.get(key)
            if obj is None:
                message = 'Missing mandatory key "{0}" from "{1}"'.format(key, json.dumps(kwargs))
                logger.error('%s %s', LOG_PREFIX, message)
                raise UserAccessError(status="400", message=message)

        username = UserAccess.get_username(logger, **kwargs)
        session_key = cherrypy.session["sessionKey"]

        object_type = kwargs.get('object_type')
        app_name = kwargs.get('app_name')
        object_owner = kwargs.get('owner')

        try:
            app_capabilities = json.loads(UserAccess.get_app_capabilities(app_name, session_key, logger))
        except BadRequest as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status='400', message=str(e))

        if not app_capabilities:
            message = '{0} has not registered itself yet...make sure your app calls UserAccess.register_app_capabilities()'.format(app_name)
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status="400", message=message)

        # given object type and requested op, fetch capability name
        capabilities_names, message = UserAccess.fetch_capabilities_names_all_ops(app_capabilities, object_type, logger)
        if capabilities_names is None:
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status='400', message=message)
        try:
            capabilities = UserAccess.is_user_capable_all_ops(username, object_type, capabilities_names, session_key, logger, owner=object_owner)
        except BadRequest as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status="400", message=str(e))
        except Exception as e:
            logger.error('%s %s', LOG_PREFIX, str(e))
            raise UserAccessError(status="500", message=str(e))
        render_msg = {
            'username': username,
            'permissions': {
                'read': True,
                'write': True,
                'delete': True
            },
            'object_type': object_type,
            'message': 'User "{0}" capabilities on objects of type "{1}"'.format(username, object_type)
            }
        if not capabilities['read']:
            render_msg['permissions']['read'] = False
        if not capabilities['write']:
            render_msg['permissions']['write'] = False
        if not capabilities['delete']:
            render_msg['permissions']['delete'] = False

        return self.render_json(render_msg)

    @route('/:action=user_capabilities')
    @expose_page(must_login=login_required, methods=['GET', 'POST'])
    def user_capabilities(self, action, **kwargs):
        '''
        This method fetches the capabilities of the current user unless a user is specified
        @param self: the self param
        @param action: method name
        @param kwargs: key value arguments *optional*
            {
                "user":<string>
            }
        '''
        LOG_PREFIX = '[user_capabilities] '

        username = self._get_username(**kwargs)
        user_capabilities = []

        try:
            session_key = cherrypy.session["sessionKey"] 
            user_capabilities = UserAccess.fetch_user_capabilities(username, session_key, logger)
        except BadRequest as e: 
            message = '{}'.format(e)
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status=400, message=message)
        except Exception as e:
            message = 'Exception while polling splunkd for user {}. - {}'.format(username, str(e))
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status=500, message=message)
        return self.render_json(user_capabilities)

    @route('/:action=user_roles')
    @expose_page(must_login=login_required, methods=['GET', 'POST'])
    def user_roles(self, action, **kwargs):
        '''
        This method fetches the roles of the current user unless a 'user' key
        is specified.
        @type action: string 
        @param action: method name registered with CherryPy

        @type kwargs: dictionary
        @param kwargs: key value arguments *optional*
            {
                "user" : <string>
            }
        @return json data
        @raise UserAccessError on Errors
        '''

        LOG_PREFIX = '[user_roles] '

        username = self._get_username(**kwargs)
        user_roles = []

        try:
            session_key = cherrypy.session["sessionKey"]
            user_roles = UserAccess.fetch_user_roles(username, session_key, logger)
        except BadRequest as e: 
            message = '{}'.format(e)
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status=400, message=message)
        except Exception as e:
            message = 'Exception while polling splunkd for user {}. - {}'.format(username, str(e))
            logger.error('%s %s', LOG_PREFIX, message)
            raise UserAccessError(status=500, message=message)
        return self.render_json(user_roles)
