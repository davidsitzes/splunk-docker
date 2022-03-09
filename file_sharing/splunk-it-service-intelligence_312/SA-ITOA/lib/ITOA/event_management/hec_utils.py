# {copyright}

import json

from splunk import ResourceNotFound
from splunk.rest import simpleRequest
from splunk.util import safeURLQuote, normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n

from ITOA.setup_logging import setup_logging
logger = setup_logging('itsi_event_management.log', 'itsi.hec_utils')

class HttpEventListenerException(Exception):
    pass

class HECUtil(object):
    """
    A class to support Http collector enablement and token management
    """

    @staticmethod
    def setup_hec_token(session_key, token_name, app='splunk_httpinput', index=None,
                        sourcetype=None, source=None, host=None, is_use_ack=False):
        """
        Creates an HEC token and chowns it to nobody, so all roles can acquire and
        index events to splunk.

        An HEC token is a session_key equivalent which lets users write events
        to Splunk via REST.

        @type session_key: basestring
        @param session_key: splunkd auth key

        @type token_name: basestring
        @param token_name: a user identifiable name of the hec token.

        @type app: basestring
        @param app: app name

        @type index: basestring
        @param index: index where events will be written to.

        @type sourcetype: basestring
        @param sourcetype: sourcetype associated with events that will be
        written

        @type source: basestring
        @param source: source associated with events that will be written.

        @type host: basestring
        @param host: host associated with events that will be written.

        @type is_use_ack: bool
        @param is_use_ack: to create sync token, set this flag

        @return: nothing.
        """
        if not isinstance(session_key, basestring):
            raise TypeError(_('Invalid session_key type. Expecting string.'))
        if isinstance(session_key, basestring) and not session_key.strip():
            raise ValueError(_('Invalid session_key value.'))

        if not isinstance(token_name, basestring):
            raise TypeError(_('Invalid token_name type. Expecting string.'))
        if isinstance(token_name, basestring) and not token_name.strip():
            raise ValueError(_('Invalid token_name value.'))

        if not isinstance(app, basestring):
            raise TypeError(_('Invalid app. Expecting string.'))
        if isinstance(app, basestring) and not app.strip():
            raise ValueError(_('Invalid app value.'))

        util = HECUtil(session_key, app=app)
        content = util.enable_http_listener()
        enable_ssl = normalizeBoolean(content.get('enableSSL', True))
        port = content.get('port')
        util.acquire_token(token_name, index, sourcetype=sourcetype, source=source, host=host,
                           is_use_ack=is_use_ack)

    def __init__(self, splunkd_session_key, user='nobody', app='splunk_httpinput'):
        if splunkd_session_key is None or splunkd_session_key == "":
            raise HttpEventListenerException("Invalid splunkd session key")
        self.splunkd_session_key = splunkd_session_key
        if not user:
            raise HttpEventListenerException("Invalid user name")
        self.base_uri = '/servicesNS/' + user + '/' + app + '/data/inputs/http/'

    def update_global_settings(self, enableSSL=True, port=8088, **kwargs):
        """
        Update HTTP listen global settings which can't be updated per SSL settings, port etc

        @type enableSSL: bool
        @param enableSSL: True/False

        @type port: int
        @param port: port number

        @type kwargs: dict
        @param kwargs: Advance settings can be passed as kwargs settings

        @rtype: bool
        @return: True if successful otherwise exception
        """

        global_uri = self.base_uri.rstrip('/') + '/http'

        if 'output_mode' not in kwargs:
            kwargs['output_mode'] = 'json'

        if enableSSL is not None:
            kwargs['enableSSL'] = enableSSL

        if port is not None:
            kwargs['port'] = port

        response, content = simpleRequest(global_uri, sessionKey=self.splunkd_session_key, method='POST',
                                          raiseAllErrors=True,
                                          postargs=kwargs)

        if response.status not in (200, 201):
            msg = _('Failed to update Http event listener global settings, response=`%s`.') % response
            logger.error('%s. content=`%s`', msg, content)
            raise HttpEventListenerException(msg)
        return response, content

    def get_global_settings(self):
        """
        Get HTTP listen global settings which can't be updated per SSL settings, port etc

        @rtype: tuple
        @return: response header and body
        """

        global_uri = self.base_uri.rstrip('/') + '/http'

        response, content = simpleRequest(global_uri, sessionKey=self.splunkd_session_key, method='GET',
                                          raiseAllErrors=True,
                                          getargs={'output_mode': 'json'})

        if response.status == 200:
            logger.info('Successfully collected Http event listener global settings')
            return response, content
        else:
            msg = _('Failed to collect Http event listener global settings, response={0},' \
                  ' content={1}.').format(response, content)
            logger.error(msg)
            raise HttpEventListenerException(msg)

    def toggle_http_listener(self, is_enable=True):
        """
        Enable or disable https listener

        @type is_enable: flag to toggle
        @param is_enable: flag to toggle enable or disable http listener

        @rtype: bool
        @return: True/False
        """
        uri = self.base_uri.rstrip('/')
        if is_enable:
            uri += '/http/enable'
        else:
            uri += '/http/disable'

        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, method='POST', raiseAllErrors=True,
                                          postargs={'output_mode': 'json'})

        operation_type = 'enabled' if is_enable else 'disabled'
        if response.status == 200 or response.status == 201:
            logger.info('Successfully %s Http event listener', operation_type)
            return True
        else:
            logger.error('Failed to %s Http event listener, response=%s, content=%s', operation_type, response, content)
            return False

    def create_token(self, token_name, index, sourcetype='stash', disabled=False,
                     is_use_ack=False, **kwargs):
        """
            @type token_name: string
            @param token_name: token_name of token

            @type index: basestring
            @param index: index where data is being sent

            @type sourcetype: basestring
            @param sourcetype: default sourcetype of token

            @type disabled: bool
            @param disabled: disabled flag of token

            @type kwargs: dict
            @param kwargs: Advance token setting like host, source etc

            @type is_use_ack: bool
            @param is_use_ack: to create sync token, set this flag

            @rtype tuple
            @return: tuple of response header and body
        """
        if token_name is not None:
            kwargs['name'] = token_name
        else:
            raise HttpEventListenerException('token_name can not be None')

        if index is not None:
            kwargs['index'] = index
        else:
            raise HttpEventListenerException('index can not be None')

        if sourcetype is not None:
            kwargs['sourcetype'] = sourcetype

        if disabled is not None:
            kwargs['disabled'] = disabled

        if is_use_ack:
            kwargs['useACK'] = '1'

        # Check for allowed indexes
        if 'indexes' in kwargs:
            kwargs['indexes'] = kwargs['indexes'] + ',' + index
        else:
            kwargs['indexes'] = index

        # default output mode is json
        if 'output_mode' is not kwargs:
            kwargs['output_mode'] = 'json'

        # Try to get existing
        try:
            # Check token is already existed
            self.get_token(token_name)
            logger.info('We have found already existed token, hence we will update existing token with new settings')
            logger.debug("Updated Token settings are=%s", kwargs)
            # Token is already exists then remove name field from params
            del kwargs['name']
            response, content = self.update_token(token_name, **kwargs)
            return response, content
        except ResourceNotFound, re:
            logger.exception(re)
            logger.info("Token=`%s` not found. Creating new token.", token_name)
            logger.debug("Token settings=`%s`", kwargs)

            # Create it
            response, content = simpleRequest(self.base_uri, sessionKey=self.splunkd_session_key, method='POST', postargs=kwargs)
            if response.status not in (200, 201):
                msg = _('Failed to create token=`%s`, response=%s, content=%s.') % (token_name, response, content)
                logger.error(msg)
                raise HttpEventListenerException(msg)

            msg = _('Successfully created token=`%s`, response=%s, content=%s.') % (token_name, response, content)
            logger.info(msg)
            return response, content

    def _get_token_uri(self, token_name):
        return self.base_uri + safeURLQuote('http://' + token_name, safe='')

    def toggle_token(self, token_name, is_enable=True):
        """
            Enable or disable http auth token

            @type token_name: basestring
            @param token_name: name of token

            @type is_enable: bool
            @param is_enable: enable or disable token

            @rtype bool
            @return: True or False
        """
        if token_name is None:
            raise HttpEventListenerException('Token name can not be None')
        uri = self._get_token_uri(token_name)
        if is_enable:
            uri += '/enable'
        else:
            uri += '/disable'
        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, method='POST',
                                          postargs={'output_mode': 'json'})
        operation_type = 'enabled' if is_enable else 'disabled'
        if response.status == 200 or response.status == 201:
            logger.info('Successfully %s %s token', operation_type, token_name)
            return True
        else:
            logger.error('Failed to %s %s', operation_type, token_name)
            return False

    def delete_token(self, token_name):
        """
            Delete given token

            @type token_name: basestring
            @param token_name: name of token

            @rtype: token type
            @return: token name
        """
        if token_name is None:
            raise HttpEventListenerException('Token name={} can not be None'.format(token_name))
        uri = self._get_token_uri(token_name)
        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, method='DELETE',
                                          postargs={'output_mode': 'json'})
        if response.status == 200:
            logger.info('Successfully deleted token=%s', token_name)
            return True
        else:
            logger.error('Failed to delete token=%s, response=%s, content=%s', token_name, response, content)
            return False

    def update_token(self, token_name, **kwargs):
        """
            Update token settings

            @type token_name: basestring
            @param token_name: name of token

            @type kwargs: dict
            @param kwargs: token update settings
        """
        uri = self._get_token_uri(token_name)
        if 'output_mode' not in kwargs:
            kwargs['output_mode'] = 'json'
        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, postargs=kwargs, method='POST')
        if response.status == 200 or response.status == 201:
            logger.info('Successfully updated token setting=%s', token_name)
            return response, content
        else:
            msg = _('Failed to update token={0} settings. response={1}, content={2}.').format(token_name, response, content)
            logger.error(msg)
            raise HttpEventListenerException(msg)

    def get_token(self, token_name, **kwargs):
        """
            Get token settings

            @type token_name: basestring
            @param token_name: name of token

            @type kwargs: dict
            @param kwargs: token update settings
        """
        uri = self._get_token_uri(token_name)
        if 'output_mode' not in kwargs:
            kwargs['output_mode'] = 'json'
        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, getargs=kwargs, method='GET')
        if response.status == 200 or response.status == 201:
            logger.info('Successfully get token setting=%s', token_name)
            return response, content
        else:
            msg = _('Failed to get token={0} settings. response={1}, content={2}.').format(token_name, response, content)
            logger.error(msg)
            raise HttpEventListenerException(msg)

    def update_token_acl(self, token_name, perms_read='*', perms_write='*', sharing='global', owner='nobody'):
        """
        Update token acl

        @type token_name: basestring
        @param token_name: token name

        @type perms_read: basestring
        @param perms_read: perms to read

        @type perms_write: basestring
        @param perms_write: perms to write

        @type sharing: basestring
        @param sharing: sharing option

        @type owner: basestring
        @param owner: owner

        @rtype: tuple
        @return: tuple of response and content. Or raise exception
        """
        uri = self._get_token_uri(token_name) + '/acl'
        post_args = {
            'sharing': sharing,
            'owner': owner,
            'perms.read': perms_read,
            'perms.write': perms_write,
            'output_mode': 'json'
        }
        response, content = simpleRequest(uri, sessionKey=self.splunkd_session_key, postargs=post_args, method='POST')
        if response.status == 200 or response.status == 201:
            logger.info('Successfully updated acl setting of token=%s', token_name)
            return response, content
        else:
            msg = _('Failed to update acl settings of token={0}. response={1}, content={2}.').format(token_name, response, content)
            logger.error(msg)
            raise HttpEventListenerException(msg)

    def acquire_token(self, token_name, index, sourcetype=None, source=None, host=None,
                      is_use_ack=False):
        """
        Return valid token -
            if token does not exist then create token
            if token is disabled then it enable it too

        @type token_name: basestring
        @param token_name: token name

        @type index: basestring
        @param index: index name

        @type sourcetype: basestring
        @param sourcetype: sourcetype

        @type source: basestring
        @param source: source name

        @type host: basestring
        @param host: host name

        @type is_use_ack: bool
        @param is_use_ack: to create sync token, set this flag

        @rtype: basestring
        @return: token or None
        """
        try:
            # Get token
            response, token_setting_raw = self.get_token(token_name)
            # Token exists
            token_setting = json.loads(token_setting_raw)
            for entry in token_setting.get('entry', []):
                content = entry.get('content', {})
                if normalizeBoolean(content.get('disabled')):
                    self.toggle_token(token_name)
                # token index is different then current on then update index to token
                if content.get('index') != index:
                    self.update_token(token_name, index=index, indexes=index)
                return content.get('token')
        except ResourceNotFound:
            logger.info("Could not find resource %s - Attempting to create one", token_name)
            res, contents = self.create_token(token_name, index, sourcetype=sourcetype,
                                              host=host, source=source, is_use_ack=is_use_ack)
            contents = json.loads(contents)
            for entry in contents.get('entry', []):
                content = entry.get('content', {})
                if normalizeBoolean(content.get('disabled')):
                    self.toggle_token(token_name)
                token = content.get('token')
                break
            # update acl settings
            self.update_token_acl(token_name)
            return token
        except Exception as e:
            logger.exception(e)
            return None

    def enable_http_listener(self):
        """
        Enable Http listener app if it is disabled, return True if everything goods well otherwise false

        @rtype: dict or None
        @return: return https listener settings
        """
        res, global_settings_contents = self.get_global_settings()
        global_settings_content = json.loads(global_settings_contents)
        for entry in global_settings_content.get('entry', []):
            # Get first entry
            content = entry.get('content', {})
            if normalizeBoolean(content.get('disabled')):
                self.toggle_http_listener()
                content['disabled'] = False
            return content
        return None
