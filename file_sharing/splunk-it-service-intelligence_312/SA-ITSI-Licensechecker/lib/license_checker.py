# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import logging
import sys
import json
from splunk.rest import simpleRequest
from splunk import SplunkdException

from splunk import setupSplunkLogger
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

def setup_logging(log_file, logger_name, logger=None, level=logging.INFO, is_console_header=False,
                  log_format='%(asctime)s %(levelname)s [%(name)s] [%(module)s] [%(funcName)s] %(message)s', is_propagate=False):
    """
        Setup logging
    @param log_file: log file name
    @param logger_name: logger name (if logger specified then we ignore this argument)
    @param logger: logger object
    @param level: logging level
    @param is_console_header: set to true if console logging is required
    @param log_format: log message format
    @param is_propagate: set to true if you want to propagate log to higher level
    @return: logger
    """
    if log_file is None or logger_name is None:
        raise ValueError(_("log_file or logger_name is not specified"))

    if logger is None:
        # Logger is singleton so if logger is already defined it will return old handler
        logger = logging.getLogger(logger_name)

    logger.propagate = is_propagate  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)

    # If handlers is already defined then do not create new handler, this way we can avoid file opening again
    # which is issue on windows see ITOA-2439 for more information
    if len(logger.handlers) == 0:
        file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', log_file]),
                                                            maxBytes=2500000, backupCount=5)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        logger.handlers = []
        logger.addHandler(file_handler)

        # Console stream handler
        if is_console_header:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            logger.addHandler(console_handler)

    # Read logging level information from log.cfg so it will overwrite log
    # Note if logger level is specified on that file then it will overwrite log level
    LOGGING_DEFAULT_CONFIG_FILE = make_splunkhome_path(['etc', 'log.cfg'])
    LOGGING_LOCAL_CONFIG_FILE = make_splunkhome_path(['etc', 'log-local.cfg'])
    LOGGING_STANZA_NAME = 'python'
    setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME,
                      verbose=False)

    return logger


class LicenseCheck(object):

    EXPIRED_TIME_NOT_AVAILABLE = -1

    def __init__(self, splunkd_uri, session_key, app_name='itsi'):
        """
        Init class which perform check license expiration only
        this is special cases
        @param app_name: app name
        @param splunkd_uri: splunkd uri
        @param session_key: session key
        @return:
        """
        self.splunkd_uri = splunkd_uri
        self.session_key = session_key
        self.app_name = app_name
        self.log = setup_logging('itsi_license_checker.log', 'itsi.license_checker')

    def _get_license_master_info(self):
        """
        Check if instance is master or slave
        @return: dict
                type: local or remote
                uri: license master uri
        """
        uri = self.splunkd_uri + '/services/properties/server/license/master_uri'
        response, content = simpleRequest(
            path=uri,
            getargs={'output_mode': 'json'},
            sessionKey=self.session_key,
            method='GET')

        if response.status == 200:
            info = {
                'type': 'local' if content == 'self' else 'remote',
                'uri': self.splunkd_uri if content == 'self' else content
            }
            return info
        else:
            message = _('Could not get license master URI. uri={0}.').format(uri)
            self.log.error(message)
            raise SplunkdException(message)

    def get_license_info(self, is_get_type=True):
        """
            Fetch information about installed licenses of given app

            @return a list of dict (expiration_time : int|<special>, size : int)
        """
        if is_get_type:
            instance_type = self._get_license_master_info()['type']
        else:
            instance_type = 'remote'
        if instance_type == 'local':
            return self._get_license_info(endpoint_type='licenses')
        else:
            return self._get_license_info(endpoint_type='localslave')


    def _get_license_info(self, endpoint_type):
        """
        Fetches information about app licenses using one of two possible endpoint types
            -  Endpoint type 'licenses' (Supports local license master only.)
            -  Endpoint type 'localslave' (Supports local and remote license master, supported only Splunk 6.2+ onwards)
        @param endpoint_type: {string} endpoint type
        @return: list of license of given app
        """
        if endpoint_type not in ('licenses', 'localslave'):
            raise ValueError(_('Invalid endpoint_type=%s') % endpoint_type)

        if endpoint_type == 'licenses':
            uri = self.splunkd_uri + '/services/licenser/licenses'
        elif endpoint_type == 'localslave':
            uri = self.splunkd_uri + '/services/licenser/localslave'

        response, contents = simpleRequest(path=uri, getargs={'output_mode': 'json'}, sessionKey=self.session_key,
                                           method='GET')
        self.log.debug('Licensing endpoint response headers: %s', response)
        self.log.debug('Licensing endpoint response content: %s', contents)
        if response.status != 200:
            message = _('Failed to get data from server info end point={0}').format(uri)
            self.log.error(message)
            raise SplunkdException(message)

        # Locate addon licenses
        licenseInfo = []
        for entry in json.loads(contents).get('entry', None):
            content = entry.get('content', None)
            if content is None:
                continue
            add_ons = content.get('add_ons', None)
            if add_ons is None:
                continue
            for app, value in add_ons.iteritems():
                self.log.debug('Found one addon: %s, values: %s', app, value)
                if app == self.app_name:
                    if endpoint_type == 'licenses':
                        exp_time = content.get('expiration_time')
                        size = int(float(value.get('size', 0)))
                    elif endpoint_type == 'localslave':
                        # local slave does not have expired license information at all
                        # In case this behavior changed in future release (SPL-91339), please change the below code
                        exp_time = self.EXPIRED_TIME_NOT_AVAILABLE
                        size = int(float(value.get('parameters', {}).get('size', 0)))

                    licenseInfo.append({'expiration_time': exp_time, 'size': size})

        self.log.debug('License information: %s', licenseInfo)
        return licenseInfo

    def verify_license_expiration(self):
        """
        Check if any valid license exists for the app
        @return: List of message
                    - list item contains 'type': type of message, 'message': message itself
        """
        # Getting license from localslave endpoint always which does not contain expired licenses at all
        # In case this behavior changes, we need to address it in the below code.
        try:
            license_info = self.get_license_info(is_get_type=False)
            messages = []
            if len(license_info) == 0:
                # No license show message
                self.log.error("Splunk instance does not have valid license for IT Service Intelligence.")
                messages.append({
                    'type': 'error',
                    'message': 'You do not have a valid Splunk IT Service Intelligence license. For information on how to acquire a valid license, Contact Splunk (sales@splunk.com or +1 866.GET.SPLUNK).'
                })
            else:
                self.log.info("Instance has valid license for IT Service Intelligence")

            self.log.debug("Messages=%s", messages)
            return messages
        except Exception as e:
            self.log.exception(e)
            raise e
