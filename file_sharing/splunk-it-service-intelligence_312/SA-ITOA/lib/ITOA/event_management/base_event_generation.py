# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import abc
import csv
import gzip
import json
import sys
import os
import random

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from splunk.util import normalizeBoolean
from ITOA.event_management.notable_event_utils import NotableEventException
from notable_event_utils import filter_index_fields_and_get_event_id_for_notable_event
from ITOA.setup_logging import setup_logging
from ITOA.event_management.push_event_manager import PushEventManager

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)
logger = setup_logging('itsi_event_management.log', 'itsi.custom_alert.event_base_generator')


# This is common modular action which is being copied from CIM
# Once we moved to model of pull library at run time,  Please delete ModularAction class code and
# pull this class from common lib

import splunk.rest as rest


class InvalidResultID(Exception):
    pass


class ModularAction(object):
    DEFAULT_MESSAGE = _('sendmodalert - signature="%s" action_name="%s" search_name="%s" sid="%s" orig_sid="%s" rid="%s" orig_rid="%s" app="%s" owner="%s" action_mode="%s" action_status="%s"')

    ## we require a logging instance
    def __init__(self, settings, logger, action_name=None):
        self.settings = json.loads(settings)
        self.logger = logger
        self.session_key = self.settings.get('session_key')
        self.sid = self.settings.get('sid')
        self.orig_sid = ''
        self.rid = ''
        self.orig_rid = ''
        self.results_file = self.settings.get('results_file')
        self.search_name = self.settings.get('search_name')
        self.app = self.settings.get('app')
        self.owner = self.settings.get('owner')
        self.configuration = self.settings.get('configuration', {})
        ## use | sendalert param.action_name=$action_name$
        self.action_name = self.configuration.get('action_name') or action_name or 'unknown'
        self.action_mode = 'undetermined'
        self.action_status = ''
        ## Since we don't use the result object we get from settings it will be purged
        del self.settings['result']

        ## get job
        self.job = {}
        try:
            response, content = rest.simpleRequest('search/jobs/%s' % self.sid, sessionKey=self.session_key,
                                                   getargs={'output_mode': 'json'})
            if response.status == 200:
                self.job = json.loads(content)['entry'][0]['content']
                self.logger.info(self.message(_('Successfully retrieved search job info')))
                self.logger.debug(self.job)
            else:
                self.logger.warning(self.message(_('Could not retrieve search job info')))
        except Exception:
            logger.exception("Exception retrieving search job info")
            self.logger.warning(self.message(_('Could not retrieve search job info')))

        ## set action_mode
        if self.job.get('delegate', 'scheduler') == 'scheduler':
            self.action_mode = 'saved'
        else:
            self.action_mode = 'adhoc'

    ## The purpose of this method is to provide a common messaging interface
    def message(self, signature, status=None):
        status = status or self.action_status
        return ModularAction.DEFAULT_MESSAGE % (
        signature, self.action_name, self.search_name, self.sid, self.orig_sid, self.rid, self.orig_rid, self.app,
        self.owner, self.action_mode, status)

    ## The purpose of this method is to update per-result ModAction attributes
    def update(self, result):
        ## This is for events/results that were created as the result of a previous action
        self.orig_sid = result.get('orig_sid', '')
        ## This is for events/results that were created as the result of a previous action
        self.orig_rid = result.get('orig_rid', '')
        if 'rid' in result:
            self.rid = result['rid']
        else:
            raise InvalidResultID(_('Result must have an ID'))

    ## The purpose of this method is to generate per-result invocation messages
    def invoke(self):
        self.logger.info(self.message(_('Invoking modular alert action')))

    def dowork(self):
        return


class SendAlert(ModularAction):

    __metaclass__ = abc.ABCMeta

    """
        Send alert to index file
    """
    # FIELD NAME
    HTTP_AUTH_TOKEN = 'http_auth_token'
    HTTP_TOKEN_NAME = 'http_token_name'
    INDEX_NAME = 'index'
    SOURCETYPE = 'sourcetype'
    TITLE = 'title'
    DESCRIPTION = 'description'
    OWNER = 'owner'
    STATUS = 'status'
    SEVERITY = 'severity'
    DRILLDOWN_SEARCH_TITLE = 'drilldown_search_title'
    DRILLDOWN_SEARCH_SEARCH = 'drilldown_search_search'
    DRILLDOWN_SEARCH_LATEST_OFFSET = 'drilldown_search_latest_offset'
    DRILLDOWN_SEARCH_EARLIEST_OFFSET = 'drilldown_search_earliest_offset'
    DRILLDOWN_TITLE = 'drilldown_title'
    DRILLDOWN_URI = 'drilldown_uri'
    UNIQUE_IDENTIFIER_FIELDS = 'event_identifier_fields'
    METADATA = 'meta_data'
    EDITOR = 'editor'

    def __init__(self, settings, is_validate=True):
        """
        Initialized send alert class instance

        @type settings: basestring
        @param settings: sys.stdin.read() contains

        @type is_validate: bool
        @param is_validate: flag to validate required params or not

        @return:
        """
        self.required_params = [self.HTTP_TOKEN_NAME, self.INDEX_NAME]
        self.optional_params = [self.HTTP_AUTH_TOKEN,
                                self.SOURCETYPE, self.TITLE,
                                self.DESCRIPTION, self.TITLE, self.SEVERITY,
                                self.OWNER, self.STATUS, self.DRILLDOWN_SEARCH_SEARCH, self.DRILLDOWN_SEARCH_TITLE,
                                self.DRILLDOWN_SEARCH_EARLIEST_OFFSET, self.DRILLDOWN_SEARCH_LATEST_OFFSET,
                                self.DRILLDOWN_TITLE, self.DRILLDOWN_URI, self.UNIQUE_IDENTIFIER_FIELDS]

        action_name = 'event_generator'
        super(SendAlert, self).__init__(settings, logger, action_name)
        self.splunkd_uri = self.settings.get('server_uri')

        # Construct UI to update alert_actions settings
        self.app = 'SA-ITOA'
        self.owner = 'nobody'

        self.params = {}

        # define it after validation
        self.push_manager = None

        if is_validate and not self.validate_params():
            raise ValueError(_('Failed to validate arguments. Please make sure arguments are correct'))
        else:
            self.initialize_params()

        # Get collection fields
        self.event_id_key = 'event_id'

    @abc.abstractmethod
    def pre_processing(self, event):
        """
        Abstract function which has to be implement by inherit class
        Normally it is being used to perform some validation or may be
         send events to some where else

        @param event: dict
        @param event: event which is going to be push to index or had pushed

        @rtype: bool
        @return: True - if event pushed to kv store successfully otherwise false
        """
        raise NotImplementedError(_('Function is not implemented'))

    @abc.abstractmethod
    def undo_pre_processing(self):
        """
        Undo operation of pre_processsing

        @return:
        """
        raise NotImplementedError(_('Function is not implemented'))

    def validate_params(self):
        """
        Validate parameters

        @rtype: bool
        @return: True/False
        """
        is_found = True
        field_not_available = None
        for key in self.required_params:
            if key not in self.configuration:
                is_found = False
                field_not_available = key
                break
        if not is_found:
            raise ValueError(_('Required field={0} does not exist').format(field_not_available))
        return self.additional_validation()

    def initialize_params(self):
        """
        Initialize parameters
        @return:
        """
        for key in self.required_params:
            self.params[key] = self.configuration.get(key)
        for optional_key in self.optional_params:
            self.params[optional_key] = self.configuration.get(optional_key)
        # Now fetch remaining configuration
        for key, value in self.configuration.iteritems():
            if key not in self.params and value:
                self.params[key] = value
        self.logger.debug('Parameters=%s', self.params)
        return self.params

    def _get_field(self, name, default_value=None):
        """
        Get field
        @type name: basestring
        @param name: field name

        @type default_value: basestring
        @param default_value:  default value if field value does not exist

        @return: field value
        """
        return self.configuration.get(name, default_value)

    def _get_sourcetype(self):
        """
        Get sourcetype, dafault value is stash

         @rtype: basestring
        @return: sourcetype
        """
        value = self._get_field(self.SOURCETYPE)
        if value is None:
            # Return default
            return 'stash'
        else:
            return value

    def additional_validation(self):
        """
        Perform additional validation like checking for auth token key. If key does not exist
        then create http token key

        @return: None
        """
        # Check if auth token is provided otherwise, get auth token and set it
        # Get new
        token_name = self._get_field(self.HTTP_TOKEN_NAME)

        # Acquire token
        index = self._get_field(self.INDEX_NAME)
        sourcetype = self._get_sourcetype()

        try:
            self.push_manager = PushEventManager(self.session_key, token_name=token_name)
        except Exception as e:
            self.logger.exception(e)
            return False
        return True

    def update_and_push_event(self, result, num):
        """
        Update push event

        @type result: dict
        @param result: result

        @type num: int
        @param num: result count

        @return: None
        """

        blacklist_param_fields = [self.HTTP_AUTH_TOKEN, self.INDEX_NAME, self.HTTP_TOKEN_NAME, self.SOURCETYPE,
                                  self.METADATA, self.EDITOR]

        result.setdefault('rid', str(num))
        result['orig_sid'] = result.get('orig_sid', self.sid)
        result['orig_rid'] = result.get('orig_rid', result['rid'])

        self.update(result)
        self.invoke()

        fields_to_send = {}
        # Add parameter fields
        for field in self.params:
            if field not in blacklist_param_fields:
                fields_to_send[field] = self._get_field(field)

        # Make sure event does not contains fields which are similar name as parameters
        for field in result:
            # if field similar to parameter of alert
            if field in self.configuration:
                if 'orig_' + field not in result:
                    result['orig_' + field] = result[field]
                else:
                    self.logger.warning('Field=orig_%s already exist in the result hence adding random integer in the'
                                        ' field ', field)
                    result['orig_' + field + str(int(random.random() * 100000))] = result[field]
                del result[field]

        if result.get('host') is not None:
            host = result.get('host')
        else:
            host = self.settings.get('server_host')

        # Search name will be come source otherwise result source is being set as source type
        if self.search_name:
            source = self.search_name
            # Add search_name field
            fields_to_send['search_name'] = self.search_name
        else:
            source = fields_to_send.get('source')

        fields_to_send['source'] = source
        fields_to_send['host'] = host

        # Filter index time fields and also create event_id, _time, mod_time and event_identifier_hash
        identifier_fields = self._get_field(self.UNIQUE_IDENTIFIER_FIELDS)
        self.logger.debug('Identifier fields="%s" for search=%s', identifier_fields, self.search_name)
        event_time = result.get('_time') if normalizeBoolean(self.configuration.get('is_use_event_time', 0)) else None
        fields_to_send.update(filter_index_fields_and_get_event_id_for_notable_event(result, self.logger,
                                                                                     identifier_fields,
                                                                                     fields_to_send=fields_to_send,
                                                                                     event_time=event_time,
                                                                                     is_token_replacement=True))
        # Join serviceid field with service_ids
        if fields_to_send.get('serviceid'):
            serviceid = fields_to_send.get('serviceid').split('\n')
            if fields_to_send.get('service_ids'):
                service_ids = fields_to_send.get('service_ids').split(',')
                fields_to_send['service_ids'] = ','.join(set(service_ids + serviceid))
            else:
                fields_to_send['service_ids'] = ','.join(serviceid)

        result = self.pre_processing(fields_to_send)

        if not result:
            self.logger.error('Failed to create notable due to pre-processing step event=%s', fields_to_send)
            raise NotableEventException(_('Pre-processing step failed while creating notable event'))
        else:
            self.logger.debug("Sending event=%s to index", fields_to_send)
            try:
                self.push_manager.push_event(
                        fields_to_send,
                        time=float(fields_to_send.get('_time')),
                        host=host,
                        source=source,
                        sourcetype=self._get_sourcetype()
                 )
            except Exception as e:
                self.undo_pre_processing()
                raise e

    def run(self):
        """
        Main function which is invoked by base class function

        @rtype: bool
        @return: True/False
        """
        if not os.path.exists(self.results_file):
            self.logger.info('Result file=%s does not exist. This could happen when search has no results', self.results_file)
            sys.stdout.write('No Result Found')
        try:
            with gzip.open(self.results_file, 'rb') as fh:
                for num, result in enumerate(csv.DictReader(fh)):
                    self.update_and_push_event(result, num)
            return True
        except IOError as e:
            if e.errno == 2: # No file exist
                self.logger.info('No results founds from search, %s', e.errno)
            else:
                self.logger.exception(e)
                sys.stderr.write(e.message)
                raise e
        except Exception as e:
            self.logger.exception(e)
            sys.stderr.write(e.message)
            raise e
