# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
ITSI does not manage Anomaly Detection search directly, it manages through
a set of MAD restful endpoints.
This class provides the context manager interface which is invoked by the service
change handlers.
'''

import json
import splunk.rest as splunk_rest
import ITOA.itoa_common as utils
from splunk.appserver.mrsparkle.lib import i18n
from splunk.util import safeURLQuote
from ITOA.setup_logging import setup_logging


logger = setup_logging("itsi_searches.log", "itsi.mad.searches")
ITSI_AD_SUMMARY_INDEX = "anomaly_detection"
ITSI_AD_BASE_SEARCH = "`get_itsi_summary_index` alert_level!=-2 indexed_is_service_max_severity_event::0 indexed_is_service_aggregate::1"
ITSI_COHESIVE_AD_BASE_SEARCH = "`get_itsi_summary_index` alert_level!=-2 indexed_is_service_max_severity_event::0 indexed_is_service_aggregate::0 | eval entity_id=if(entity_key==\"N/A\", \"pseudo:\"+entity_title, \"defined:\"+entity_key)"
ITSI_AD_EM_SPLUNKD_URI = '/services/event_management_interface/mad_event_action'
ITSI_ENTITY_LIMIT_ALERT_URI = '/services/event_management_interface/user_message_mad_event'
ITSI_AD_MANAGE_SEARCH = 1
ITSI_MAD_CONTEXT_NAME = 'itsi_mad_context'
ITSI_MAD_COHESIVE_CONTEXT_NAME = 'itsi_mad_cohesive_context'

class ItsiMADContextManager(object):
    '''
    ITSI Base Level MAD Context Manager
    Contains operations and functions to interact with the MAD rest endpoints

    All the MAD rest level exceptions are suppressed, but the exception log will be
    logged in the itsi_mad_context_mgr.log.
    '''
    log_prefix = '[ITSI MAD Context Manager]'
    collection_name = 'itsi_service'

    def __init__(self, session_key, app='SA-ITSI-MetricAD', owner='nobody', type=None):
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.uri = safeURLQuote('/servicesNS/' + self.owner + '/' + self.app + '/metric_ad/contexts')
        self.type = type

    def _get_splunk_host_port(self):
        uri = '/services/server/settings'
        params = {
                "output_mode":"json"
            }

        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                           method='GET',
                                           sessionKey=self.session_key,
                                           getargs=params)
            if res.status == 200:
                settings = json.loads(contents)
                entity = settings["entry"]
                host = '127.0.0.1'
                port = entity[0].get('content').get('mgmtHostPort')

                if not port:
                    port = 8089
                return (host, port)

        except Exception as e:
            return ("localhost", 8089)

    def get_mad_context(self, context=None):
        '''
        Get all MAD context on the system
        @rtype: list
        @return: all the MAD context created on the system if nothing is specified
                 otherwise, return the specific context
        '''
        content = None
        uri = self.uri

        if context:
            if not utils.is_valid_str(context.strip()):
                message = _("Context name must be in the format of a valid string")
                logger.error(message)
                raise Exception(message)
            else:
                uri = self.uri + '/' + context

        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      sessionKey=self.session_key,
                                                      getargs={'output_mode': 'json'})
            if res.status == 200:
                content = json.loads(contents)
        except Exception as e:
            # catch all the exceptions within the manager class
            logger.exception(e)

        return content

    def create_mad_context(self, context):
        '''
        Create a new MAD Trending context

        @type context: basestring
        @param context: name of the new context

        @type return: boolean
        @param return: True if the context is created successfully

        '''
        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string")
            logger.error(message)
            raise Exception(message)

        if not context.strip():
            message = _("Missing context name, a context name is required to create new context")
            logger.error(message)
            raise Exception(message)

        if self.type == "trending":
            base_search_string = ITSI_AD_BASE_SEARCH
        elif self.type == "cohesive":
            base_search_string = ITSI_COHESIVE_AD_BASE_SEARCH
        else:
            # Not a supported AD type
            return False

        (host,port) = self._get_splunk_host_port()

        postargs = {
            'name': context,
            'output_dest': ITSI_AD_SUMMARY_INDEX,
            'search': base_search_string,
            'alert_url': ITSI_AD_EM_SPLUNKD_URI,
            'metric_limit_url': ITSI_ENTITY_LIMIT_ALERT_URI,
            'managed_saved_search': ITSI_AD_MANAGE_SEARCH
        }
        try:
            res, contents = splunk_rest.simpleRequest(self.uri ,
                                                      method='POST',
                                                      sessionKey=self.session_key,
                                                      postargs=postargs)
            return res.status == 200
        except Exception as e:
            logger.exception(e)
            return False

    def create_mad_instance(self, context, data):
        '''
        Create a MAD instance for a trending context
        @type context: basestring
        @param context: name of the context

        @type data: json dict.
        @param data: kpi id

        @type return: basestring
        @param return: instance id if creation is successful, otherwise None
        '''
        content = None
        if not utils.is_valid_str(context):
            message = _("context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not utils.is_valid_dict(data):
            message = _("Instance data must be in the format of a valid dictionary.")
            logger.error(message)
            raise Exception(message)

        if not context.strip() or not data:
            message = _("Must have context or instance data to create an instance")
            logger.error(message)
            raise Exception(message)

        # Default resolution time is set to 5m
        # since the default value of alert_period is also 5m
        uri = self.uri + '/' + context + '/instances'

        postargs = self.generate_instance_payload(data)

        res, contents = splunk_rest.simpleRequest(uri,
                                                  method='POST',
                                                  sessionKey=self.session_key,
                                                  postargs=postargs)
        if res.status == 200 or res.status == 201:
            content = json.loads(contents)
        return content.get('id')


    def delete_mad_context(self, context):
        '''
        Delete a MAD context

        @type context: basestring
        @param context: name of the context

        @type return: boolean
        @param return: True if the context is deleted successfully
        '''
        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not context.strip():
            message = _("Missing context name, a context name is required to delete a context.")
            logger.error(message)
            raise Exception(message)

        uri = self.uri + '/' + context
        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      method='DELETE',
                                                      sessionKey=self.session_key)
            return res.status == 200
        except Exception as e:
            logger.exception(e)
            return False

    def enable_mad_context(self, context, enable=True):
        '''
        Enable a MAD context
        @type context: basestring

        @param context: name of the context
        @type enable: boolean

        @param enable: if user wants to enable/disable the context
        @type return: boolean

        @param return: True if the context is enabled/disabled successfully
        '''

        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not context.strip():
            message = _("Missing context name, a context name is required to create new context.")
            logger.error(message)
            raise Exception(message)

        uri = self.uri + '/' + context
        toggle = 0 if enable else 1
        postargs = {
            'disabled': toggle
        }
        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      method='POST',
                                                      sessionKey=self.session_key,
                                                      postargs=postargs)

            return res.status == 200
        except Exception as e:
            logger.exception(e)
            return False

    def delete_mad_instance(self, context, instance_id):
        '''
        Delete instances of a particular context
        @type context: basestring
        @param context: name of the context

        @type instance_id: basestring
        @param instance_id: unique ID of the instance

        @type return: boolean
        @param return: True if delete is successful, False otherwise
        '''

        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string.")
            ogger.error(message)
            raise Exception(message)

        if not utils.is_valid_str(instance_id):
            message = _("Instance id must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not context.strip() or not instance_id:
            message = _("Must have context or instance id to delete an instance.")
            logger.error(message)
            raise Exception(message)

        uri = self.uri + '/' + context + '/instances/' + instance_id
        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      method='DELETE',
                                                      sessionKey=self.session_key)
            return res.status == 200
        except Exception as e:
            logger.exception(e)
            return False

    def get_mad_instances(self, context):
        '''
        Get instances of a particular context
        @type context: basestring
        @param context: name of the context

        @type return: list
        @param return: list of instances of this context
        '''

        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not context.strip():
            message = _("Must have context name to get the instance list.")
            logger.error(message)
            raise Exception(message)
        uri = self.uri + '/' + context + '/instances'

        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      method='GET',
                                                      sessionKey=self.session_key)
            if res.status == 200:
                return json.loads(contents)
        except Exception as e:
            logger.exception(e)
            return None

    def update_mad_instance(self, context, instance_id, data):
        '''
        Updated values of a particular MAD instance
        @type context: basestring
        @param context: name of the context

        @type instance_id: basestring
        @param instance_id: MAD instance unique id

        @type return: boolean
        @param return: True is update is successful, False otherwise
        '''
        if not utils.is_valid_str(context):
            message = _("Context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not utils.is_valid_str(instance_id) or not context.strip():
            message = _("Instance id must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)


        if not utils.is_valid_dict(data):
            message = _("Instance data must be in the format of a valid dictionary.")
            logger.error(message)
            raise Exception(message)

        uri = self.uri + '/' + context + '/instances/' + instance_id
        postargs = data
        try:
            res, contents = splunk_rest.simpleRequest(uri,
                                                      method='POST',
                                                      sessionKey=self.session_key,
                                                      postargs=postargs)
            return res.status == 200
        except Exception as e:
            logger.exception(e)
            return False

    def get_mad_instance_id_for_kpi(self, context, kpi_id, all_instance=None):
        """
        Get instances of a particular context based on an kpi id
        @type context: basestring
        @param context: name of the context

        @type kpi_id: basestring
        @param kpi_id: kpi unique id
        
        @type all_instance: list
        @param all_instance: list of instances present in kvstore

        @type return: basestring
        @param return: the corrsponding instance id based on the kpi id

        Mad does not limit the number of instances for each kpi, in theory
        user can create multiple instance for the same kpi.
        In ITSI context, we ensure that each kpi only has one instance,
        so the return of this method will only return on instance id.
        """
        if not utils.is_valid_str(context):
            message =_("Context name must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not utils.is_valid_str(kpi_id):
            message = _("kpi id must be in the format of a valid string.")
            logger.error(message)
            raise Exception(message)

        if not context.strip() or not kpi_id.strip():
            message = _("Must have context name or kpi_id to get the instance.")
            logger.error(message)
            raise Exception(message)

        instance_id = None
        if all_instance is None:
            all_instance = self.get_mad_instances(context)
        try:
            for instance in all_instance:
                if instance.get('selector', {}).get('filters', {}).get('itsi_kpi_id', '') == kpi_id:
                    instance_id = instance.get('id', '')
                    break
        except Exception as e:
            logger.exception(e)
            return None

        return instance_id

    def generate_instance_payload(self, data):
        """
        Generates instance payload from kpi information.
        
        @type data: dict
        @param data: dict containing kpi information for instance
        eg. dict =  {
                    'resolution': '5m',
                    'sensitivity': 8,
                    'filters': {'itsi_kpi_id': <kpi_id>, 'itsi_service_id': <service_id>}
                }
        
        @rtype: dict
        @return: payload for creating instance
        """

        if self.type == 'trending':
            selector_json = {
                        'type': 'simple_selector',
                        'value_key': 'alert_value',
                        'filters': data.get('filters', {})
                    }
        else:
            selector_json = {
                'type': 'simple_selector',
                'value_key': 'alert_value',
                'group_by': 'entity_id',
                'filters': data.get('filters', {})
            }

        post_args = {
                'resolution': data.get('resolution', '5m'),
                'type': self.type,
                'selector': json.dumps(selector_json),
                'disabled': 0,
                'sensitivity': data.get('sensitivity')
            }

        return post_args

    def create_bulk_mad_instances(self, data_list):
        """
        Creates instances in bulk using batch_save endpoint
        
        @type data_list: list of dict
        @param data_list: list of dict containing instance payload.
        eg. dict returned from generate_instance_payload() method.
                
        @return: contents returned by REST endpoint
        """

        if self.type == 'trending':
            uri = self.uri + '/' + ITSI_MAD_CONTEXT_NAME + '/instances' + '/bulk-create'
        else:
            uri = self.uri + '/' + ITSI_MAD_COHESIVE_CONTEXT_NAME + '/instances' + '/bulk-create'

        res, contents = splunk_rest.simpleRequest(uri,
                                                  method='POST',
                                                  sessionKey=self.session_key,
                                                  postargs={'data': json.dumps(data_list)},
                                                  timeout=300)
        if res.status in (200, 201):
            return json.loads(contents)
        else:
            return None
