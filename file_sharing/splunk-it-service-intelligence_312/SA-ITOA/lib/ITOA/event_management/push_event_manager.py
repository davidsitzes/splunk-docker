# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import urllib
import splunk.rest as rest
from splunk.appserver.mrsparkle.lib import i18n
import time as time_import

import splunk
from splunk.util import normalizeBoolean

from SA_ITOA_app_common.solnlib.modular_input import event_writer


def get_hec_token(session_key, token_name):
    """
    This method sends a rest request to the data enpoint
    to get the hec_token to be used by the HEC event writer

    @type session_key: basestring
    @param session_key: the session key

    @type token_name: basestring
    @param token_name: token_name

    @rtype: basestring
    @return: the HEC token
    """
    encoded_token_name = urllib.quote(token_name)
    resp, content = rest.simpleRequest('/servicesNS/nobody/SA-ITOA/data/inputs/http/' + encoded_token_name,
                                       getargs={"output_mode": "json"},
                                       sessionKey=session_key)
    if resp.status != 200:
        raise Exception(_('Unable to reach the data inputs enpoint, failed with status code="{0}".').format(resp.status))
    content = json.loads(content)
    if 'entry' not in content or not len(content['entry']):
        raise Exception(_('Could not find token value in response from server for token name="{0}".').format(token_name))
    content = content['entry'][0]['content']
    return content.get('token', None)


def get_hec_uri(session_key):
    """
    Gets the URI with which to communicate with HEC

    @type session_key: basestring
    @param session_key: the session key

    @rtype: object
    @return: the data to be used for the HEC event writer
    """
    resp, content = rest.simpleRequest('/servicesNS/nobody/SA-ITOA/data/inputs/http/http',
                                       getargs={"output_mode": "json"},
                                       sessionKey=session_key)
    if resp.status != 200:
        raise Exception(_('Unable to reach the data inputs endpoint, failed with status code="{0}"').format(resp.status))
    content = json.loads(content)
    if 'entry' not in content or not len(content['entry']):
        # We return default values if we don't have a proper data format
        content = {
            'host': 'localhost',
            'port': '8088',
            'enableSSL': '1'
        }
    else:
        content = content['entry'][0]['content']
    # Fun Fact! the host value from http configuration is often unresolvable, the accepted method is to always use the
    # splunkd management host (typically 127.0.0.1) for all HEC operations
    host = splunk.getDefault('host')
    port = content.get('port', '8088')
    enable_ssl = normalizeBoolean(content.get('enableSSL', '1'))
    scheme = 'https' if enable_ssl else 'http'

    return scheme + '://' + host + ':' + port


class PushEventManager(object):
    """
    Push Event to any index using http listener. As part of instance creation
    it enable Http Listener if it is disabled and acquire token for given name and settings
    Use push_event function to push event to given index
    """

    def __init__(self, session_key, token_name, hec_token=None, hec_uri=None):
        """
        Initialize token settings

        @type token_name: basestring
        @param token_name: token_name

        @type hec_token: basestring
        @param hec_token: the hec token to use to communicate with HEC, if unprovided it will be fetched via REST

        @type hec_uri: basestring
        @param hec_uri: the uri to use to communicate with HEC, if unprovided it will be fetched via REST

        @rtype: object
        @return:
        """
        if not hec_uri:
            hec_uri = get_hec_uri(session_key)
        if not hec_token:
            hec_token = get_hec_token(session_key, token_name)
        splunkd_host = splunk.getDefault('host')
        splunkd_port = splunk.getDefault('port')
        splunkd_scheme = splunk.getDefault('protocol')
        # Passing in the hec and splunkd information prevents the doing of unncessary requests/subprocesses
        self.push_event_object = event_writer.HECEventWriter(token_name, session_key, scheme=splunkd_scheme,
                                                             host=splunkd_host, port=splunkd_port, hec_uri=hec_uri,
                                                             hec_token=hec_token)

    def get_events_to_push(self, events, time, source, sourcetype, host, index):
        """
        Given a list of raw events and indexing specific details, return a list
        that can further be fed to the HTTP Event Collector.
        See: http://dev.splunk.com/view/event-collector/SP-CAAAE6M

        @type self: PushEventManager

        @param events: list of raw event dictionaries
        @type events: list of dict
        @param time: event time
        @param source: event source
        @param sourcetype: event sourcetype
        @param host: event host
        @param index: index to write to

        @return a dictionary that the HEC understands
        """
        if not isinstance(events, list):
            raise TypeError(_('`events` is not a valid list. Received type=`%s`.') % type(events).__name__)

        # remove keys pre-hec. w/o this we generate multi-valued fields for keys
        # which craps out the rules engine grouping algorithm.

        prepped = []
        pop_keys = ('source', 'sourcetype', '_time', 'host', 'index')
        for ev in events:
            ev_time = ev.get('_time', time)
            if not ev_time:
                ev_time = time_import.time()
            for k in pop_keys:
                ev.pop(k, None)
            prepped.append(self.push_event_object.create_event(ev, float(ev_time), index, host, source, sourcetype))
        return prepped

    def push_event(self, event, time=None, source=None, sourcetype=None, host=None, index=None):
        """
        Push event to index

        @type self: PushEventManager

        @type event: dict
        @param event: even to push

            ideally consumer of this function should pass event
            with time, host, source and sourcetype. Beside this 'event'
            must in the json form
            for example:
            {
                time: <epoch time>,
                host: <host>, source:<source>,
                sourcetype:<sourcetype>,
                event: <json event>
            }
            See:
            http://dev.splunk.com/view/event-collector/SP-CAAAE6M

        NOTE:
        ++++++++++++++
        if host, source or sourcetype is not assigned then default values is being used which is
        assigned to token
        if time is not specified then index time would be event time
        ++++++++++++++

        @param time: event time
        @param source: event source
        @param sourcetype: event sourcetype
        @param host: event host
        @param index: index to write to
        @return: tuple (response, content)
        """
        events_to_push = self.get_events_to_push([event], time, source, sourcetype, host, index)
        return self.push_event_object.write_events(events_to_push)

    def push_events(self, events, source=None, sourcetype=None, host=None, index=None):
        """
        Push events to index.

        @type self: PushEventManager

        @type events: list
        @param events: events to push

            ideally consumer of this function should pass each event
            with time, host, source and sourcetype. Beside this 'event'
            must in the json form
            for example:
            {
                time: <epoch time>,
                host: <host>, source:<source>,
                sourcetype:<sourcetype>,
                event: <json event>
            }
            See:
            http://dev.splunk.com/view/event-collector/SP-CAAAE6M

        NOTE:
        ++++++++++++++
        - if host, source or sourcetype is not assigned then default
            values is being used which is assigned to token
        - We expect each event to have its own _time set here.
        ++++++++++++++

        @param source: event source
        @param sourcetype: event sourcetype
        @param host: event host
        @param index: index to write to
        @return: tuple (response, content)
        """
        events_to_push = self.get_events_to_push(events, None, source, sourcetype, host, index)
        return self.push_event_object.write_events(events_to_push)
