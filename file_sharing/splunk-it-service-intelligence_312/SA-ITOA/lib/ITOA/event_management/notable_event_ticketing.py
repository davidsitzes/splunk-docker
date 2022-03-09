# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Use this module to update information on an ITSI Notable vis-a-vis its external
tickets.
"""

import re
import sys
import json
import time
from uuid import uuid1

import splunk.rest as splunk_rest
from splunk.util import safeURLQuote, normalizeBoolean
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n


from splunk import ResourceNotFound, RESTException
from ITOA.storage import itoa_storage
from notable_event_utils import Audit
from ITOA.itoa_common import JsonPathElement, get_itoa_logger

class ExternalTicket(object):
    """
    An instance of this class corresponds to an external ticket
    and is persisted in KV Store in the collection
    'itsi_notable_event_ticketing'
    An example of records is given further below. In the example below we see
    two records. Each record represents tickets in a specific external ticket
    system.

    ticket_system is also included in tickets because lookup cannot combine a multivalue
    fields with a single value

    ~~~~~~~~~~~~~~~~
    Example:
    ~~~~~~~~~~~~~~~~
    {
        event_id: 123,
        ticket_system: snow,
        tickets: [{
            ticket_id: <id>
            ticket_url: <some url>
            ticket_system: <system>
            <other params for this ticket>
        },{
            ticket_id: <id2>
            ticket_url: <some url>
            ticket_system: <system>
            <other params for this ticket>
        }]
    },
    {
        event_id: 124,
        ticket_system: remedy,
        tickets: [{
            ticket_id: <id>
            ticket_url: <some url>
            ticket_system: <system>
            <other params for this ticket>
        },{
            ticket_id: <id2>
            ticket_url: <some url>
            ticket_system: <system>
            <other params for this ticket>
        }]
    }
    """

    default_kv_collection = 'itsi_notable_event_ticketing'
    default_kv_ns = 'nobody'
    default_kv_app = 'SA-ITOA'
    default_token_name='Auto Generated ITSI Notable Index Audit Token'

    # keys in a record in our kv store collection
    KEY_TICKET_SYSTEM = 'ticket_system'  # jira, snow, siebel etc...
    KEY_TICKETS = 'tickets'  # all external tickets for this ticket_system
    KEY_TICKETS_TICKET_ID = 'ticket_id'  # external ticket id
    KEY_TICKETS_TICKET_URL = 'ticket_url'  # external ticket url
    KEY_OBJECT_TYPE = 'object_type'  # object type
    VAL_OBJECT_TYPE = 'external_ticket'  # value corresponding to the key above
    KEY_EVENT_ID = 'event_id'  # notable event id
    KEY_UID = '_key'  # unique id for this object in kv store
    KEY_TIME = 'mod_time' # time at which event was modified
    KEY_CREATE_TIME = 'create_time' # time at which event was created

    @staticmethod
    def get_auditor(session_key, token, host, source, sourcetype):
        """
        Returns an audit object
        @param session_key: splunk session key
        @param audit_token_name: token name for this auditor
        """
        return Audit(session_key, audit_token_name=token, audit_host=host, audit_source=source, audit_sourcetype=sourcetype)

    def __init__(self, event_id, session_key, logger,
                 collection=default_kv_collection, ns=default_kv_ns,
                 app=default_kv_app, audit_token_name=default_token_name,
                 **kwargs):
        """
        For a given notable id, this object corresponds to an external ticket
        @type event_id: basestring
        @param event_id: ITSI notable event id

        @type session_key: basestring
        @param session_key: splunkd session key

        @type logger: logger
        @param logger: caller's logger

        @type collection: basestring
        @param collection: kv store collection

        @type kwargs: dict
        @param kwargs: other
        """
        if not isinstance(event_id, basestring):
            raise TypeError(_('Invalid type `event_id`.'))
        if not event_id.strip():
            raise ValueError(_('Invalid value `event_id`.'))
        if not isinstance(session_key, basestring):
            raise TypeError(_('Invalid type `session_key`.'))
        if not session_key.strip():
            raise ValueError(_('Invalid value `session_key`.'))
        if not isinstance(collection, basestring):
            raise TypeError(_('Invalid type `collection`.'))
        if not collection.strip():
            raise ValueError(_('Invalid value `collection`.'))
        if not isinstance(ns, basestring):
            raise TypeError(_('Invalid type `ns`.'))
        if not ns.strip():
            raise ValueError(_('Invalid value `ns`.'))
        if not isinstance(app, basestring):
            raise TypeError(_('Invalid type `app`.'))
        if not app.strip():
            raise ValueError(_('Invalid value `app`.'))

        self.event_id = event_id
        self.session_key = session_key
        self.ns = ns
        self.app = app
        self.collection = collection
        self.object_type = ExternalTicket.VAL_OBJECT_TYPE
        self.storage_interface = itoa_storage.ITOAStorage(collection=collection)
        self.logger = logger
        self.auditor = ExternalTicket.get_auditor(
                session_key,
                audit_token_name,
                kwargs.get('audit_host'),
                kwargs.get('audit_source', 'Notable Event Audit'),
                kwargs.get('audit_sourcetype', 'stash')
        )

    @staticmethod
    def curate_search_prepend_command(prepend_command, ids, is_group, action_name, action_config, logger):
        """
        Given an input prepend command, curate it for ticketing.
        For actions on a notable event associated with an external ticket,
        we append the event id as a correlation id.
        When working on a notable event group, we ought to pass in the group_id as the
        correlation id.
        All actions, read event data from the `itsi_tracked_alerts` index
        regardless of whether it belongs to a group or not.
        Events in this index though, have no field to indicate a group id if
        applicable.

        This method will append an eval field to the existing prepend_command and
        make it more pertinent for a notable event group, so we assign group_id
        as correlation_id.

        Currently this method only does something if we are working on a group
        i.e. `is_group` is True.

        @type prepend_command: basestring
        @param prepend_command: existing prepend command.

        @type ids: list of event ids
        @param ids: event ids that were passed to us as input.

        @type is_group: boolean
        @param is_group: Indicates if we are working on a group.

        @type action_name: basestring
        @param action_name: name of the action that is being executed.

        @type action_config: dict
        @param action_config: configuration for this action. everything under
            the action's stanza in notable_event_actions.conf

        @type logger: logger
        @param logger: caller's logger
        """
        if not logger:
            logger = get_itoa_logger('itsi.notable_event.actions.ticketing', 'itsi_event_management.log')

        if not isinstance(prepend_command, basestring):
            message = _('Invalid type=`%s` for `%s`. Expecting string.') % (type(prepend_command).__name__, prepend_command)
            logger.exception(message)
            raise TypeError(message)

        if not isinstance(ids, list) or not ids:
            message = _('Invalid ids list. Received=`%s`. Type=`%s`.') % (ids, type(ids).__name__)
            logger.exception(message)
            raise TypeError(message)

        if not is_group:
            logger.info('No special curation of prepend_command=`%s` is required for regular notable events', prepend_command)
            return prepend_command

        group_captain_id = ids[0]   # when operating on more than one group,
                                    # we will use first id. Refresh should take care
                                    # updating others...

        # obtain value to append to search string as an eval. we want to append this
        # because sendalert should get a group_id to use as a correlation id
        correlation_value = action_config.get('correlation_value_for_group','') # `$result.itsi_group_id$`

        pattern = re.compile( 
            '^'                 # begin
            '(?:\$result.)'     # ignore group. our string begins with "$result."
            '([\\w-]*)'         # capture group
            '(?:\$)'            # ignore group. our string ends with `$`
            '$')                # end

        match = re.match(pattern, correlation_value)
        if not match:
            logger.error('Empty/missing correlation_value_for_group in your notable_event_actions.conf.')
            raise KeyError(_('Empty/missing correlation_value_for_group in your notable_event_actions.conf.'))
        
        eval_field = match.group(1) # we are guaranteed this group.

        prepend_command += ' | eval %s="%s"' % (eval_field, group_captain_id)

        return prepend_command

    @staticmethod
    def curate_params(params, action_name, action_config, logger, **kwargs):
        """
        Given params to a sendalert command, curate them. We will ensure that a
        correlation id parameter is always passed on with the command to splunk
        search.

        @type params: basestring
        @param params: already constructed params

        @type action_name: basestring
        @param action_name: the action that is being executed, i.e.
        snow_incident etc...

        @type action_config: dict
        @param action_config: the configuration of the action name, essentially
        everything under the action's stanza in notable_event_actions.conf

        @type logger: logger
        @param logger: caller's logger

        @rtype params: basestring 
        @return newly curated params consisting of the mandatory correlation id
            / value kv pair if it doesnt already exist.
        """
        if not logger:
            logger = get_itoa_logger('itsi.notable_event.actions.ticketing','itsi_event_management.log')

        if not isinstance(params, basestring):
            message = _('Expecting string type for params. Received=`%s`.') % type(params).__name__
            logger.exception(message)
            raise TypeError(message)

        is_group = kwargs.get('is_group', False)

        logger.debug('pre-curating params=`%s`\nis_group=`%s` action_name=`%s` action_config=`%s`', params,
                is_group, action_name, json.dumps(action_config))

        msg = _('Correlation id is mandated for operations pertaining to external ticket.')

        correlation_key = action_config.get('correlation_key') #`correlation_id` etc..

        if is_group:
            correlation_value = action_config.get('correlation_value_for_group') # `$result.itsi_group_id$`
        else:
            correlation_value = action_config.get('correlation_value') #`$result.event_id$` etc...

        if correlation_key is None or correlation_value is None:
            logger.error('%s. Missing `correlation_value`/`correlation_value_for_group`/`correlation_key`. Config="%s"',
                    msg, action_config)
            raise KeyError(msg)

        # we want to capture two potential groups and check if group(2) is
        # alright, i.e. not empty.
        # group 1 = param.correlation_id
        # group 2 = "$result.event_id$" (or $result.itsi_group_id$ for a group)
        # the rest of them need not be captured
        # if group 2 is empty i.e. "" then we will append event_id as correlation id,
        # else we will respect what is passed in to us.

        pattern = re.compile( 
            '^'                                                     # begin
            '(?:.*)'                                                # ignore group
            '(param.' + correlation_key + '=)(\"[a-zA-Z._$-]*\")'   # capture two groups
            '(?:.*)$')                                              # ignore the rest

        match = re.match(pattern, params)
        if match:
            logger.debug('params match found. groups=`%s`', match.groups())

        to_add = ' param.%s="%s"'%(correlation_key, correlation_value)
        logger.debug('params to_add=%s', to_add)

        # add correlation id k-v if there is no match
        if not match:
            logger.info('%s. None found or incorrect correlation_id kv. Will append `%s`. Config="%s"',
                msg, to_add, action_config)
            params += to_add
        else:
            # Replace incorrect correlation id kv with correct kv. Blindly appending
            # with param.correlation_id=blah (say) causes unpredictable results,
            # including refresh failure. TA_snow seems to randomly pick from
            # `param.correlation_id=blah` vs `param.correlation_id=""` when creating
            # an external ticket.
            if len(match.groups()) == 2 and match.group(2) =='""':
                logger.info('%s. Empty correlation_id kv found. Will replace'
                    ' with `%s` as correlation_id. Config=`%s`', msg, to_add, action_config)
                empty_correlation_kv = 'param.%s=""'%correlation_key
                params = params.replace(empty_correlation_kv, to_add)

        # NOTE: When operating on more than one Group, we cannot restrict the user
        # from overwriting correlation_value to something else. We advise an
        # end-user to not overwrite correlation_id value in the HTML modal.

        logger.debug('post-curating params=`%s`', params)
        return params

    @staticmethod
    def do_refresh(session_key, logger, event_action_data,
            event_action_executed_on_ids, action_config, ns='nobody', app='SA-ITOA'):
        """
        Assumes that an event action has already been executed on a list of
        events.
        Refreshes notable events with external ticket information.

        @type event_action_data: dict
        @param event_action_data: incoming data for executing action

        @type action_executed_on_ids: list
        @param action_executed_on_ids: ids on which action has been executed

        @type action_config: dict
        @param action_config: configuration for our action, key'ed by action
        name 

        @returns nothing.
        @raises TypeError on invalid input parameters
        """
        if not logger:
            logger = get_itoa_logger('itsi.notable_event.ticketing','itsi_event_management.log')

        action_name = event_action_data.get('name')
        if any([not isinstance(action_name, basestring),
            isinstance(action_name, basestring) and not action_name.strip()]):
            logger.error('Invalid action_name')
            raise TypeError(_('Invalid action_name'))

        refresh_event_ids = event_action_data.get('ids')
        if not refresh_event_ids:
            raise KeyError(_('Missing `ids` in data'))

        if not action_config:
            logger.error('No refresh config found for %s', action_name)
            raise KeyError(_('No refresh config found for %s.') % action_name)

        uri = action_config.get('relative_refresh_uri')
        if not isinstance(uri, basestring):
            logger.error('Expecting str for uri. Received=%s', type(uri).__name__)
            raise TypeError(_('Expecting str for uri. Received: %s.') % type(uri).__name__)

        # extract correlation id. w/o this our refresh is a no-go.
        query_param = action_config.get('correlation_key')

        getargs = {'output_mode': 'json'}

        event_id = event_action_executed_on_ids[0]
        if not query_param:
            # means our correlation id will not go as getargs but as part of the URL
            uri += '/' + event_id
        else:
            getargs[query_param] = event_id

        res, content = splunk_rest.simpleRequest(
                safeURLQuote(uri),
                sessionKey=session_key,
                getargs=getargs)

        if res.status!=200:
            logger.error('Failed to refresh notable event=%s\n'
                'uri=`%s`, getargs=`%s` response=`%s` content=`%s`',
                event_id, uri, getargs, res, content)
            raise Exception(_('Failed to refresh notable event=%s.') % event_id)

        content = json.loads(content)
        logger.info('uri=`%s` getargs=`%s` \n content=`%s`', uri, getargs, json.dumps(content))

        # Extract refresh data from response. For this we will first walk the
        # response content which is json.

        json_path = action_config.get('refresh_response_json_path')
        json_path = json_path.split('.')

        pertinent = content # content containing the refresh values that we care about.
        for e in json_path:
            path_elem = JsonPathElement(e)
            if not path_elem.is_array():
                pertinent = pertinent.get(str(path_elem))
            else:
                idx = path_elem.get_array_index()
                pertinent = pertinent[idx]
        logger.debug('refresh response config=`%s`', json.dumps(pertinent))

        # we have `pertinent` which should be the blob we care about...
        ticket_id_key = action_config.get('refresh_response_ticket_id_key')
        ticket_url_key = action_config.get('refresh_response_ticket_url_key')

        ticket_system = action_config.get('ticket_system_name')

        ticket_id = pertinent.get(ticket_id_key)
        ticket_url = pertinent.get(ticket_url_key)
        
        # we will always work with the assumption that there can be more than
        # one ticket ID/URL pair for a given Notable Event. BMC's Remedy
        # supports such a config. So, bottom line is, always work with a list.

        if isinstance(ticket_id, basestring):
            ticket_id = [ticket_id]
        if isinstance(ticket_url, basestring):
            ticket_url = [ticket_url]

        if not isinstance(ticket_id, list) or not isinstance(ticket_url, list):
            raise TypeError(_('Will only work with list of ticket id and url.'
                ' Received type id=%s url=%s') % (type(ticket_id).__name__,
                    type(ticket_url).__name__))

        logger.debug('Refreshing ids=%s\nticket id=%s ticket url=%s.',
                refresh_event_ids, ticket_id, ticket_url)

        for id_, url in zip(ticket_id, ticket_url):
            ExternalTicket.bulk_upsert(refresh_event_ids, ticket_system, id_,
                                       url, session_key, logger)
         
    def get(self, ticket_system=None):
        """
        Fetch ticket details for given `ticket_system`.
        Set `ticket_system` to None to get all tickets for this event.

        @type ticket_system: basestring
        @param ticket_system: concerned ticket system.
            Could be 'remedy', 'servicenow' or 'siebel' or 'jira' or 'bugzilla'

        @rtype: basestring
        @return: requested ticket info
        """
        query_op = "$and"
        query_val = []

        query_val.append({ExternalTicket.KEY_EVENT_ID: self.event_id})
        if ticket_system:
            self.logger.debug('Requested tickets for ticket_system=%s', ticket_system)
            query_val.append({ExternalTicket.KEY_TICKET_SYSTEM: ticket_system})

        query = {query_op: query_val}

        self.logger.debug('query=%s', json.dumps(query))

        result = self.storage_interface.get_all(self.session_key, self.ns,
                                                self.object_type, filter_data=query)
        self.logger.debug('Storage result get: %s', result)
        return result

    @staticmethod
    def bulk_upsert(event_ids, ticket_system, ticket_id, ticket_url, session_key,
            logger, **kwargs):
        """
        Do bulk upsert.
        @param ticket_system: external ticket system's identifier Ex: remedy
        @param ticket_id: external ticket's identifier
        @param ticket_url: external ticket's URL
        @param kwargs: extra key-value args to add as part of our update.
        @rtype: list
        @returns: result in the order of execution.
        """
        if not isinstance(event_ids, list):
            raise TypeError(_('Invalid type event_ids. Received=%s.') % type(event_ids).__name__)

        result = []
        activities = []
        activity = 'Linked with External Ticket System=`%s` Ticket ID=`%s` Ticket URL=`%s`' % (
                ticket_system, ticket_id, ticket_url)
        bulk_data = []
        for e in event_ids:
            obj = ExternalTicket(e, session_key, logger)
            r = obj.upsert(ticket_system, ticket_id, ticket_url, do_audit=False, **kwargs)
            result.extend(r)
            activities.append(activity)
            bulk_data.append({'event_id': e, 'ticket_system': ticket_system,
                'ticket_id': ticket_id, 'ticket_url': ticket_url})
        auditor = ExternalTicket.get_auditor(
                session_key,
                kwargs.get('audit_token_name', ExternalTicket.default_token_name),
                kwargs.get('audit_host'),
                kwargs.get('audit_source', 'Notable Event Audit'),
                kwargs.get('audit_sourcetype', 'stash')
        )
        auditor.send_activity_to_audit_bulk(bulk_data, activities, 'Linked External Ticket.')
        return result

    def upsert(self, ticket_system, ticket_id, ticket_url, do_audit=True, **kwargs):
        """
        Update event_id with external ticket information.

        @param ticket_system: external ticket system's identifier Ex: remedy
        @param ticket_id: external ticket's identifier
        @param ticket_url: external ticket's URL
        @param do_audit: activity will be passed to audit or not. defaults to True.
        @param kwargs: extra key-value args to add as part of our update.
        """
        # Validations
        if not isinstance(ticket_system, basestring):
            raise TypeError(_('Expecting ticket_system to be str type.'))
        if not ticket_system.strip():
            raise ValueError(_('Expecting ticket_system to be non-zero length str.'))
        if not isinstance(ticket_id, basestring):
            raise TypeError(_('Expecting ticket_id to be str type.'
                             ' Received={}.').format(type(ticket_id).__name__))
        if not ticket_id.strip():
            raise ValueError(_('Expecting ticket_id to be non-zero length str.'
                              ' Received={}.').format(ticket_id))

        # first fetch existing ticket entry for given ticket_system
        existing = self.get(ticket_system)
        record = json.loads(existing) if isinstance(existing, basestring) else existing

        if not record:
            # no existing ticket(s) for ticket_system
            record = {
                ExternalTicket.KEY_EVENT_ID: self.event_id,
                ExternalTicket.KEY_UID: str(uuid1()),
                ExternalTicket.KEY_TICKET_SYSTEM: ticket_system,
                ExternalTicket.KEY_TICKETS: [{
                    ExternalTicket.KEY_TICKET_SYSTEM: ticket_system,
                    ExternalTicket.KEY_TICKETS_TICKET_ID: ticket_id,
                    ExternalTicket.KEY_TICKETS_TICKET_URL: ticket_url
                }],
                ExternalTicket.KEY_OBJECT_TYPE: ExternalTicket.VAL_OBJECT_TYPE,
                ExternalTicket.KEY_TIME: time.time(),
                ExternalTicket.KEY_CREATE_TIME: time.time()
            }
            record[ExternalTicket.KEY_TICKETS][0].update(kwargs)
        else:
            if len(record) > 1:
                self.logger.warning(('Expecting only 1 record for an `event_id` + '
                                  '`ticket_system` combination. Received more. Will only work '
                                  'with the first event'))
            record = record[0]
            record[ExternalTicket.KEY_TIME] = time.time()
            # event_id has tickets for given 'ticket_system'
            tickets = record.get(ExternalTicket.KEY_TICKETS, [])
            ticket_exists = False
            for ticket in tickets:
                if ticket['ticket_id'] == ticket_id.strip():
                    ticket_exists = True
                    ticket[ExternalTicket.KEY_TICKETS_TICKET_URL] = ticket_url
                    ticket.update(kwargs)

            if not ticket_exists:
                # no such ticket exists
                ticket_val = {
                    ExternalTicket.KEY_TICKET_SYSTEM: ticket_system,
                    ExternalTicket.KEY_TICKETS_TICKET_ID: ticket_id,
                    ExternalTicket.KEY_TICKETS_TICKET_URL: ticket_url
                }
                ticket_val.update(kwargs)
                tickets.append(ticket_val)

        results = self.storage_interface.batch_save(self.session_key, self.ns, [record])
        if do_audit:
            activity = 'Linked with External Ticket System=%s Ticket ID=%s Ticket URL=%s' % (ticket_system, ticket_id, ticket_url)
            data = {'event_id': self.event_id, 'ticket_system': ticket_system, 'ticket_id': ticket_id, 'ticket_url': ticket_url}
            self.auditor.send_activity_to_audit(data, activity, 'Linked External Ticket.')
        return results

    @staticmethod
    def bulk_delete(event_ids, ticket_system, ticket_id, session_key, logger):
        """
        Do bulk delete.
        @param ticket_system: external ticket system's identifier Ex: remedy
        @param ticket_id: external ticket's identifier
        @param kwargs: extra key-value args to add as part of our update.
        @rtype: list
        @returns: result in the order of execution.
        """
        if not isinstance(event_ids, list):
            raise TypeError(_('Invalid type event_ids. Received=%s.') % type(event_ids).__name__)

        for e in event_ids:
            obj = ExternalTicket(e, session_key, logger)
            obj.delete(ticket_system, ticket_id)

    def delete(self, ticket_system=None, ticket_id=None):
        """
        Delete ticket corresponding to ticket system and ticket id
        /snow/123   delete ticket with id 123 of ticket system snow
        /snow       delete all tickets of snow
        /           delete all tickets for this event

        @param ticket_system: external ticket system's identifier Ex: remedy
        @param ticket_id: external ticket's identifier
        """
        query_op = "$and"
        query_val = []
        query_val.append({ExternalTicket.KEY_EVENT_ID: self.event_id})

        # if no ticket_system is passed delete all the tickets
        if not ticket_system:
            query = {query_op: query_val}
            result = self.storage_interface.delete_all(self.session_key, self.ns,
                                                self.object_type, query)
            self.logger.debug('Successfully deleted all tickets for event_id=%s', self.event_id)
            return

        # retrieve list for a given ticket system
        query_val.append({ExternalTicket.KEY_TICKET_SYSTEM: ticket_system})
        query = {query_op: query_val}

        # if ticket id is not passed delete all the tickets for the ticket system
        if not ticket_id:
            result = self.storage_interface.delete_all(self.session_key, self.ns,
                                        self.object_type, query)
            self.logger.debug('Successfully deleted all tickets for ticket_system=%s', ticket_system)
            return

        # if ticket_id is passed retrieve the list of tickets for a ticket system
        # iterate through list for a ticket id and delete
        result = self.storage_interface.get_all(self.session_key, self.ns,
                                                    self.object_type, filter_data=query)
        if isinstance(result, basestring):
            result = json.loads(result)
        if len(result) == 0:
            self.logger.error('Could not find ticket system. ticket_system=%s', ticket_system)
            raise ValueError(_('Delete failed. Ticket system does not exist or has been deleted already.'))

        record = result[0]
        tickets = record.get(ExternalTicket.KEY_TICKETS, [])

        number_of_tickets = len(tickets)
        if number_of_tickets == 0:
            self.logger.error('Could not find ticket. ticket_id=%s ', ticket_id)
            raise ValueError(_('Delete failed. Ticket does not exist or has been deleted already.'))

        # searching for the ticket in the tickets list by passed in ticket id
        ticket_exists = False
        for ticket in tickets:
            if ticket['ticket_id'] == ticket_id.strip():
                # found ticket. Need to remove ticket from tickets list
                ticket_exists = True
                tickets.remove(ticket)
                self.logger.debug('Deleting. ticket_id=%s details=%s ',
                         ticket_id, json.dumps(ticket))

        if not ticket_exists:
            self.logger.error('Could not find ticket. ticket_id=%s ', ticket_id)
            raise ValueError(_('Delete failed. Unable to find ticket with id {}.').format(ticket_id))

        # if there is only one ticket for a ticket system delete the entire ticket system
        if number_of_tickets == 1:
            self.logger.debug(('Successfully deleted single ticket with ticket_id=%s') % ticket_id)
            result = self.storage_interface.delete(self.session_key, self.ns,
                                                self.object_type, record.get(ExternalTicket.KEY_UID))
            return

        # if there are more than one tickets
        # update the record with updated ticket array
        record[ExternalTicket.KEY_TICKETS] = tickets
        self.storage_interface.batch_save(self.session_key, self.ns,
                                          result)
        self.logger.debug('Successfully deleted ticket_id=%s record=%s' , ticket_id, record)
