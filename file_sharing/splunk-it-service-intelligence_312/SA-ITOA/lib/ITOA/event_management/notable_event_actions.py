# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This module deals with Notable Event Actions.
Examples of a Notable Event Action are: `ping host` or `send email`
"""

import json

import splunk.rest as splunk_rest
import splunk.search as splunk_search
from splunk import ResourceNotFound
from splunk.util import safeURLQuote, normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n

from ITOA.event_management.notable_event_utils import NotableEventActionException
from ITOA.itoa_common import get_conf
from ITOA.setup_logging import setup_logging
from base_event_management import time_function_call
from notable_event_ticketing import ExternalTicket
from notable_event_utils import Audit

ACTION_TYPE_MANIFEST = {
        'external_ticket' : ExternalTicket
        }


class NotableEventAction(object):
    """
    Represents a Notable Event Action
    """

    BATCH_SIZE = 250 # update 250 events at a time

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None,
                 audit_token_name='Auto Generated ITSI Notable Index Audit Token', **kwargs):
        """
        Notable event actions to be perform

        @type session_key: basestring
        @param session_key: session key

        @type app: basestring or str
        @param app: app name

        @type owner: basestring or str
        @param owner: owner name

        @type logger: object
        @param logger: logger

        @type audit_token_name: basestring
        @param audit_token_name: audit token name

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: instance of class
        @return: object
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.conf_file_name = 'notable_event_actions'

        if logger is None:
            self.logger = setup_logging('itsi_event_management.log',
                    'itsi.notable_event.actions')
        else:
            self.logger = logger

        # Dict which hold configuration
        self.configuration = self.get_configuration()

        # Dict which hold all accessible actions
        self.all_actions = self.get_all_actions()
        self.audit = Audit(self.session_key, audit_token_name=audit_token_name,
                           audit_host=kwargs.get('audit_host'),
                           audit_source=kwargs.get('audit_source', 'Notable Event Audit'),
                           audit_sourcetype=kwargs.get('audit_sourcetype', 'stash'))

    def get_configuration(self):
        """
        Get configured notable event actions

        @rtype: dict
        @return: notable event actions, key'ed by action name, value is a blob
        """
        rval = get_conf(self.session_key, self.conf_file_name, search='disabled=0', count=-1, app=self.app)

        response = rval.get('response')

        if response.status != 200:
            self.logger.error('Failed to fetch configuration file=`%s`, rval=`%s`',
                self.conf_file_name, rval)
            raise NotableEventActionException(_('Failed to fetch data using url=`%s`.') % self.conf_file_name)

        content = rval.get('content')
        content = json.loads(content)

        configuration = {}

        for entry in content.get('entry', []):
            configuration[entry.get('name')] = entry.get('content', {})

        return configuration

    def get_actions(self):
        """
        Get actions

        @rtype: dict
        @return: list of action which user can perform on notable
        """
        return self._get_available_action()

    def get_action(self, action_name):
        """
        Get any given action
        @type action_name - action name
        @param action_name - action name

        @return: dict - Action information
        """
        if action_name is None:
            message = _("Invalid action name")
            self.logger.error(message)
            raise ValueError(message)
        if action_name not in self.all_actions:
            self.logger.error("Action does not exist for this user")
            raise ResourceNotFound(_("Action {0} does not exist for this user {1}.").format(action_name, self.owner))

        return self.all_actions.get(action_name)

    def _get_available_action(self):
        """
        Compare action list against accessible actions for the app
        @rtype: list
        @return: notable actions to perform
        """
        action_list = self.configuration.keys()

        # Check actions are valid in alert_actions.conf
        valid_actions = self._is_valid_actions(action_list)

        # Decorate the configuration from notable_event_actions.conf into the valid actions
        for action in valid_actions:
            action['is_group_compatible'] = self.configuration[action['action_name']].get('is_group_compatible', 0)
            action['is_bulk_compatible'] = self.configuration[action['action_name']].get('is_bulk_compatible', 0)
            action['execute_once_per_group'] = self.configuration[action['action_name']].get('execute_once_per_group',
                                                                                             0)
            action['execute_in_sync'] = self.configuration[action['action_name']].get('execute_in_sync',
                                                                                      0)

        return valid_actions

    def _is_valid_actions(self, actions_list):
        """
        Check if give action is accessible by this app and is a valid action

        return valid action only

        @type actions_list: list
        @param actions_list: actions list to compare against accessible actions

        @rtype: list of dict
        @return: return valid action list where each item contain action_name, label
        """
        valid_actions = []
        for action in actions_list:
            if action in self.all_actions:
                valid_actions.append({'action_name': action,
                                      'label': self.all_actions.get(action, {}).get('label', action)})
            else:
                self.logger.warning('Provided action=%s is not a valid action or does'
                                    'not have valid action', action)
        return valid_actions

    def get_all_actions(self, is_get_full_email=False):
        """
        Get all accessible custom modular alerts

        @type is_get_full_email: basestring
        @param is_get_full_email - flag to pull full email content

        @rtype: dict
        @return: return valid accessible objects
        """
        uri_string = '/servicesNS/' + self.owner + '/' + self.app + '/alerts/alert_actions'
        if is_get_full_email:
            uri_string += '/email'

        uri = safeURLQuote(uri_string)
        res, contents = splunk_rest.simpleRequest(uri, getargs={'output_mode': 'json','count': '-1'},
                                                  sessionKey=self.session_key)
        actions = {}
        if res.status == 200:
            json_contents = json.loads(contents)
            for entry in json_contents.get('entry', []):
                if entry.get('name') not in actions:
                    actions[entry.get('name')] = entry.get('content')
        else:
            self.logger.error('Failed to get all accessible notable events, uri=%s, response="%s", content="%s"',
                              uri, res, contents)

        # Overload  the email action with things we can actually pass to the sendemail search command
        if not is_get_full_email and 'email' in actions:
            actions['email'] = {
                'label': 'Send email',
                'content_type': '',
                'to': '',
                'cc': '',
                'bcc': '',
                'priority': '',
                'subject': '',
                'message': ''
            }
        self.logger.debug('All actions: %s', actions.keys())

        return actions

    def get_command_params(self, action_name, data, is_group=False):
        """
        Applicable only to sendalert/sendemail

        Given input data, extract command parameters for given action_name.
        @type action_name: str
        @param action_name: action name you wish to execute

        @type data: basestring
        @param data: given input data
        """
        # TODO ITOA-5104: modularize this method. It's really big.

        action_content = self.all_actions.get(action_name)
        self.logger.debug('action_content=`%s`\ndata=`%s`', action_content, data)
        params = ''
        field_prefix = 'action'

        if isinstance(data, basestring):
            data = json.loads(data)
        if not isinstance(data, dict):
            raise TypeError(_('Expecting a valid dict for data. Received=%s. Type=%s.') % (data,
                type(data).__name__))

        # first work on action_content. this is the set of key/values we are
        # working with from the alert_actions endpoint.
        long_prefix = field_prefix + '.' + action_name
        for key in action_content.iterkeys():
            short_field_name = field_prefix + '.' + key
            full_field_name = long_prefix + '.' + key
            # data either contain full name or only field name,we support for both
            if full_field_name in data:
                params += ' %s="%s"' % (key, str(data[full_field_name]).replace('"', '\\"'))
            elif short_field_name in data:
                params += ' %s="%s"' % (key, str(data[short_field_name]).replace('"', '\\"'))
            elif key in data:
                params += ' %s="%s"' % (key, str(data[key]).replace('"', '\\"'))
            else:
                self.logger.debug('Either %s is not a valid field or does not exist in the request', key)

        # finally we could also have alert params sitting inside the data
        # this is entirely dependent on how the alert action is defined.
        # i.e parameters are mentioned in <alert_action>.conf.spec file or the
        # conf file i.e. <alert_action>.conf
        for key in data.iterkeys():
            if key is None:
                continue
            short_key = key
            if key.startswith(long_prefix):
                short_key = key[len(long_prefix)+1:]  # remove . too
            elif key.startswith(field_prefix):
                short_key = key[len(field_prefix)+1:]  # remove . too
            # Make sure we did not add key earlier
            if short_key in action_content or key in action_content:
                continue
            params += ' %s="%s"'%(short_key, str(data[key]).replace('"', '\\"'))

        # certain actions viz, those corresponding to the creation/updating of an external
        # ticket mandate us to work with a correlation id being passed in along
        # with other parameters. Enforce the same here. If none is given or if
        # correlation id value is an empty string, we will append
        # $result.event_id$ as correlation id

        action_config = self.configuration.get(action_name, {})
        action_type = action_config.get('type', '')
        if action_type == 'external_ticket' and action_type in ACTION_TYPE_MANIFEST:
            obj = ACTION_TYPE_MANIFEST[action_type]
            params = obj.curate_params(params, action_name, action_config,
                    self.logger, is_group=is_group)
        self.logger.debug('action params for command=%s', params)
        return params

    def execute_actions(self, data):
        """
        Execute one or more action or actions
        @type data - dict or list (when data is list then action is executed in bulk)
        @param data: data
                data - when it is list then more than one event action is being perform
                data - is dict then only one action is being performed
                data structure would looks like this
                    ids : [] -> list of events or group ids
                    name:  -> action name
                    params: key:value pair for action parameters
                    _is_sync: bool to check if action is sync or async
                    _is_group: bool to check if action is being perform on group or not
                    _group_data: list if event ids where action is perform if list is
                        empty then action is being done on all events of the group
                    earliest_time - earliest time
                    latest_time - latest time

        @return: list of dict
                    [{
                        sid: search id
                        ids: [] list of events or group id where action is being perform
                        action_name: name of action which is being performed
                    }...]
        """
        if not (isinstance(data, dict) or isinstance(data, list)):
            self.logger.error("Invalid data %s", data)
            raise NotableEventActionException(_("Invalid data so can't perform actions."))

        action_info = []
        if isinstance(data, dict):
            data = [data]
        for action_data in data:
            action_info.extend(self._parse_and_call_execute_action(action_data))
        return action_info

    def should_execute_once_per_group(self, action_config):
        """
        For action on bulk events, given an action config should we execute
        only once per group? Or should be execute once each for an event in a
        group?

        @type action_config: dict
        @param action_config: values under a stanza in
            notable_event_actions.conf.

        @rtype: boolean
        @return: return True or False depending on what the config has.

        @raises TypeError when invalid type for input parameter.
        """
        if not isinstance(action_config, dict):
            raise TypeError(_('action_config invalid type. Received=%s') % type(action_config).__name__)

        self.logger.debug('Received config=%s', action_config)

        if 'execute_once_per_group' not in action_config:
            self.logger.debug('`execute_once_per_group` not found.'
                ' Defaulting to True. Implies execute once for a group')
            return True

        return normalizeBoolean(action_config['execute_once_per_group'])

    def get_event_ids(self, data):
        """
        Return event ids to work on. We will either work on all event ids
        specified or the first event id depending on conf setting.

        @type data: dict
        @param data: incoming data for this action

        @rtype: (list, list)
        @return: (list of ids to operate on, list of additional ids to track but not operate on)

        @raises NotableEventActionException on bad request.
        """
        action_name = data.get('name')
        action_config = self.configuration.get(action_name)
        if action_config is None:
            message = _('`%s` must have some configuration. Received None') % action_name
            self.logger.error(message)
            raise NotableEventActionException(message)

        execute_once = self.should_execute_once_per_group(action_config)
        self.logger.debug('Execute once=%s', execute_once)

        received_ids = data.get('ids')
        self.logger.debug('Received event_ids=%s Type=%s', received_ids,
            type(received_ids).__name__)

        ###############
        # WARNING: The order of the following `if` statements is important. Do not change it.
        # Though I can combine them as an OR `if`, I want the appropriate log statement.
        # I wish Python had a switch case like in C/C++.
        ###############
        if normalizeBoolean(data.get('_is_group', False)):
            self.logger.info('is_group=True. Will always execute once=%s. action_name=`%s` '
                    'received=`%s` chosen itsi_group_id=`%s`', execute_once, action_name, received_ids, received_ids[0])
            return [received_ids[0]], []

        if execute_once:
            self.logger.info('execute_once=True action_name=`%s` '
                'received=`%s` chosen event_id=`%s`', action_name, received_ids, received_ids[0])
            return [received_ids[0]], received_ids[1:]

        return received_ids, []

    def should_execute_in_sync(self, data):
        """
        Should action be executed in sync?
        We will always use the value in the action's conf file
        if `execute_in_sync` is present we will abide, else we will abide by the
            request issued to us by the UI. i.e. data.get('_is_sync', False)
            If no '_is_sync' is found in the request, we will default to `False`

        @type data: dict
        @param data: incoming data for action.

        @rtype: bool
        @return True if certain criterion are met. False otherwise.

        @raises TypeError if invalid incoming param
        """
        if not isinstance(data, dict):
            self.logger.error('Invalid data %s', data)
            raise TypeError(_("Invalid data."))

        action_name = data.get('name')

        if any([not isinstance(action_name, basestring),
            isinstance(action_name, basestring) and not action_name.strip()]):
            message = _('Invalid action_name %s') % action_name
            self.logger.error(message)
            raise TypeError(message)

        action_config = self.configuration.get(action_name)

        if not action_config:
            message = _('%s does not have any config') % action_name
            self.logger.error(message)
            raise NotableEventActionException(message)

        self.logger.debug('action name=%s config=%s', action_name, action_config)

        in_sync = normalizeBoolean(action_config.get('execute_in_sync', data.get('_is_sync', False)))
        self.logger.debug('should execute in sync=%s', in_sync)

        return in_sync

    def refresh_notable(self, data, action_executed_on_ids):
        """
        Refresh given notables if applicable.
        @type action_executed_on_ids: list
        @param action_executed_on_ids: list of ids on which this action has been
            executed on.

        @type data: dict
        @param data: incoming data

        @returns nothing
        """
        if not isinstance(data, dict):
            self.logger.error('Invalid data=%s', data)
            raise TypeError(_('Invalid data for refresh.'))
        if not isinstance(action_executed_on_ids, list):
            self.logger.error('Invalid list of ids=%s', action_executed_on_ids)
            raise TypeError(_('Invalid list of ids for refresh.'))

        action_name = data.get('name')
        action_config = self.configuration.get(action_name)

        # Refresh is applicable only if there is a key `type` in your stanza
        # and whose value value exists in `ACTION_TYPE_MANIFEST`
        # Ex: In notable_event_actions.conf:
        #   [snow_incident]
        #   ...
        #   type = external_ticket
        #   ...
        #   and here `external_ticket` exists in our ACTION_TYPE_MANIFEST
        if 'type' not in action_config or action_config.get('type') not in ACTION_TYPE_MANIFEST:
            self.logger.info('Refresh is not applicable for `%s`.', action_name)
            return

        self.logger.info('Refreshing notable events=`%s`.', data.get('ids', []))
        obj_type = ACTION_TYPE_MANIFEST[action_config['type']]
        obj_type.do_refresh(self.session_key, self.logger, data,
                action_executed_on_ids, action_config)
        self.logger.info('Refresh completed. Action executed on=`%s`. Refreshed=`%s`',
                action_executed_on_ids, data.get('ids', []))

    def _parse_and_call_execute_action(self, data):
        """
        Parse and execute actions
        @param data: data which hold action information for schema please refer execute_actions
            data structure would looks like this
                ids : list of events or group ids
                name: string action name
                params: dict key/value pair for action parameters
                _is_sync: bool to check if action is sync or async
                _is_group: bool to check if action is being perform on group or not
                _group_data: list if event ids where action is perform if list is
                    empty then action is being done on all events of the group
                earliest_time - earliest time
                latest_time - latest time
        @return: list of executed actions
        """
        if not isinstance(data, dict):
            self.logger.error("Invalid data %s", data)
            raise NotableEventActionException(_("Invalid data so can't perform actions."))

        action_name = data.get('name')
        params = data.get('params', {})
        if isinstance(params, basestring):
            params = json.loads(params)
        ids, additional_ids = self.get_event_ids(data)
        is_sync = self.should_execute_in_sync(data)

        # Allow action on group events instead of single notable events
        # When group flag is set then it event_id is actually a group id
        is_group = normalizeBoolean(data.get('_is_group'), False)

        # If user want to perform operation on limit events from group then
        # he can specify those ids in _group_action. Here
        #    _group_data = {
        #            event_ids: [event1, event2] so on .. /
        #    }
        #    Note - do not set group data if you want to run action on all events of group

        group_data = data.get('_group_data', {})

        result = self._execute_action_in_batch(action_name, ids, params, is_sync, is_group, group_data,
                                               data.get('earliest_time'), data.get('latest_time'), additional_ids)

        self.refresh_notable(data, ids)

        return result

    def _execute_action_in_batch(self, action_name, ids, params, is_sync, is_group, group_data, earliest_time=None,
                                 latest_time=None, additional_ids=None):
        """
        Execute action in batch. Some actions will be executed once per
        event_id, while others will be executed once for the group. This is very
        specific to the action type.

        @type action_name: basestring
        @param action_name: action name

        @type ids: list of event or group id where action is being performed
        @param ids: list of ids where action is being formed

        @type: params: dict
        @param params: action parameters

        @type is_sync: bool
        @param is_sync: set to true, search which execute this search need to wait for completion

        @type is_group: bool
        @param is_group: set to true when action is being form on group

        @type group_data: dict or None
        @param group_data: when is_group flag is set then user can pass event id in this dict. When is_group
                is set to true with no group_action_data then action is being perform on all event from group
                group_data should have either of those
                    event_ids - list of ids
                    filter_search - filter search

        @type earliest_time: basestring
        @param earliest_time: earliest time

        @type latest_time: basestring
        @param latest_time: latest time

        @type additional_ids: list of ids of related events
        @param additional_ids: list of ids of related events that are part of the bulk action, but not the main id of the action

        @return: dict
            { 'sid' : <search id>, 'ids': [], 'action_name': '' }
        """
        # validate ids
        if not isinstance(ids, list) or len(ids) < 1:
            msg = _('Invalid ids={0} to perform action. List must have at-least'
            'one action to perform action.').format(ids)
            self.logger.error(msg)
            raise NotableEventActionException(msg)

        # perform action in batch if ids are more than a given limit
        index = 0
        execute_action_info = []

        filter_search = None
        # if action is perform on whole group with specific ids then we directly fetch ids
        if is_group and isinstance(group_data, dict):
            if isinstance(group_data.get('event_ids'), list) and len(group_data.get('event_ids')) > 0:
                # Directly perform action on events instead of group
                ids = group_data.get('event_ids')
                is_group = False
            if group_data.get('filter_search') and isinstance(group_data.get('filter_search'), basestring):
                filter_search = group_data.get('filter_search')

        while index < len(ids):
            batch_size = self.BATCH_SIZE if len(ids) > index + self.BATCH_SIZE else len(ids) - index
            batch = ids[index: batch_size]
            sid = self.execute_action(action_name, batch, params, is_sync, is_group, filter_search, earliest_time,
                                      latest_time, additional_ids)
            self.logger.debug('Successfully created sid=%s for action=%s, ids=%s', sid, action_name, ids)
            execute_action_info.append({
                'sid': sid,
                'ids': batch,
                'action_name': action_name
            })
            index += batch_size
        return execute_action_info

    def curate_default_prepend_command(self, prepend_command, ids, is_group, action_name):
        """
        For certain action types, we need to curate the prepend_command. See
        specific implementations for more details.

        @type prepend_command: basestring
        @param prepend_command: prepend_command so far

        @type ids: list
        @param ids: event ids we are working on

        @type is_group: boolean
        @param is_group: indicates if we are working on a Notable Event group

        @type action_name: basestring
        @param action_name: name of the action being executed

        @rtype: basestring
        @return: curated default prepand command for given action
        """
        action_config = self.configuration.get(action_name, {})
        action_type = action_config.get('type', '')
        if action_type not in ACTION_TYPE_MANIFEST:
            self.logger.debug('No curation required. Command=`%s` action_type=`%s` action_name=`%s`', prepend_command,
                action_type, action_name)
            return prepend_command

        self.logger.debug('pre-curate action_type=`%s` action_name=`%s` default_prepend_command=`%s`',
            action_type, action_name, prepend_command)

        obj = ACTION_TYPE_MANIFEST.get(action_type)
        try:
            prepend_command = obj.curate_search_prepend_command(
                prepend_command,
                ids,
                is_group,
                action_name,
                action_config,
                self.logger
            )
        except AttributeError:
            self.logger.warning('Attribute error: `curate_search_prepend_command` for `%s`. Will pass.', str(obj))

        self.logger.debug('post-curate default_prepend_command=`%s`', prepend_command)

        return prepend_command

    def get_default_prepend_command(self, ids, action_name, is_group=False, filter_search=None):
        """
        get the default prepend command for given ids and action name

        @type ids: list
        @param ids: event or group id of notable events

        @type action_name: basestring
        @param action_name: name of the action that is being executed

        @type is_group: bool
        @param is_group: set to true when action is being done on a group.

        @type filter_search: basestring
        @param filter_search: a search to filter events

        @rtype: basestring
        @return: the default prepend command
        """
        if not isinstance(ids, list) or not ids:
            message = _('Invalid ids. Expecting valid list. Received=`%s`.') % ids
            self.logger.error(message)
            raise TypeError(message)

        group_filter_command = ''
        event_filter_command = ''
        if is_group and filter_search:
            # Filter has to be done on event index
            event_filter_command += filter_search

        for eid in ids:
            if is_group:
                group_filter_command += ' itsi_group_id="%s" OR' % eid
            else:
                event_filter_command += ' event_id="%s" OR' % eid

        # Remove the trailing `OR` that we blindly appended earlier.
        group_filter_command = group_filter_command.rstrip('OR')
        event_filter_command = event_filter_command.rstrip('OR')

        group_filter = ''
        if is_group:
            # append sub-search which fetches event_ids from group index.
            group_filter = '[ search `itsi_event_management_group_index` {0} | table event_id ]'.format(group_filter_command)

        prepend_command = 'search `itsi_event_management_index_with_state("{0} {1}")`'.format(event_filter_command, group_filter)

        return self.curate_default_prepend_command(prepend_command, ids, is_group, action_name)

    def get_alert_command(self, action_name, action_data):
        """
        Get the appropriate alert command to execute an action.
        i.e. sendalert et al.

        @type action_name: basestring
        @param action_name: the name of the action to execute

        @type action_data: dict
        @param action_data: data sent with the action, presumably the parameters

        @rtype: basestring
        @return: the alert command
        """
        action_content = self.all_actions.get(action_name)

        if action_name == 'email':
            alert_command = 'sendemail'
        elif action_name == 'script':
            alert_command = action_content.get('command')
            # file name token replacement
            if 'filename' not in action_data and 'action.script.filename' not in action_data:
                self.logger.error('file name is required to run a script')
                raise ValueError(_('Filename is missing in the request.'))
            else:
                field_prefix = 'action.' + action_name
                token_name = '$' + field_prefix + '.filename$'
                filename = action_data.get('filename') or action_data.get('action.script.filename')
                alert_command = alert_command.replace(token_name, filename)
        elif action_name == 'rss':
            alert_command = action_content.get('command')
        else:
            alert_command = 'sendalert'
        return alert_command

    def synchronize_search(self, search_job, search_command):
        """
        Synchronizing an existing search implies, waiting for search to complete
        and verifying that it ran successfully.

        @type search_job: SearchJob
        @param search_job: Executed search job

        @type search_command: basestring
        @param search_command: the executed command

        @rtype: None
        @returns Nothing

        @raise NotableEventActionException
        """
        splunk_search.waitForJob(search_job)
        if search_job.isFailed:
            self.logger.error('%s search failed. Refer search.log at "%s" ', search_command,
                              search_job.links.get('search.log'))
            raise NotableEventActionException(_('%s search failed. Refer search.log at "%s".') %
                                              (search_command, search_job.links.get('search.log')))
        # Check messages as well
        is_error = False
        error_msg = ''
        for msg in search_job.messages:
            if not msg:
                pass
            if isinstance(msg, basestring) and (msg.upper() == 'ERROR' or msg.upper() == 'FATAL'):
                error_msg = str(msg)
                is_error = True
                break
        if is_error:
            message = _('Search failed with message=%s') % error_msg
            self.logger.error(message)
            raise NotableEventActionException(message)

    def run_search(self, search_command, is_sync, earliest_time=None, latest_time=None):
        """
        Run a splunk search.

        @type search_command: basestring
        @param search_command: the command to execute

        @type is_sync: boolean
        @param is_sync: indicates if search should be run synchronously

        @type earliest_time: basestring
        @param earliest_time: earliest time

        @type latest_time: basestring
        @param latest_time: latest time

        @rtype: basestring
        @returns: job's search id.
        """
        job = splunk_search.dispatch(search=search_command, sessionKey=self.session_key,
                owner=self.owner, namespace=self.app,
                earliestTime=earliest_time, latestTime=latest_time)
        if is_sync:
            self.synchronize_search(job, search_command)

        return job.sid

    def get_search_command(self, action_name, action_data, ids, is_group, filter_search=None):
        alert_command = self.get_alert_command(action_name, action_data)
        default_prepand_command = self.get_default_prepend_command(ids, action_name, is_group, filter_search)
        search_command = action_data.get('prepand_search_command', default_prepand_command)

        if not search_command.rstrip(' ').endswith('|'):
            search_command += ' | '

        if action_name in ['script', 'rss']:
            search_command += ' %s ' % alert_command
        else:
            search_command += ' %s "%s" ' % (alert_command, action_name)
            # get params and add it to search command
            search_command += self.get_command_params(action_name, action_data, is_group)

        # Workaround for issue SPL-128836
        if action_name in ['email']:
            email_data = self.get_all_actions(True).get('email', {})
            if email_data.get('mailserver'):
                self.logger.info('Adding mail server=%s to email command', email_data.get('mailserver'))
                search_command += ' server="%s" '% email_data.get('mailserver')
        return search_command

    @time_function_call
    def execute_action(self, action_name, ids, data, is_sync=False, is_group=False, filter_search=None,
                       earliest_time=None, latest_time=None, additional_ids=None):
        """
        Invoke sendalert command by passing given parameter

        @type action_name: basestring or str
        @param action_name: action name

        @type ids: list
        @param ids: event or group id of notable events

        @type data: dict
        @param data: data which hold all parameters values, along with action_name

        @type is_sync: bool
        @param is_sync: set to true, search which execute this search need to wait for completion

        @type is_group: bool
        @param is_group: set to true when action is being form on group

        @type group_data: dict or None
        @param group_data: when is_group flag is set then user can pass event id in this dict. When is_group
                is set to true with no group_action_data then action is being perform on all event from group

        @type earliest_time: basestring
        @param earliest_time: earliest time

        @type latest_time: basestring
        @param latest_time: latest time

        @type additional_ids: list of ids of related events
        @param additional_ids: list of ids of related events that are part of the bulk action, but not the main id of the action

        @rtype sid: basestring
        @return: return sid of search job
        """
        if not isinstance(action_name, basestring):
            message = _('Action name is not specified="%s".') % action_name
            self.logger.error(message)
            raise ValueError(message)

        valid_actions = [action.get('action_name') for action in self.get_actions()]

        if action_name not in valid_actions:
            self.logger.error('Invalid action provided=%s', action_name)
            raise NotableEventActionException(_('Invalid action. This action: `%s`'
                ' is not allowed for notable event.') % action_name)

        # All actions are executed as a Splunk search. Surprise!!!
        search_command = self.get_search_command(action_name, data, ids, is_group, filter_search)

        self.logger.info('Generated search command=`%s` for action=`%s` with earliest_time=%s, latest_time=%s',
             search_command, action_name, earliest_time, latest_time)

        sid = self.run_search(search_command, is_sync)

        # audit logging
        bulk_data = []
        activities = []
        additional_ids = additional_ids if additional_ids is not None else []
        activity_type = ''
        if not is_group:
            activity_type = 'Action Executed'
            for eid in ids:
                bulk_data.append({'action_name': action_name, 'search_command': search_command,'event_id': eid})
                activities.append('Action="%s" executed.' % action_name)
            # add additional event IDs to bulk_data to track action execution on other events in bulk selection
            for additional_eid in additional_ids:
                bulk_data.append({'action_name': action_name, 'search_command': search_command,'event_id': additional_eid})
                activities.append('Action="%s" executed.' % action_name)
        else:
            activity_type = 'Action Executed for Group.'
            bulk_data.append({'action_name': action_name, 'search_command':search_command, 'is_group': True, 'event_id': ids[0]})
            activities.append('Action="%s" executed.' % action_name)

        self.audit.send_activity_to_audit_bulk(bulk_data, activities, activity_type)
        return sid
