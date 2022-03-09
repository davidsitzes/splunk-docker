# $(copyright)

import sys
import decimal
import uuid
import time
import hashlib
import json
import re

from splunk.rest import simpleRequest
from splunk.util import stringToFieldList, normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n
import splunk.search
import splunk
import splunk.rest as rest

from push_event_manager import PushEventManager
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'appserver', 'controllers']))
from user_access_errors import UserAccessError

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import get_session_user, get_conf, get_current_utc_epoch


def get_index_fields_to_avoid():
    """
    @rtype: tuple
    @return: index fields to avoid
    """
    # If we ever allow _ fields then make sure we do not reindex '_bkt', '_cd'
    return ('_time', '_raw', 'index', 'punct', 'linecount', 'timeendpos', 'timestartpos', 'eventtype',
            'tag', 'splunk_server', 'search_name')


def is_proprietary_index_field(field):
    """
    Return true if field starts with _, date_, tag:: or if it is from get_index_fields_to_avoid()

    @type field: basestring
    @param field: field to check

    @return: bool
    """
    # If we ever allow _ fields then make sure we do not allow field to index '_bkt', '_cd'
    return (field.startswith('_') or field in get_index_fields_to_avoid() or field.startswith('date_') or
            field.startswith('tag::') or field.startswith('info_'))


def replace_tokens(data):
    """
    Pass dict and replace token on each value of the dict
    Note: in place upgrade
    @type data: dict
    @param data: dict where we do to token replacement of each field

    @return: None (in place upgrade)
    """
    if not isinstance(data, dict):
        return

    for key, value in data.iteritems():
        if value:
            data[key] = token_replacement(value, data)


def token_replacement(field, result_set):
    """
    Replace token in given field and return actual value
    @type field: basestring
    @param field: field which hold %field% token to replace with value

    @type result_set: dict
    @param result_set: result set which hold all fields
    """

    if not field or not isinstance(field, basestring):
        return field

    regex = re.compile('\%([\w.\s]+)\%')
    # Performing token replacement
    dynamic_fields = regex.findall(field)
    if dynamic_fields:
        new_field = field
        for token in dynamic_fields:
            value = result_set.get(token, '')
            # sometimes value itself contain token itself, in that case lets
            # looks for original value because of name conflict we rename some field
            # to orig_<field>
            if not value or value == '%'+token+'%':
                # look for orig_<field>
                value = result_set.get('orig_' + token, '')
            new_field = new_field.replace('%'+token+'%', value)
        field = new_field
    return field


def filter_index_fields_and_get_event_id_for_notable_event(result, logger, event_identifier_fields_string=None,
                                                           event_time=None, is_none_allowed=False, fields_to_send=None,
                                                           is_token_replacement=False):
    """
    A common utils which is being used by mod alert and notable event rest interface to
    process event before we push to index
    Like make sure right sourcetype, time, event_id is being set and also prefix with orig_ with some set of fields

    @type result: dict
    @param result: event to process

    @type logger: logger object
    @param logger: logger instance to log

    @type event_identifier_fields_string: basestring
    @param event_identifier_fields_string: common seperated list of field name which is being used to calculate event
            identifier hash

    @type event_time: float/basestring
    @param event_time: epoch time for event. If it is not specified then UTC epoch time for now is used

    @type fields_to_send: dict
    @param fields_to_send: Set of field and values which is being processed already. Mod alert case it is processed
                           already

    @type is_token_replacement: bool
    @param is_token_replacement: token replacement is required

    @rtype: dict
    @return: a dict which contains modified field set
    """
    if not fields_to_send:
        fields_to_send = {}

    event_id_key = 'event_id'

    # Note make sure original event time is not assigned _time for new event. If it is required in some use cases then
    # use event_time

    prefix_fields_with_orig = ['_raw']

    for field in prefix_fields_with_orig:
        if field in result:
            field_value = result[field]
            logger.debug('Found field, converting to orig_%s', field)
            del result[field]
            # Avoid two _ in field name
            orig_field = 'orig' + field if field.startswith('_') else 'orig_' + field
            if orig_field not in result:
                result[orig_field] = field_value
            else:
                logger.warning('Field=%s already exist in the result hence skipping field conversion of field=%s',
                            orig_field, field)

    for field in result:
        if not is_proprietary_index_field(field):
            # Handle empty and null value
            if result[field]:
                fields_to_send[field] = result[field]
            elif is_none_allowed:
                fields_to_send[field] = result[field]
            else:
                logger.debug('Field=%s does not have any value=%s', field, result[field])

    # Check for event id
    if event_id_key not in result or not result.get(event_id_key):
        # Create UUID
        logger.debug('Event does not contain ID.  Creating ID')
        fields_to_send[event_id_key] = str(uuid.uuid1())

    current_time = str(get_current_utc_epoch())
    if event_time:
        # Time has to be epoch time
        time_field_value = event_time
        # Check if time is epoch
        try:
            decimal.Decimal(time_field_value)
            fields_to_send['_time'] = time_field_value
        except decimal.InvalidOperation:
            logger.warning('time in the event is not epoch, ignoring and inserting epoch time')
            fields_to_send['_time'] = current_time
    else:
        # Assign now time
        fields_to_send['_time'] = current_time

    fields_to_send['sourcetype'] = 'stash'

    # Add mod_time
    fields_to_send['mod_time'] = current_time

    # Add event identifier hash
    event_identifier_fields = stringToFieldList(event_identifier_fields_string)
    if len(event_identifier_fields) == 0:
        logger.warning('Event identifier fields are not specified,'
                    ' defaulting to source, title, description')
        event_identifier_fields = ['source']

    if is_token_replacement:
        logger.debug('Performing token replacement with field set=%s', fields_to_send)
        replace_tokens(fields_to_send)
        logger.debug('Successfully completed token replacement for field set=%s', fields_to_send)

    hash_string = ''
    for f in event_identifier_fields:
        # Fall back on the orig masked field if updated not present
        if f not in fields_to_send and f in prefix_fields_with_orig:
            if f.startswith('_'):
                f = 'orig' + f
            else:
                f = 'orig_' + f
        logger.debug('Identifier field=%s, value=%s', f, fields_to_send.get(f))
        hash_string += str(fields_to_send.get(f, ''))
    fields_to_send['event_identifier_hash'] = hashlib.sha256(hash_string).hexdigest()

    return fields_to_send


def get_collection_name_for_event_management_objects(object_type):
    """
    Method returns a collection name given an object type
    @param object_type: event management object type
    @param type: string
    @return collection_name: collection where objects of object_type is stored
    @return type: string
    """
    return OBJECT_COLLECTION_MATRIX.get(object_type)


class SearchUtils(object):
    """
     Search utils which perform search related operation for notable events. For example
     update existing notable events which run |delete to remove event first and then add new
     event
    """

    def __init__(self, session_key, logger, index='itsi_tracked_alerts', user=None, namespace=None):
        """
        Initialized object

        @type session_key: basestring
        @param session_key: session key

        @type logger: logger object
        @param logger: logger object to log

        @type index: basestring
        @param index: index name

        @type user: basestring
        @param user: under which search is being created

        @type namespace: basestring
        @param namespace: app name space

        @rtype: object
        @return: instance of given class
        """
        if not session_key:
            raise TypeError(_('Invalid session key'))
        self.session_key = session_key
        self.logger = logger
        self.index = index
        # Run these search as nobody to avoid concurrent search limit
        self.owner =  user if user is not None else 'nobody'
        self.app = namespace if namespace is not None else 'itsi'

    def _do_status_transition_access_check(self, status_from, status_to):
        # Only do access check if a status transition is occurring
        if not ((status_to == 'None') or (status_from == status_to)):
            capability_to_check = 'transition_status-' + status_from + '_to_' + status_to + '-notable_event'

            username = get_session_user(self.session_key)

            try:
                user_is_capable = UserAccess.is_user_capable(
                    username,
                    capability_to_check,
                    self.session_key,
                    self.logger,
                    owner=self.owner)
            except Exception as e:
                self.logger.exception(e)
                message = '{}'.format(e)
                raise UserAccessError(status=500, message=message)

            if user_is_capable:
                message = _('"{0}" has the capability "{1}".').format(username, capability_to_check)
                self.logger.info('%s', message)
            else:
                message = _('"{0}" does not have the capability "{1}".').format(username, capability_to_check)
                self.logger.error('%s', message)
                raise UserAccessError(status=403, message=message)

    def _return_match_event(self, event_list, id_key, event_id):
        """
        Return matched event (Supporting function for update)

        @type event_list: list
        @param event_list: event list

        @type id_key: basestring
        @param id_key: key name which hold event id

        @type event_id: basestring
        @param event_id: which handles events id

        @return:
        """
        for event in event_list:
            if event.get(id_key) == event_id:
                return event
        return None

    def update_group_events(self, group_id, fields_to_update, event_filter,
                            earliest_time=None, latest_time=None, id_key='event_id'):
        """
        Get events for specific group that pass event_filter

        @type group_id: basestring
        @param group_id: group id

        @type fields_to_update: dict
        @param fields_to_update: key, value fields to update

        @type event_filter: basestring
        @param event_filter: event to filter

        @type earliest_time: basestring
        @param earliest_time: earliest time

        @type latest_time: basestring
        @param latest_time: latest time

        @type id_key: basestring
        @param id_key: key which holds id in the event

        @rtype: list
        @return: list of events which needs to be updated
        """
        filter_string = event_filter if event_filter else ''
        search_string = 'search index=itsi_tracked_alerts [search index=itsi_grouped_alerts itsi_group_id="{1}" | table event_id] | lookup itsi_notable_event_state_lookup _key AS event_id OUTPUT severity AS lookup_severity, owner AS lookup_owner, status AS lookup_status | eval severity=if(isnull(lookup_severity), severity, lookup_severity), status=if(isnull(lookup_status), status, lookup_status), owner=if(isnull(lookup_owner), owner, lookup_owner) | fields - lookup_* | search {0}'.format(filter_string, group_id)
        self.logger.info('Search %s which will run to update group events', search_string)

        results = self._get_events_by_search_string(search_string, earliest_time, latest_time, False, 'itsi_group_id')

        ids = []
        for result in results:
            if fields_to_update and 'status' in fields_to_update:
                # Validate it if status change is allowed
                self._do_status_transition_access_check(str(result.get('status')), str(fields_to_update.get('status')))
            ids.append(result.get(id_key))

        return ids

    def get_events(self, ids, earliest_time=None, latest_time=None,
                   is_delete=False, id_key='event_id'):
        """
        This function delete old event and return its field value to updated events

        @type ids: list of event ids
        @param ids: list ids to fetch notable events

        @type earliest_time: epoch time
        @param earliest_time: search earliest time

        @type latest_time: epoch time
        @param latest_time: epoch latest search time

        @type is_delete: bool
        @param is_delete: flag to delete the command

        @type id_key: basestring
        @param id_key: key which hold id in the event

        @rtype: list of dict
        @return: In place updated updated_events args and return itself
        """

        if not isinstance(ids, list):
            raise TypeError(_('ids are not a valid list.'))

        # Construct search
        search_string = 'search index=' + self.index

        for index, eid in enumerate(ids):
            if index == 0:
                search_string += ' {0}="{1}" '.format(id_key, eid)
            else:
                search_string += 'OR {0}="{1}" '.format(id_key, eid)

        # Add delete
        if is_delete:
            self.logger.info('Delete flag is set hence appending | delete command')
            # Make sure splunk_server, _cd, _btk and index is single valued
            #  eval splunk_server = mvindex(splunk_server,0) | eval _btk = mvindex(_btk,0) |  eval _cd = mvindex(_cd,0)
            # However eval trick does not work. So we had to make sure splunk_server and those field should not be mutli
            # value
            search_string += ' | delete'

        self.logger.info('Search="%s" is going to invoked with earliest=%s and latest=%s',
                         search_string, earliest_time, latest_time)
        return self._get_events_by_search_string(search_string, earliest_time, latest_time, is_delete, id_key, ids=ids)

    def _get_events_by_search_string(self, search_string, earliest_time=None, latest_time=None,
                                     is_delete=False, id_key='event_id', ids=None):
        """
        Function which run a search and return events which has been deleted
        @type search_string: basestring
        @param search_string: search which needs to be invoked

        @type earliest_time: epoch time
        @param earliest_time: search earliest time

        @type latest_time: epoch time
        @param latest_time: epoch latest search time

        @type is_delete: bool
        @param is_delete: flag to delete the command

        @type id_key: basestring
        @param id_key: key which hold id in the event

        @rtype: list of dict
        @return: In place updated updated_events args and return itself
        """
        if not isinstance(search_string, basestring):
            raise TypeError(_("Search String=%s is not valid string, type=%s.") % (search_string, type(search_string)))

        if earliest_time is not None and latest_time:
            job = splunk.search.dispatch(search_string, sessionKey=self.session_key, earliestTime=earliest_time,
                                         latestTime=latest_time, owner=self.owner, rf='*',
                                         namespace=self.app)
        elif earliest_time is not None:
            job = splunk.search.dispatch(search_string, sessionKey=self.session_key, earliestTime=earliest_time,
                                         owner=self.owner, rf='*', namespace=self.app)
        elif latest_time:
            job = splunk.search.dispatch(search_string, sessionKey=self.session_key, latestTime=latest_time,
                                         owner=self.owner, rf='*', namespace=self.app)
        else:
            job = splunk.search.dispatch(search_string, sessionKey=self.session_key,
                                         owner=self.owner, rf='*', namespace=self.app)

        # Wait for job to be done
        splunk.search.waitForJob(job)
        # check if search was successfully done
        if job.isFailed:
            job.cancel()
            raise splunk.SearchException(_('Search failed to clean up event(s), messages="%s".'), job.messages)

        results = []
        # get results only when you perform non-delete operation
        if not is_delete:
            fetched_event_ids = []
            for result in job.results:
                result_dict = {}
                # Handle multi valued field
                fetched_event_ids.extend(stringToFieldList(str(result.get(id_key))))
                self.logger.debug('Fetch result id=%s', result.get(id_key))
                for field in result:
                    if not is_proprietary_index_field(field):
                        result_dict[field] = str(result.get(field))
                # Add same time
                result_dict['_time'] = str(result.toEpochTime())
                results.append(result_dict)
        else:
            # Check is event is delete for sure checking  _ALL_ (INDEX)
            # Check for message
            is_error = False
            error_msg = ''
            for msg in job.messages:
                if not msg:
                    pass
                if isinstance(msg, basestring) and (msg.upper() == 'ERROR' or msg.upper() == 'FATAL'):
                    error_msg = str(msg)
                    is_error = True
            if is_error:
                # Check if we have one event deleted
                self.logger.error('Failed to delete old event, %s', error_msg)
                raise splunk.RESTException(500, msg=error_msg,
                                           extendedMessages=_("Failed to delete one or more event(s)={0}.").format(ids))

        # Check if all events is being returned
        # Check only when you are not deleting it
        if not is_delete and ids:
            self.logger.debug('Fetched ids=%s, request_ids=%s', fetched_event_ids, ids)
            difference = list(set(ids).difference(fetched_event_ids))
            self.logger.debug('Calculated difference=%s', difference)

            if len(difference) != 0:
                self.logger.error('Event ids=%s were not found', difference)
                raise splunk.ResourceNotFound(msg=_('%s resource(s) was not found.') % (str(difference)))

        # clean up
        job.cancel()
        self.logger.info('Successfully returning %s events', len(results))
        return results


class Audit(object):
    """
    Class which is being used to send audit to notable event audit log
    """

    def __init__(self, session_key, audit_token_name='Notable Index Audit Token',
                 audit_index='itsi_notable_audit',
                 audit_host=None, audit_source='Notable Event Audit', audit_sourcetype='stash'):
        """

        @param session_key:
        @param audit_token_name:
        @param audit_index:
        @param audit_host:
        @param audit_source:
        @param audit_sourcetype:
        @return:
        """
        if not session_key:
            raise TypeError(_('Invalid session key'))
        self.session_key = session_key
        self.tracking_key = 'activity'
        self.tracking_type = 'activity_type'
        self.audit_user_key = 'user'
        self.time_key = '_time'
        self.audit_index = audit_index
        self.audit_token_name = audit_token_name
        self.audit = PushEventManager(self.session_key, audit_token_name)

    def _get_current_user(self):
        """
        Given session_key, get the user who is logged in.
        @return username of the person who is logged in.
        """
        resp, content = rest.simpleRequest('/authentication/current-context',
                getargs={"output_mode":"json"},
                sessionKey=self.session_key,
                raiseAllErrors=False)
        content = json.loads(content)
        return content['entry'][0]["content"]["username"]

    def _prep(self, data, activity, activity_type, user):
        """
        Prepare audit data prior to indexing.
        @param data: data dict to audit
        @param activity: activity string
        @param activity_type: activity type string
        @param user: current user who is logged in

        @return Nothing. Inplace prep of data.
        """
        data[self.audit_user_key] = user
        data[self.tracking_key] = activity
        data[self.tracking_type] = activity_type
        data[self.time_key] = str(get_current_utc_epoch())

    def send_activity_to_audit_bulk(self, data, activities, activity_type):
        """
        Send activity to notable index in bulk.

        @type data: list
        @param data: data to send to audit log

        @type activities: list
        @param activities: list of activities corresponding to data.

        @type activity_type: basestring
        @param activity_type: activity type

        @rtype: None
        @return: Nothing
        """
        # Add activity tracking again
        user = self._get_current_user()
        for d, a in zip(data, activities):
            self._prep(d, a, activity_type, user)

        self.audit.push_events(data)

    def send_activity_to_audit(self, data, activity, activity_type):
        """
        Send activity to notable index

        @type data: dict
        @param data: data to send to audit log

        @type activity: basestring
        @param activity: activity

        @type activity_type: basestring
        @param activity_type: activity type

        @rtype: None
        @return: Nothing
        """
        user = self._get_current_user()
        self._prep(data, activity, activity_type, user)
        self.audit.push_event(data)

class MethodType(object):
    GET = 'get',
    CREATE = 'create',
    UPDATE = 'update',
    DELETE = 'delete',
    GET_BULK = 'get_bulk',
    CREATE_BULK = 'create_bulk',
    UPDATE_BULK = 'update_bulk',
    DELETE_BULK = 'delete_bulk'


NOTABLE_EVENT_CAPABILITIES = {
    'read': 'read-notable_event',
    'write': 'write-notable_event',
    'delete': 'delete-notable_event'
}

CAPABILITY_MATRIX = {
    'rbac': {
        'read': 'configure_perms',
        'write': 'configure_perms',
        'delete': 'configure_perms'
    },
    'correlation_search': {
        'read': 'read_itsi_correlation_search',
        'write': 'write_itsi_correlation_search',
        'delete': 'delete_itsi_correlation_search',
        'interact': 'interact_with_itsi_correlation_search'
    },
    'notable_event': NOTABLE_EVENT_CAPABILITIES,
    'notable_event_comment': NOTABLE_EVENT_CAPABILITIES,
    'notable_event_tag': NOTABLE_EVENT_CAPABILITIES,
    'notable_event_ticketing': NOTABLE_EVENT_CAPABILITIES,
    'notable_event_action': {
        # Execute endpoint is the only one supported for notable actions in POST requests
        # Hence POST => write action => execute-notable_event_action
        'read': 'read-notable_event_action',
        'write': 'execute-notable_event_action'
    },
    'notable_event_aggregation_policy': {
        'read': 'read_itsi_notable_aggregation_policy',
        'write': 'write_itsi_notable_aggregation_policy',
        'delete': 'delete_itsi_notable_aggregation_policy',
        'interact': 'interact_with_itsi_notable_aggregation_policy'
        },
    'notable_event_group': {
            'read': 'read-notable_event_action',
            'write': 'execute-notable_event_action',
            'delete': 'execute-notable_event_action'
        }
}

OBJECT_COLLECTION_MATRIX = {
    'notable_event_comment': 'itsi_notable_event_comment',
    'notable_event_tag': 'itsi_notable_event_tag',
    'external_ticket': 'itsi_notable_event_ticketing',
    'notable_event_group': 'itsi_notable_event_group',
    'notable_event_aggregation_policy': 'itsi_notable_event_aggregation_policy',
    'notable_event_seed_group': 'itsi_correlation_engine_group_template',
    'correlation_search': 'itsi_correlation_search'
}


class NotableEventConfiguration(object):

    def __init__(self, session_key, logger, status_conf_file_name='itsi_notable_event_status',
                 severity_conf_file_name='itsi_notable_event_severity',
                 owner_collection_uri='/servicesNS/nobody/SA-ITOA/storage/collections/data/itsi_user_realnames'):
        """
        Get all configuration for notable event like status, severity and owners

        @type session_key: basestring
        @param session_key: splunkd session key

        @type logger: object
        @param logger: logger

        @type status_conf_file_name: basestring
        @param status_conf_file_name: conf file which hold status

        @type severity_conf_file_name: basestring
        @param severity_conf_file_name: conf file which hold severity

        @type owner_collection_uri: basestring
        @param owner_collection_uri: uri to the collection consisting of real
            user names

        @return: not applicable
        """
        if not session_key:
            raise TypeError(_('Invalid session key'))
        if not logger:
            raise TypeError(_('Invalid logger object'))

        self.session_key = session_key
        self.logger = logger
        self.default_owner = 'unassigned'

        self.severity_contents = self._get_conf_file_stanzas(severity_conf_file_name)
        self.status_contents   = self._get_conf_file_stanzas(status_conf_file_name)
        self.owner_contents    = self.get_owner_contents(owner_collection_uri)

    def get_default_owner(self):
        """
        Get default owner

        @rtype: basestring
        @return: default owner
        """
        self.logger.debug('Default owner=%s', self.default_owner)
        return self.default_owner

    def get_default_status(self):
        """
        Get default status

        @rtype: basestring
        @return: key of default status
        """
        default_status_key = None
        for status_key, content in self.status_contents.iteritems():
            if normalizeBoolean(content.get('default')):
                # If there is more than one default then return first one
                default_status_key = status_key
                break
        # Could not find then return first
        if default_status_key is None and self.status_contents:
            default_status_key =  self.status_contents.keys()[0]if self.status_contents.keys() else None

        self.logger.debug('Default status=%s', default_status_key)
        if default_status_key is None:
            raise TypeError(_('Default status can not be None.'))
        return default_status_key

    def get_default_severity(self):
        """
        Get default severity

        @rtype: basestring
        @return: key of default severity
        """
        default_severity = None
        for key, content in self.severity_contents.iteritems():
            if normalizeBoolean(content.get('default')):
                # If there is more than one default then return first one
                default_severity = key
                break
        # Could not find then return first
        if default_severity is None and self.severity_contents:
            default_severity = self.severity_contents.keys()[0] if self.severity_contents.keys() else None

        self.logger.debug('Default severity=%s', default_severity)
        if default_severity is None:
            raise TypeError(_('Default severity can not be None.'))

        return default_severity

    def _get_conf_file_contents(self, conf_file_name):
        """
        Get conf file full contains

        @type conf_file_name: basestring
        @param conf_file_name: file name

        @rtype: dict
        @return: return contents
        """
        conf_data = get_conf(self.session_key, conf_file_name)
        response = conf_data.get('response')
        if int(response.get('status')) == 200:
            contents = json.loads(conf_data.get('content'))
            return contents
        else:
            self.logger.error('Failed to get severity from itsi_notable_event_severity, response="%s"', response)
            raise NotableEventException(_('Failed to get severity from itsi_notable_event_severity, response="%s".')
                                        % response)

    def _get_conf_file_stanzas(self, conf_file_name):
        """
        Get conf file stanza names

        @type conf_file_name: basestring
        @param conf_file_name: file name

        @rtype: list
        @return: list of conf file stanza names and its content
        """
        contents = self._get_conf_file_contents(conf_file_name)
        names = {}
        for entry in contents.get('entry', []):
            names[entry.get('name')] = entry.get('content')
        return names

    def get_severities(self):
        """
        Get list severity values

        @rtype: list
        @return: list of severity values
        """
        return self.severity_contents.keys()


    def get_statuses(self):
        """
        Get list of valid status values

        @rtype: list
        @return: list of statuses
        """
        return self.status_contents.keys()

    def get_owner_contents(self, owner_collection_uri):
        """
        Get owners
        @type owner_collection_uri: basestring
        @param owner_collection_uri: uri of the collection containing the
            real user names

        @rtype: list
        @return: valid owners of the app
        """
        if not isinstance(owner_collection_uri, basestring):
            raise TypeError(_('Invalid type for owner_collection_uri.'))

        if not owner_collection_uri:
            raise ValueError(_('Invalid value for owner_collection_uri.'))

        uri = owner_collection_uri

        response, content = simpleRequest(uri, self.session_key, getargs={'output_mode': 'json'})

        if response.status != 200:
            self.logger.error('Failed to get users from uri=%s', uri)
            raise NotableEventException(_('Failed to get users from uri=%s.') % uri)

        valid_users = {}

        user_names = json.loads(content)

        for user in user_names:
            valid_users[user.get('_key')] = user
        # Add default owner too
        valid_users[self.default_owner] = {'_key': self.default_owner, 'realname': self.default_owner}

        return valid_users

    def get_owners(self):
        """
        Get owners

        @rtype: list
        @return: valid owners of the app
        """
        return self.owner_contents.keys()


class NotableEventException(Exception):
    pass


class NotableEventActionException(Exception):
    pass
