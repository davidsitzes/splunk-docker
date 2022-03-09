# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time
import uuid

from splunk.appserver.mrsparkle.lib import i18n
from base_event_management import BaseEventManagement
from notable_event_utils import Audit, MethodType, NotableEventConfiguration
from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_current_utc_epoch
from push_event_manager import PushEventManager

class NotableEventGroup(BaseEventManagement):
    """
    Class to create, update, get and delete group state
    Use to store notable event comments
    {
        _key: Random key
        object_type: notable_event_group,
        owner: <assignee>,
        severity: <severity>,
        status: <status>,
        mod_time: <mod_time>
        <create_time> : <create_time>
    }


    """

    def __init__(self, session_key, current_user_name=None, collection='itsi_notable_event_group',
                 object_type='notable_event_group',
                 user='nobody', **kwargs):
        """
        Initialize
        @param session_key: session key
        @param collection: collection name
        @param object_type: object type
        @param user: user context to save
        @param audit_token_name: audit token to used to send to audit logging
        @param kwargs: extra args
        @return:
        """
        # Initialized base event object
        super(NotableEventGroup, self).__init__(
            session_key, collection, object_type, user, current_user_name
        )
        self.mod_time_key = 'mod_time'
        self.create_time_key = 'create_time'
        self.user = 'nobody'
        self.logger = setup_logging('itsi_event_management.log', 'itsi.notable_event.group')
        self.audit = Audit(self.session_key, audit_token_name='Auto Generated ITSI Notable Index Audit Token',
                           audit_host=kwargs.get('audit_host'),
                           audit_source=kwargs.get('audit_source', 'Notable Event Audit'),
                           audit_sourcetype=kwargs.get('audit_sourcetype', 'stash'))
        self.notable_event_configuration = NotableEventConfiguration(session_key, self.logger)

    def pre_processing(self, data_list, method):
        """
        Add mod_time and event time to the group

        @type data_list: list
        @param data_list: list of data to validate and add time, user info etc

        @type method: basestring
        @param method: method type

        @rtype: list
        @return: It updates list in place and also return it back as well
        """
        if not isinstance(data_list, list):
            raise TypeError(_('Data is not a valid list, data_list type is: %s'), type(data_list))
        for data in data_list:
            # Make sure data is valid dict
            if not isinstance(data, dict):
                raise TypeError(_('Data is not a valid dictionary.'))

            time_value = get_current_utc_epoch()
            if method == MethodType.CREATE:
                # Add mod time, create time
                data[self.create_time_key] = time_value
            if method != MethodType.DELETE:
                # Need to set it for create and update
                data[self.mod_time_key] = time_value
        return data_list

    def _get_activity(self, updated_data, activity_type=None):
        """
        Return activity which is happening during update

        @type updated_data: dict
        @param updated_data: data to get activity

        @type activity_type: basestring
        @param activity_type: type of activity

        @rtype: basestring
        @return: activity log statement
        """
        activity_tracking = ''
        keys_to_del = []

        if activity_type == 'acknowledge':
            return '{0} acknowledged notable event group'.format(updated_data.get('owner'))

        for key, value in updated_data.iteritems():
            if key.startswith('__old__'):
                actual_key = key[len('__old__'):]
                # For status and severity, stores its level
                old_value = value
                new_value = updated_data[actual_key]
                # Put label along with id to show them pretty
                if actual_key == 'status' or actual_key == 'severity':
                    if actual_key == 'status':
                        old_value = self.notable_event_configuration.\
                                         status_contents.get(old_value, {}).get('label') + " ({0})".format(old_value)
                        new_value = self.notable_event_configuration.\
                                        status_contents.get(new_value, {}).get('label') + " ({0})".format(new_value)
                    if actual_key == 'severity':
                        old_value = self.notable_event_configuration.\
                                         severity_contents.get(old_value, {}).get('label') + " ({0})".format(old_value)
                        new_value = self.notable_event_configuration.\
                                        severity_contents.get(new_value, {}).get('label') + " ({0})".format(new_value)

                activity_tracking += '{0} changed from {0}="{1}" to {0}="{2}". '.format(actual_key, old_value,
                                                                                        new_value)
                keys_to_del.append(key)
        # delete old entry in the dict
        for key in keys_to_del:
            del updated_data[key]

        if not activity_tracking and updated_data:
            fields = set(updated_data.keys()).intersection(set(['status', 'severity', 'owner']))
            activity_tracking = 'Updated '
            for field in fields:
                value = updated_data[field]
                if field == 'severity':
                    value = self.notable_event_configuration.severity_contents.get(value, {}).get('label', '')\
                            + " ({0})".format(value)
                if field == 'status':
                    value = self.notable_event_configuration.status_contents.get(value, {}).get('label', '')\
                            + " ({0})".format(value)
                activity_tracking += ' {0}={1} '.format(field, value)
        return activity_tracking

    def create(self, data, **kwargs):
        """
        Create notable event

        @type data - dict
        @param data - notable event schema to create

        @rtype dict
        @return create object _key or raise an exception
        """
        # We need to set _key because _key should be same as group_id
        # if we set this value in payload then generic facade understand
        # that as update instead of create, hence we are passing as different
        # then _key
        # group_id comes from the UI and should not be confused with itsi_group_id
        # To-Fix:
        # - Update UI to use itsi_group_id
        if isinstance(data, dict) and 'group_id' in data:
            data['_key'] = data.pop('group_id')
        activity = self._get_activity(data, data.pop('action_type', None))
        ret = super(NotableEventGroup, self).create(data, **kwargs)
        # Create is kind of update here because group had already create with some initial state
        # now we are tracking it's state by creating record in KV
        self.audit.send_activity_to_audit({'event_id': data.get('_key')}, activity, 'Notable Event Group Update')

        self.check_to_send_break_group_event(data['_key'], **kwargs)
        return ret

    def create_bulk(self, data_list, **kwargs):
        """
        Create more than one notable events

        @type data_list: list
        @param data_list: data list

        @rtype: list
        @return: list of created
        """
        activities = []
        activities_data = []
        action_type = kwargs.pop('action_type', None)
        if isinstance(data_list, list):
            for data in data_list:
                if 'group_id' not in data:
                    continue
                data['_key'] = data.pop('group_id', None)
                activities.append(self._get_activity(data, action_type))
                activities_data.append({'event_id': data.get('_key')})
        ret = super(NotableEventGroup, self).create_bulk(data_list, **kwargs)
        # Create is kind of update here because group had already create with some initial state
        # now we are tracking it's state by creating record in KV
        self.audit.send_activity_to_audit_bulk(activities_data, activities, 'Notable Event Group Bulk Update')
        self.check_to_send_multiple_break_group_events(data_list, **kwargs);
        return ret

    def update(self, object_id, data, is_partial_update=False, **kwargs):
        """
        Update one notable event

        @type object_id: basestring
        @param object_id: object id

        @type data: dict
        @param data: data

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: Extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        activity = self._get_activity(data, data.pop('action_type', None))
        ret = super(NotableEventGroup, self).update(object_id, data, is_partial_update, **kwargs)
        self.audit.send_activity_to_audit({'event_id': data.get('_key')}, activity,
                                          'Notable Event Group Update')
        self.check_to_send_break_group_event(data['_key'], **kwargs)
        return ret

    def update_bulk(self, object_ids, data_list, is_partial_update=False, **kwargs):
        """
        Perform update for one or more notable events

        @type object_ids: list
        @param object_ids: notable events

        @type data_list: list
        @param data_list: notable events

        @type is_partial_update: bool
        @param is_partial_update: flag for partial update

        @type kwargs: dict
        @param kwargs: Extra params to perform

        @rtype: list
        @return: update notable event schema
        """
        activities = []
        activities_data = []
        action_type = kwargs.pop('action_type', None)
        for data in data_list:
            if 'group_id' not in data:
                continue
            data['_key'] = data.pop('group_id', None)
            activities.append(self._get_activity(data, action_type))
            activities_data.append({'event_id': data.get('_key')})
        ret = super(NotableEventGroup, self).update_bulk(object_ids, data_list, is_partial_update,
                                                         **kwargs)
        self.audit.send_activity_to_audit_bulk(activities_data, activities, 'Notable Event Group Bulk Update')
        self.check_to_send_multiple_break_group_events(data_list, **kwargs);
        return ret

    def add_drilldown(self, object_id, drilldown, is_partial_update=True, **kwargs):
        """
        Add drilldown link to notable event group

        Perform update for one or more notable events

        @type object_id: basestring
        @param object_id: object id

        @type drilldown: dict
        @param drilldown: drilldown to be added

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: Extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        if not self.is_valid_drilldown(drilldown):
            raise ValueError(_('Drilldown data must have link and name'))

        group = self.get(object_id)

        clean_drilldown = self._clean_drilldown(drilldown)

        try:
            drilldown_list = group.get('drilldown', [])
        except AttributeError:
            raise TypeError(_('Group is not of type dict'))

        try:
            drilldown_list.append(clean_drilldown)
        except AttributeError:
            raise TypeError(_('Drilldown field is not of type list'))

        ret = super(NotableEventGroup, self).update(object_id, {'drilldown': drilldown_list}, is_partial_update, **kwargs)

        return ret

    def update_drilldown(self, object_id, drilldown, is_partial_update=True, **kwargs):
        """
        Update drilldown for a NotableEventGroup

        @type object_id: basestring
        @param object_id: object id

        @type drilldown: dict
        @param drilldown: drilldown to be updated

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        if not self.is_valid_drilldown(drilldown):
            raise ValueError(_('Drilldown data must have link and name'))

        group = self.get(object_id)

        clean_drilldown = self._clean_drilldown(drilldown)

        try:
            drilldown_list = group.get('drilldown', [])
        except AttributeError:
            raise TypeError(_('Group is not of type dict'))

        drilldown_index = self._find_drilldown(drilldown_list, clean_drilldown)

        if not drilldown_list or drilldown_index is None:
            ret = self.add_drilldown(object_id, clean_drilldown, is_partial_update, **kwargs)
            return ret

        try:
            drilldown_list[drilldown_index].update(clean_drilldown)
        except IndexError:
            raise IndexError(_('Drilldown index of: {0} out of bounds for drilldown list').format(drilldown_index))
        except ValueError:
            raise ValueError(_('Nondictionary type given for drilldown'))
        except TypeError:
            raise TypeError(_('Drilldown index given is not an integer'))
        except AttributeError:
            raise AttributeError(_('Drilldown list item at index: {0} is not of type dict').format(drilldown_index))

        ret = super(NotableEventGroup, self).update(object_id, {'drilldown': drilldown_list}, is_partial_update, **kwargs)

        return ret

    def delete_drilldown(self, object_id, drilldown, is_partial_update=True, **kwargs):
        """
        Delete drilldown for a NotableEventGroup

        @type object_id: basestring
        @param object_id: object id

        @type drilldown: dict
        @param drilldown: drilldown to be updated

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        if not self.is_valid_drilldown(drilldown):
            raise ValueError(_('Drilldown data must have link and name'))

        group = self.get(object_id)

        clean_drilldown = self._clean_drilldown(drilldown)

        try:
            drilldown_list = group.get('drilldown', [])
        except AttributeError:
            raise TypeError(_('Group is not of type dict'))

        drilldown_index = self._find_drilldown(drilldown_list, clean_drilldown)

        if drilldown_index is None:
            raise KeyError(_('Drilldown with name: {0} not found').format(drilldown['name']))

        try:
            drilldown_list.pop(drilldown_index)
        except AttributeError:
            raise AttributeError(_('Drilldown list is not of type list'))
        except TypeError:
            raise TypeError(_('Drilldown index given is not an integer'))
        except IndexError:
            raise IndexError(_('Drilldown index of: {0} out of bounds for drilldown list').format(drilldown_index))

        ret = super(NotableEventGroup, self).update(object_id, {'drilldown': drilldown_list}, is_partial_update, **kwargs)

        return ret

    def check_to_send_break_group_event(self, group_id, **kwargs):
        """
        Check to see if you need to send an event to break the group by looking through kwargs for a break group flag

        @type group_id: basestring
        @param group_id: the id of the group

        @type kwargs: dict
        @param kwargs: Extra params to perform
        """
        # If we detect a policy id for breaking the group, then sent an event to the rules engine to break the group
        break_group_policy_id = kwargs.get('break_group_policy_id', False)
        if break_group_policy_id:
            self.send_break_group_event(group_id=group_id, policy_id=break_group_policy_id)

    def check_to_send_multiple_break_group_events(self, data_list, **kwargs):
        """
        Check to see if you need to send an event to break the group by looking through kwargs for a break group flag

        @type data_list: list
        @param data_list: notable events

        @type kwargs: dict
        @param kwargs: Extra params to perform
        """
        # If we detect a policy id for breaking the group, then sent an event to the rules engine to break the group
        break_multiple_groups = kwargs.get('break_multiple_groups', False)
        if break_multiple_groups:
            self.send_multiple_break_group_events(group_list=data_list)

    def send_break_group_event(self, group_id, policy_id):
        """
        Sends an event to the itsi_tracked_alerts index to break a specified group

        @type group_id: basestring
        @param group_id: the id of the group to be broken

        @type policy_id: basestring
        @param policy_id: the id of the group to be broken

        @return:
        """
        push_event_manager = PushEventManager(self.session_key, 'Auto Generated ITSI Event Management Token')
        event = {
            'event_id': str(uuid.uuid1()),
            'itsi_policy_id': policy_id,
            'itsi_group_id': group_id,
            'break_group_flag': True
        }
        push_event_manager.push_event(event, source='itsi@internal@group_closing_event', time=str(get_current_utc_epoch()))

    def send_multiple_break_group_events(self, group_list):
        """
        Sends an event to the itsi_tracked_alerts index to break a specified group

        @type group_list: list
        @param group_list: notable events

        @return:
        """
        for group in group_list:
            if 'break_group_policy_id' not in group:
                continue
            group_id = group.pop('_key', None)
            policy_id = group.pop('break_group_policy_id', None)
            self.send_break_group_event(group_id, policy_id)

    def is_valid_drilldown(self, drilldown):
        """
        Validation for drilldown link
        Must have name and the link
        And all values must be a string

        @type drilldown: dict
        @param drilldown: drilldown to be added

        @rtype: bool
        @return: True or false according to validation.
        """
        if type(drilldown) is not dict:
            return False

        VALID_FIELD = ['name', 'link']

        for field in VALID_FIELD:
            if field not in drilldown:
                return False
            if not drilldown.get(field):
                return False
            if type(drilldown.get(field)) is not str:
                return False

        return True

    def _clean_drilldown(self, drilldown):
        """
        Remove all non-whitelisted fields from drilldown dict

        @type drilldown: dict
        @param drilldown: drilldown to clean

        @rtype: dict
        @return: cleaned drilldown
        """
        whitelisted_fields = [
            'name',
            'link'
        ]

        for key in drilldown.keys():
            if key not in whitelisted_fields:
                del drilldown[key]

        return drilldown

    def _find_drilldown(self, drilldown_list, drilldown):
        """
        Find drilldown in drilldown list by name

        @type drilldown_list: list
        @param drilldown_list: list of drilldowns

        @type drilldown: dict
        @param drilldown: drilldown to find

        @rtype: int
        @return: index of found drilldown in drilldown list
        """
        for index, dd in enumerate(drilldown_list):
            if dd['name'] == drilldown['name']:
                return index

        return None
