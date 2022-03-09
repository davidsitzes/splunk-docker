# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from ITOA.event_management.notable_event import NotableEvent
from utils import NotableEventValidator

class ItsiNotableEvent(NotableEvent):

    collection = 'itsi_notable_event'

    def __init__(self, session_key, current_user_name=None, user='nobody', logger=None):
        super(ItsiNotableEvent, self).__init__(session_key, index_name='itsi_tracked_alerts',
                                               current_user_name=current_user_name,
                                               token_name='Auto Generated ITSI Event Management Token',
                                               audit_token_name='Auto Generated ITSI Notable Index Audit Token',
                                               audit_host=None,
                                               audit_index='itsi_notable_audit', audit_sourcetype='stash',
                                               audit_source='itsi_notable_event_audit', logger=logger,
                                               user=user)
        self.validator = NotableEventValidator(session_key, self.logger)

    def validate_schema(self, data):
        """
        Validate schema before user CURD operation on notable event

        @type data: dict
        @param data: data which hold notable schema to create

        @rtype: bool
        @return: True - if data contains all required fields, False - otherwise or throw exception
        """
        return self.validator.validate_schema(data)

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
        fields_to_update = [] # keep track of fields that already exist in entry

        if activity_type == 'acknowledge':
            return '{0} acknowledged notable event'.format(updated_data.get('owner'))

        # handle fields that already exist in entry - show update from old value to new value
        for key in updated_data.keys():
            if key.startswith('__old__'):
                keys_to_del.append(key)
                actual_key = key[len('__old__'):]
                if actual_key not in updated_data or actual_key not in self.fields_to_track:
                    continue
                fields_to_update.append(actual_key)
                old_value = updated_data.get(key)
                new_value = updated_data.get(actual_key)
                # look up label for available fields
                if actual_key == 'status':
                    old_value = '{0} ({1})'.format(self.validator.notable_configuration_object.status_contents.get(old_value, {}).get('label'), old_value)
                    new_value = '{0} ({1})'.format(self.validator.notable_configuration_object.status_contents.get(new_value, {}).get('label'), new_value)
                elif actual_key == 'severity':
                    old_value = '{0} ({1})'.format(self.validator.notable_configuration_object.severity_contents.get(old_value, {}).get('label'), old_value)
                    new_value = '{0} ({1})'.format(self.validator.notable_configuration_object.severity_contents.get(new_value, {}).get('label'), new_value)
                activity_tracking += '{0} changed from {0}="{1}" to {0}="{2}". '.format(actual_key, old_value, new_value)

        # delete old entry in the dict
        for key in keys_to_del:
            del updated_data[key]

        # handle fields that don't exist yet - show update to new value
        for field in updated_data.keys():
            if field not in fields_to_update and field in self.fields_to_track:
                value = updated_data.get(field)
                if field == 'status':
                    value = '{0} ({1})'.format(self.validator.notable_configuration_object.status_contents.get(value, {}).get('label'), value)
                elif field == 'severity':
                    value = '{0} ({1})'.format(self.validator.notable_configuration_object.severity_contents.get(value, {}).get('label'), value)
                activity_tracking += 'updated {0}="{1}". '.format(field, value)

        return activity_tracking
