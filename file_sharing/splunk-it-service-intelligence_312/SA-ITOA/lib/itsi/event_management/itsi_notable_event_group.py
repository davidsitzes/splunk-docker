# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from ITOA.event_management.notable_event_group import NotableEventGroup


class ItsiNotableEventGroup(NotableEventGroup):
    """
    A wrapper class of NotableEventGroup.
    """

    collection = 'itsi_notable_event_group'

    def __init__(self, session_key, current_user_name=None, user='nobody'):
        super(ItsiNotableEventGroup, self).__init__(
                session_key,
                current_user_name=current_user_name,
                collection='itsi_notable_event_group',
                token_name='Auto Generated ITSI Event Management Token',
                audit_token_name='Auto Generated ITSI Notable Index Audit Token',
                audit_host=None,
                audit_index='itsi_notable_audit', audit_sourcetype='stash',
                audit_source='itsi_notable_event_audit', user=user
        )
