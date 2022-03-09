# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from itsi.event_management.itsi_notable_event import ItsiNotableEvent
from ITOA.event_management.notable_event_tag import NotableEventTag
from ITOA.event_management.notable_event_comment import NotableEventComment
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from ITOA.event_management.notable_event_aggregation_policy import NotableEventAggregationPolicy
from itsi.event_management.itsi_notable_event_group import ItsiNotableEventGroup


'''
Object manifest is used currently to control which objects are supported in event management.
'''

object_manifest = {
    'notable_event': ItsiNotableEvent,
    'notable_event_tag': NotableEventTag,
    'notable_event_comment': NotableEventComment,
    'notable_event_aggregation_policy': NotableEventAggregationPolicy,
    'correlation_search': ItsiCorrelationSearch,
    'notable_event_group': ItsiNotableEventGroup
}
