# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Manifest file 
"""

from clause_item_config import (
        CIConfigNotableEventField, CIConfigNotableEventCount,
        CIConfigDuration, CIConfigPause,
        CIConfigNotableEventExecuteAction, CIConfigNotableEventChange,
        CIConfigNotableEventComment, CIConfigNotableEventComment
        )

CONFIG_ITEM_TYPE_MANIFEST = {
        'notable_event_field': CIConfigNotableEventField,
        'notable_event_count': CIConfigNotableEventCount,
        'duration': CIConfigDuration,
        'pause': CIConfigPause,
        'notable_event_execute_action': CIConfigNotableEventExecuteAction,
        'notable_event_change': CIConfigNotableEventChange,
        'notable_event_comment': CIConfigNotableEventComment,
        'notable_event_tag': CIConfigNotableEventComment
        }
