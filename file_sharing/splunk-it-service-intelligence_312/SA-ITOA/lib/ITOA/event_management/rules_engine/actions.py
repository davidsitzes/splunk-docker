# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Represents an Actions object which currently is contained within a Rule type
object.
"""
from splunk.appserver.mrsparkle.lib import i18n
from ..notable_event_error import NotableEventBadRequest
from criterion import ExecutionCriteria

class ActionItem(object):
    """
    Represents an ActionItem
    """
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate (action_item):
        '''
        validate an ActionItem
        '''
        if not isinstance(action_item, dict):
            raise NotableEventBadRequest(_('Expecting a dictionary for %s.'
                ' Received type=%s') % type(action_item))
        
        if 'type' not in action_item:
            raise NotableEventBadRequest(_('Missing key `type`'))
        if 'config' not in action_item:
            raise NotableEventBadRequest(_('Missing key `config`'))
        if 'execution_criteria' not in action_item:
            raise NotableEventBadRequest(_('Missing key `execution_criteria`'))

        ExecutionCriteria.validate(action_item['execution_criteria'])

class Actions(object):
    """
    Actions is a Clause like object, expect it consists of a condition with
    some Action Items
    """
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Clause.validate(condition, items)`'))

    @staticmethod
    def validate(actions):
        '''
        Validate Actions
        '''
        if not isinstance (actions, dict):
            raise NotableEventBadRequest(_('Expecting `actions` to be a dict. Received type=%s.') %
                    type(actions).__name__)
        if 'condition' not in actions:
            raise NotableEventBadRequest(_('Actions: Missing key `condition`'))
        if 'items' not in actions:
            raise NotableEventBadRequest(_('Actions: Missing key `items`'))
        if not isinstance(actions['items'], list):
            raise NotableEventBadRequest(_('Actions: Expected type for `actions["items"]`=list'
                'Received=%s.') % type(actions['items']).__name__)
        for action_item in actions['items']:
            ActionItem.validate(action_item)

