# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Represents a Rule in a Notable Event Aggregation Policy
"""
from splunk.appserver.mrsparkle.lib import i18n
from ..notable_event_error import NotableEventBadRequest

from clause import Clause
from actions import Actions

class Rule(object):
    """
    A Rule within a Notable Event Aggregation Policy
    """
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Rule.validate(rule)`'))

    @staticmethod
    def validate(rule):
        '''
        validate a Rule
        '''
        if not isinstance(rule, dict):
            raise NotableEventBadRequest(_('Expecting a dictionary for %s.'
                ' Received type=%s') % type(rule))
        
        if 'title' not in rule:
            raise NotableEventBadRequest(_('Missing key `title` in rule'))
        if 'activation_criteria' not in rule:
            raise NotableEventBadRequest(_('Missing key `activation_criteria` in rule'))
        if 'actions' not in rule:
            raise NotableEventBadRequest(_('Missing key `actions` in rule'))
        if not isinstance(rule['actions'], list):
            raise NotableEventBadRequest(_('Expecting actions to be list. Received=%s type=%s') % (
                rule['actions'], type(rule['actions']).__name__))
        for action in rule.get('actions'):
            Actions.validate(action)
