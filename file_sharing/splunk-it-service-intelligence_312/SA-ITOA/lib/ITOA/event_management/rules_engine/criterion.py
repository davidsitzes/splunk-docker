# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Represents all possible criterion in a Notable Event Aggregation Policy.
    1. BreakingCriteria
    2. FilterCriteria
    3. ActivationCriteria
    4. ExecutionCriteria (defined in item.py)
"""
from splunk.appserver.mrsparkle.lib import i18n
from ..notable_event_error import NotableEventBadRequest

from clause import Clause
from item import ClauseItem

class FilterCriteria(Clause):
    """
    FilterCriteria represents the criteria which is responsible for tagging an
    incoming notable event with an existing policy.
    Example: where event title matches '*.sv.splunk.com'>
    """

    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `FilterCriteria.validate(criteria)`'))

    @staticmethod
    def validate(criteria):
        """
        validate a FilterCriteria
        """
        if not isinstance(criteria, dict):
            raise NotableEventBadRequest(_('Invalid type for criteria. Expecting a dictionary.'
                'Received type=%s') % type(criteria).__name__)

        supported_item_types = ['notable_event_field', 'pause',
                'notable_event_count', 'duration', 'clause']

        super(FilterCriteria, FilterCriteria).validate(
                criteria, supported_item_types)
        return

class BreakingCriteria(Clause):
    """
    BreakingCriteria represents the criteria which retires an active group.
    """
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `BreakingCriteria.validate(criteria)`'))

    @staticmethod
    def validate (criteria):
        """
        validate a BreakingCriteria
        """
        if not isinstance(criteria, dict):
            raise NotableEventBadRequest(_('Invalid type for criteria. Expecting a dictionary.'
                'Received type=%s') % type(criteria).__name__)

        supported_item_types = ['notable_event_count',
                'pause', 'duration', 'clause', 'notable_event_field']

        super(BreakingCriteria, BreakingCriteria).validate(criteria,
                supported_item_types)
        return

class ActivationCriteria(Clause):
    """
    ActivationCriteria represents the criteria satisfying which a Rule is
    activated for an incoming notable event or an existing group of notables.
    """

    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `ActivationCriteria.validate(criteria)`'))
    
    @staticmethod
    def validate(criteria):
        '''
        validate an ActivationCriteria
        '''
        if not isinstance(criteria, dict):
            raise NotableEventBadRequest(_('Invalid type for criteria. Expecting a dictionary.'
                'Received type=%s') % type(criteria).__name__)

        supported_item_types = ['breaking_criteria', 'notable_event_count',
                'duration', 'pause', 'clause']

        # ActivationCriteria must be a Clause
        super(ActivationCriteria, ActivationCriteria).validate(
                criteria, supported_item_types)
        return

class ExecutionCriteria(object):
    """
    ExecutionCriteria is essentially the criteria answering:
        "on which events is ActionItem applicable?".
    This is an exception for this Criteria which is the only one (thus far),
    to not inherit from `class Clause`.
    """
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `ExecutionCriteria.validate(criteria)`'))

    @staticmethod
    def validate(criteria):
        '''
        Validate an ExecutionCriteria
        '''
        if not isinstance(criteria, dict):
            raise NotableEventBadRequest(_('Invalid type for criteria. Expecting a dictionary.'
                'Received type=%s') % type(criteria).__name)

        if 'execute_on' not in criteria:
            raise NotableEventBadRequest(_('Missing key `execute_on`.'))

        valid_targets = ('ALL', 'FILTER', 'THIS', 'GROUP')

        if criteria['execute_on'] not in valid_targets:
            raise NotableEventBadRequest(_('Unsupported value for `execute_on`. Received=%s'
                ' Supported=%s') % (criteria['execute_on'], valid_targets))

        if criteria['execute_on'] == 'FILTER':
            # execute on FILTER implies you want to work on a sub-set of notable
            # events which match a certain criteria essentially some
            # search on the group on one (or more) notable event field(s).
            # This bit represented by the prescence of `config` in the criteria
            supported_item_types = ['notable_event_field', 'clause']
            items = criteria.get('config').get('items') if criteria.get('config') else []
            for item in items:
                ClauseItem.validate(item, supported_item_types)
        return
