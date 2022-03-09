# $ {copyright}
"""
Represents a clause in a Notable Event Aggregation Policy.
An Aggregation Policy doesnt really refer to this guy directly, but via one of
the many possible criterion.
"""
from splunk.appserver.mrsparkle.lib import i18n
from ..notable_event_error import NotableEventBadRequest

from item import ClauseItem

class Clause(object):
    '''
    A generic clause. Has a condition with a bunch of items to operate on.
    Schema:
    {
        "condition": <string>, // permitted values "OR", "AND"
        "items":  [ <Item* object> ]
    }
    '''
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Clause.validate(condition, items)`'))

    @staticmethod
    def validate (clause, supported_item_types=None):
        '''
        Use this method to get a clause type. Does validations
        '''
        if not isinstance(clause, dict):
            raise NotableEventBadRequest(_('Invalid type for `clause`. expecting: dict received type=%s.') % type(clause).__name__)

        if 'condition' not in clause or 'items' not in clause:
            raise NotableEventBadRequest(_('Missing key. Required: `condition`, `items`'))

        if clause['condition'] not in ('AND', 'OR'):
            raise NotableEventBadRequest(_('Bad Request. Expecting either "AND" or "OR"'
                '. Received "%s"') % clause)

        if not isinstance(clause['items'], list):
            raise NotableEventBadRequest(_('Bad Request. Expecting type=list. Received type='
                '%s') % type(clause).__name__)

        for item in clause['items']:
            ClauseItem.validate(item, supported_item_types)
