# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
All possible types of Config Items are broadly represented here.
At the very least, they contain
None of the classes can be instantiated. the only thing you can do is something
like:
    Item.validate(item)
"""
from splunk.appserver.mrsparkle.lib import i18n
from ..notable_event_error import NotableEventBadRequest
from item_manifest import CONFIG_ITEM_TYPE_MANIFEST

class Item(object):
    '''
    a generic Item. consists of `type` and a potential `config`
    '''
    def __init__(self, **kwags):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod 
    def validate(item, ignore_config=None):
        '''
        validate an Item
        @type ignore_config: bool
        @param ignore_config: for this config, ignore the config...
        '''
        if not isinstance(item, dict):
            raise NotableEventBadRequest(_('Expecting a dictionary for %s.'
                ' Received type=%s') % type(item))

        if 'type' not in item:
            raise NotableEventBadRequest(_('Missing key `type`'))

        if not ignore_config and 'config' not in item:
            # caller doesnt want us to ignore config and there is no such
            # key..this is a problem
            raise NotableEventBadRequest(_('Missing key `config`'))

class ClauseItem(Item):
    '''
    A ClauseItem is an Item in a clause. Pretty much a generic blob.
    Has a `type` and a `config` which is tightly coupled with the type.
    Possible item types are listed further below with their configs.
    Sometimes `config` need not be applicable, ex: breaking_criteria
    Supported Types: are defined in item_manifest.py
    Schema:
    {
        "type" : <string>,
        "config" : <dictionary>
    }
    '''
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate (item, supported_item_types):
        '''
        Certain keys must be present in item
        @param item: top level item
        @type item: dict

        @returns nothing
        '''
        if not isinstance(item, dict):
            raise NotableEventBadRequest(_('Expecting a dictionary for %s.'
                ' Received type=%s') % type(item))

        # ClauseItem must be an Item 
        super(ClauseItem, ClauseItem).validate(item)

        if item['type'] not in supported_item_types:
            raise NotableEventBadRequest(_('Unsupported Item Type. Received: %s.'
                ' Supported=%s') % (item['type'], supported_item_types))

        # now do specialized CIConfig type validation
        permitted_types = CONFIG_ITEM_TYPE_MANIFEST.keys()
        
        # A ClauseItem can be a BreakingCriteria and also a generic Clause type.
        permitted_types.extend(['breaking_criteria', 'clause'])

        if item['type'] not in permitted_types:
            raise NotableEventBadRequest(_('Unsupported `type`=%s. Supported types=%s') %
                    item['type'], permitted_types)

        # The case for adding `breaking_criteria` is obvious; `breaking_criteria`
        # merely indicates - "go see `breaking_criteria configuration" 
        # To prevent us from getting into
        # infinite validation, we will avoid validating anything over one level
        # of depth.
        # This is not clean but I cannot think of a better way of doing this w/o
        # breaking inheritance and circular imports.
        if item['type'] != 'breaking_criteria' and item['type'] != 'clause':
            CONFIG_ITEM_TYPE_MANIFEST[ item['type'] ].validate( item['config'] )
        # breaking criteria validation is already done; or so one hopes.
