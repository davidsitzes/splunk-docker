# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This module represents sub-types of various clause items.
Each sub-type's validation is self contained.
"""
from splunk.appserver.mrsparkle.lib import i18n

class CIConfigNotableEventField(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(notable_event_field_item):
        pass #TODO

class CIConfigNotableEventCount(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(count_item):
        pass #TODO

class CIConfigDuration(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(duration_item):
        pass #TODO

class CIConfigPause(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(notable_event_field_item):
        pass #TODO

class CIConfigNotableEventExecuteAction(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(notable_event_execute_action_item):
        pass

class CIConfigNotableEventChange(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(notable_event_change_item):
        pass

class CIConfigNotableEventComment(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate (notable_event_comment_item):
        pass

class CIConfigNotableEventTag(object):
    def __init__(self, **kwargs):
        raise TypeError(_('Cannot instantiate this class. Call'
            ' `Item.validate(item)`'))

    @staticmethod
    def validate(notable_event_tag_item):
        pass
