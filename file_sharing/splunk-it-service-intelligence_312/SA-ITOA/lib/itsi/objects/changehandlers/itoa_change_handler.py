# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n

"""
Abstract class defining the contract for a change handler
"""


class ItoaChangeHandler(object):
    def __init__(self, logger, session_key):
        super(ItoaChangeHandler, self).__init__()
        self.logger = logger
        self.session_key = session_key

    def deferred(self, change, transaction_id=None):
        """
        Determine the list of impacted objects from a specific change event
        And then perform any transformations that need to be applied so that we can
        put the system into a consistent state

        Note: If you make any changes to multiple objects, please use the bulk methods

        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: String identifier of the object type in the changed_object
                change_type: The type of change that occurred
                object_type: 'refresh_job'
            }
        @return: A boolean indicating success or failure
        """
        raise NotImplementedError()

    def assert_valid_change_object(self, change):
        """
        @param change: The object describing the change that occurred.
        :raises AttributeError if any required fields are missing or values are of incorrect type
        """
        required_attrs = ['_key', 'create_time', 'changed_object_key', 'changed_object_type', 'change_type',
                          'object_type']
        missing_attr = []
        for attr in required_attrs:
            value = change.get(attr, None)
            if value is None:
                missing_attr.append(attr)

        if len(missing_attr) > 0:
            raise AttributeError(_('Missing the following required attributes: %s') % ','.join(missing_attr))

        changed_object_key = change.get('changed_object_key')
        if not isinstance(changed_object_key, list):
            raise AttributeError(_('Expecting changed_object_key to be of type list'))

        object_type = change.get('object_type')
        if object_type != 'refresh_job':
            raise AttributeError(_('Expecting object_type to equal "refresh_job"'))

    def should_remove_duplicates(self, change):
        """
        Determine if duplicates should be removed for this type of change
        Can be overridden by subclasses, default to false
        @param change: The object describing the change that occurred
        @return: Boolean
        """
        return False
