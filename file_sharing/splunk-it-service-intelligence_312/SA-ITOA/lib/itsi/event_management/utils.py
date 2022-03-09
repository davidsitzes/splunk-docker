# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import sys
import time

from splunk import ResourceNotFound
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.event_management.notable_event_utils import NotableEventConfiguration
from ITOA.setup_logging import setup_logging
from ITOA.event_management.notable_event_aggregation_policy import NotableEventAggregationPolicy
from ITOA.event_management.notable_event_utils import get_collection_name_for_event_management_objects

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess

class NotableEventValidator(object):
    """
    Notable event validator
    """

    def __init__(self, session_key, logger, required_keys=None):
        self.session_key = session_key
        self.owner_key = 'owner'
        self.status_key = 'status'
        self.severity_key = 'severity'
        if required_keys is None:
            self.required_keys = ['_time', 'mod_time', 'title', self.owner_key, self.status_key, self.severity_key]
        else:
            self.required_keys = required_keys

        if logger:
            self.logger = logger
        else:
            raise ValueError(_('logger is not provided'))

        self.notable_configuration_object = NotableEventConfiguration(session_key, logger)

        self.valid_owners = self.notable_configuration_object.get_owners()
        self.valid_statuses = self.notable_configuration_object.get_statuses()
        self.valid_severities = self.notable_configuration_object.get_severities()

    def validate_schema(self, data):
        """
        Validate schema before user CURD operation on notable event

        @type data: dict
        @param data: data which hold notable schema to create

        @rtype: bool
        @return: True - if data contains all required fields, False - otherwise or throw exception
        """

        # Check for status, owner and severity is defined, otherwise set to default.
        if data.get(self.owner_key) is None or data.get(self.owner_key) == '':
            self.logger.info('No owner is being set for event title=%s, hence setting to default owner', data.get('title'))
            data[self.owner_key] = self.notable_configuration_object.get_default_owner()
        if data.get(self.status_key) is None or data.get(self.status_key) == '':
            self.logger.info('No status is being set for event title=%s, hence setting to default status', data.get('title'))
            data[self.status_key] = self.notable_configuration_object.get_default_status()
        if data.get(self.severity_key) is None or data.get(self.severity_key) == '':
            self.logger.info('No severity is being set for event title=%s, hence setting to default severity', data.get('title'))
            data[self.severity_key] = self.notable_configuration_object.get_default_severity()

        for key in self.required_keys:
            if key not in data:
                message = _("%s key does not exist in the data=%s.") % (key, str(data))
                self.logger.error(message)
                raise ValueError(message)

        # Make sure status, severity value is str
        data[self.owner_key] = str(data.get(self.owner_key, ''))
        data[self.status_key] = str(data.get(self.status_key, ''))
        data[self.severity_key] = str(data.get(self.severity_key, ''))
        # Lets have more logging and proper error if validation failed.
        is_validate = True
        error_message = ''

        is_validate = is_validate and self.check_owner(data.get(self.owner_key))
        if not is_validate:
            error_message = _('Invalid owner={0}. Unable to find owner in valid Splunk user list.').format(data.get(self.owner_key))
            self.logger.error(error_message)
            raise ValueError(error_message)
        is_validate = is_validate and self.check_status(data.get(self.status_key))
        if not is_validate:
            error_message = _('Invalid status={0}. Unable to find status in itsi_notable_event_status.conf.').format(data.get(self.status_key))
            self.logger.error(error_message)
            raise ValueError(error_message)
        is_validate = is_validate and self.check_severity(data.get(self.severity_key))
        if not is_validate:
            error_message = _('Invalid severity={0}. Unable to find severity in itsi_notable_event_severity.conf.').format(data.get(self.severity_key))
            self.logger.error(error_message)
            raise ValueError(error_message)
        return is_validate

    def check_severity(self, severity):
        """
        Check severity

        @type severity: basestring
        @param severity: severity

        @rtype: bool
        @return: True if valid severity otherwise False
        """
        return severity in self.valid_severities

    def check_status(self, status):
        """
        Check status

        @type status: basestring
        @param status: Status

        @rtype: bool
        @return: True if valid status otherwise False
        """
        return status in self.valid_statuses

    def check_owner(self, owner):
        """
        Check owner is valid or not

        @type owner: basestring
        @param owner: owner

        @rtype: bool
        @return: True if valid owner otherwise False
        """
        return owner in self.valid_owners


class NotableEventDefaultPolicyLoader(object):
    """
        This class is being used to load default aggregation policy
    """
    DEFAULT_POLICY = """
        {
            "_key": "itsi_default_policy",
            "group_title": "%title%",
            "group_description": "%description%",
            "group_status": "%status%",
            "group_assignee": "%owner%",
            "disabled": 0,
            "is_default": 1,
            "object_type": "notable_aggregation_policy",
            "title": "Default Policy",
            "description": "Applies to events that do not meet the criteria of any other active policy.",
            "split_by_field": "source",
            "priority": 5,
            "group_severity": "%severity%",
            "filter_criteria": {
                "condition": "OR",
                "items": []
            },
            "breaking_criteria": {
                "condition": "OR",
                "items": [
                    {
                        "type": "pause",
                        "config": {
                            "limit": "7200"
                        }
                    }
                ]
            },
            "rules": []
        }
        """

    def __init__(self, session_key, logger=None):
        if not isinstance(session_key, basestring):
            raise TypeError(_('Invalid session key'))
        self.session_key = session_key
        self.logger = logger if logger is not None else setup_logging('itsi_event_management.log',
                                                                      'itsi.notable_event.default.policy.loader')
        self.notable_event_aggregator = NotableEventAggregationPolicy(session_key, is_validate=False)

    def upload_default_policy(self):
        """
        Upload default policy
        @return: True/False - if default policy is loaded successfully or not
        """
        _id = 'itsi_default_policy'
        if not self.notable_event_aggregator.storage_interface.wait_for_storage_init(self.session_key):
            raise Exception(_("KV Store failed to initialize in time"))
        try:
            result = self.notable_event_aggregator.get(_id)

            if result:
                self.logger.info('Found %s' % _id)
                return True
            else:
                self.logger.info('Could not find %s' % _id)
                raise ResourceNotFound('%s does not exist' % _id)
        except ResourceNotFound as e:
            # load now
            self.logger.exception(e)
            self.logger.info('creating policy because we did not find default policy')
            ret = self.notable_event_aggregator.create(json.loads(self.DEFAULT_POLICY))

            # note this is not object type
            o_type = 'notable_event_aggregation_policy'

            success, rval = UserAccess.bulk_update_perms(
                object_ids=[_id],
                acl= {'read': ['*'], 'write': ['*'], 'delete': ['*']},
                object_app='itsi',
                object_type= o_type,
                object_storename=get_collection_name_for_event_management_objects(o_type),
                session_key=self.session_key,
                logger=self.logger
            )
            if not success:
                self.logger.error('Unable to save acl for %s. Response: `%s`', _id, rval)
            else:
                self.logger.info('Successfully saved acl for %s. Response:`%s`', _id, rval)

            return True if ret else False


class CorrelationSearchDefaultAclLoader(object):
    """
    This class sets the ACL permissions for the default correlation search
    'Monitor Critical Service Based on HealthScore'
    """
    DEFAULT_ACL = {'read': ['*'], 'write': ['*'], 'delete': ['*']}

    def __init__(self, session_key, logger=None):
        if not isinstance(session_key, basestring):
            raise TypeError(_('Invalid session key'))
        self.session_key = session_key
        self.logger = logger if logger is not None else setup_logging(
            'itsi_event_management.log',
            'itsi.correlation_search.default.acl.loader')
        self.retrys = 120

    def default_acl_loader(self):
        """
        Set perms for default correlation search
        @return:
        """
        _id = 'Monitor Critical Service Based on HealthScore'
        o_type = 'correlation_search'
        rval = 'Already created'

        perms = UserAccess.get_perms(
            object_id=_id,
            object_app='itsi',
            object_type=o_type,
            object_storename=get_collection_name_for_event_management_objects(
                o_type),
            session_key=self.session_key,
            logger=self.logger,
            object_owner='nobody'
        )

        while not perms and self.retrys > 0:
            self.logger.info('Trying to save acl for %s.', _id)
            success, rval = UserAccess.update_perms(
                object_id=_id,
                acl=self.DEFAULT_ACL,
                object_app='itsi',
                object_type=o_type,
                object_storename=(
                    get_collection_name_for_event_management_objects(o_type)),
                session_key=self.session_key,
                logger=self.logger
            )

            perms = UserAccess.get_perms(
                object_id=_id,
                object_app='itsi',
                object_type=o_type,
                object_storename=get_collection_name_for_event_management_objects(
                    o_type),
                session_key=self.session_key,
                logger=self.logger,
                object_owner='nobody'
            )

            self.retrys -= 1
            time.sleep(0.5)

        if not perms:
            self.logger.error(
                'Unable to save acl for %s. Response: `%s`', _id, rval)
        else:
            self.logger.info(
                'Successfully saved acl for %s. Response:`%s`', _id, rval)

