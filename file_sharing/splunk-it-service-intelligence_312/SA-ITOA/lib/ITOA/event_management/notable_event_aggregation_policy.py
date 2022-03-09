# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
A Notable Event Aggregation Policy consists of the following:
    1. a filter criteria that "collects" or labels a bunch of notable events into
        a logical group
    2. a severity that can be assigned to this logical bundle which can then
        be displayed on the Notable event viewer
    3. a breaking criteria that tells the Rules Engine to break out of the
        existing group (and start a new group)
    4. one or more rules  which can be applied to one/some/all events in
        this logical bundle of notables when a certain Activation Criteria
        is met.
"""
import time
import json

from splunk.auth import getCurrentUser
from splunk import ResourceNotFound
from splunk.appserver.mrsparkle.lib import i18n

from notable_event_error import NotableEventBadRequest
from ITOA.event_management.notable_event_utils import MethodType
from base_event_management import BaseEventManagement

from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_current_utc_epoch, SplunkUser
from ITOA.itoa_exceptions import ItoaAccessDeniedError

from rules_engine.rule import Rule
from rules_engine.criterion import FilterCriteria, BreakingCriteria


class NotableEventAggregationPolicy(BaseEventManagement):
    """
    A Notable policy as persisted in kv store:
    For a more up-to-date schema, please refer to README.md under rules_engine/
    {
        "_key": <string, policy_id>,
        "title": <string, policy name>,
        "description":  <string, policy description>,
        "filter_criteria":  <Clause*>,  /* permitted Item* types:
                                            "notable_event_field".
                                            Example: where event title matches
                                            '*.sv.splunk.com'>
                                        */
        "split_by_field": <string, field name>,
        "breaking_criteria": <Clause*>, /* permitted Item* types:
                                            'notable_event_field',
                                            'notable_event_count',
                                            'pause',
                                            'duration'
                                        */
        "priority": 5,                  // default for now
        "group_severity" <number>,      // severity to assign this logical group
        "rules": [ <Rule* object> ]
    }
    """
    DEFAULT_PRIORITY = '5'

    def __init__(self,
            session_key,
            current_user_name=None,
            collection="itsi_notable_event_aggregation_policy",
            object_type="notable_aggregation_policy",
            user='nobody', is_validate=True):
        """
        Initialize a Notable Event Aggregation Policy
        """
        if any([
            not isinstance(session_key, basestring),
            isinstance(session_key, basestring) and not session_key.strip()]):
            raise NotableEventBadRequest(_('Bad session key.'))
        if any([
            not isinstance(user, basestring),
            isinstance(user, basestring) and not user.strip()]):
            raise NotableEventBadRequest(_('Bad owner. Received=%s.') % user)
        if any([
            not isinstance(object_type, basestring),
            isinstance(object_type, basestring) and not object_type.strip()]):
            raise NotableEventBadRequest(_('Bad object type. Received=%s.') % object_type)
        if any([
            not isinstance(collection, basestring),
            isinstance(collection, basestring) and not collection.strip()]):
            raise NotableEventBadRequest(_('Bad collection name. Received=%s.') % collection)

        # in addition to the schema, other meta data are persisted. these are:
        self.mod_time_key = 'mod_time'
        self.create_time_key = 'create_time'
        self.identifying_name_key = 'identifying_name'

        # we need to turn off some validation for default policy
        self.is_validate = is_validate

        self.logger = setup_logging('itsi_event_management.log', 'itsi.notable_event.rules_engine')

        super(NotableEventAggregationPolicy, self).__init__(
            session_key, collection, object_type, user, current_user_name
        )

    def validate(self, policy, check_policy_id=False, policy_id=None):
        """
        validate a notable event aggregation policy
        @type policy: dict
        @param policy: a notable event aggregation policy

        @type check_policy_id: boolean
        @param check_policy_id: should validate policy id?

        @type policy_id: basestring
        @param policy_id: validate policy_id if check_policy_id is True

        @returns nothing
        """
        if isinstance(policy, basestring):
            try:
                policy = json.loads(policy)
            except Exception,e:
                self.logger.exception(e)
                self.logger.error('Received policy=%s', policy)
                raise NotableEventBadRequest(e)

        if check_policy_id and not isinstance(policy_id, basestring):
            raise NotableEventBadRequest(_('Policy_id is not a string. Data type=%s.') % type(policy_id).__name__)

        if not isinstance(policy, dict):
            raise NotableEventBadRequest(_('Data is not a valid dictionary, data type=%s.') % type(policy).__name__)

        req_keys = ('title', 'filter_criteria', 'breaking_criteria', 'group_severity', 'rules')

        # expect policy to have more than req_keys

        if not set(req_keys).issubset(set(policy.keys())):
            raise NotableEventBadRequest(_('Missing required key. Received=%s. Required=%s.') % (policy, req_keys))

        # validate other k-v pairs present in Notable Policy
        if self.is_validate:
            FilterCriteria.validate(policy['filter_criteria'])

        BreakingCriteria.validate(policy['breaking_criteria'])

        rules = policy.get('rules')
        if not isinstance(rules, list):
            raise NotableEventBadRequest(_('Expecting a list of rules. Received=%s Type=%s.') % (
                rules, type(rules).__name__))

        if self.is_validate:
            for rule in rules:
                Rule.validate(rule)

    def pre_processing(self, data_list, method):
        """
        Adds create time / modified time information in the data
        based on method type.

        @type data_list: list
        @param data_list: list of data to validate and add time, user info etc

        @type method: basestring
        @param method: method type

        @rtype: list
        @return: returns updated data (does in-place replacement of input)
        """
        if not isinstance(data_list, list):
            raise TypeError(_('Data is not a valid list, data_list type is %s.'), type(data_list).__name__)

        for data in data_list:
            if not isinstance(data, dict):
                raise TypeError(_('Data is not a valid dictionary. data type is: %s.'), type(data).__name__)
            session_user = getCurrentUser().get('name')
            user = session_user if session_user else self.owner
            time_value = get_current_utc_epoch()
            if method == MethodType.CREATE:
                data[self.create_time_key] = time_value
            if method != MethodType.DELETE:
                data[self.mod_time_key] = time_value
                # We require an identifying name field for objects we sort using the saved pages system
                data[self.identifying_name_key] = str(data.get('title', '')).strip().lower()


        return data_list

    def create(self, policy, **kwargs):
        """
        create a Notable Event Aggregation Policy
        @type policy: dict/json type string
        @param policy: aggregation policy

        @type kwargs: dict
        @param kwargs: other k-v arguments which will never be used.
            Mentioned here because of the way we wire things up.
        """
        self.validate(policy)
        return super(NotableEventAggregationPolicy, self).create(policy, **kwargs)

    def create_bulk(self, policies, **kwargs):
        """
        Create Notable Event Aggregation Policies in bulk
        @type policies: list
        @param policy: policies to create en-bulk

        @type kwargs: dict
        @param kwargs: other k-v arguments which will never be used.
            Mentioned here because of the way we wire things up.
        """
        for policy in policies:
            self.validate(policy)
        return super(NotableEventAggregationPolicy, self).create_bulk(policies,
                **kwargs)

    def validate_user_permission(self, policy_id):
        """
        Validate if the current user could edit Notable Event Aggregation Policy
        @type policy_id: basestring
        @param policy_id: a unique id for this given policy

        @rtype : None
        """
        if policy_id == 'itsi_default_policy':
            roles_for_current_user, all_roles_for_current_user = SplunkUser.get_roles_for_user(
                self.current_user_name, self.session_key, self.logger)
            if "itoa_admin" not in all_roles_for_current_user:
                raise ItoaAccessDeniedError(
                    _('Access denied. Default Aggregation Policy can only be edited by itoa_admin role.'), self.logger)

    def update(self, policy_id, policy, is_partial_update=False, **kwargs):
        """
        update an existing Notable Event Aggregation Policy
        @type policy_id: basestring
        @param policy_id: a unique id for this given policy

        @type policy: dict
        @param policy: the concerned policy

        @type kwargs: dict
        @param kwargs: other k-v arguments which will never be used.
            Mentioned here because of the way we wire things up.
        """
        self.validate_user_permission(policy_id)
        self.validate(policy, check_policy_id=True, policy_id=policy_id)
        return super(NotableEventAggregationPolicy, self).update(policy_id,
                policy, is_partial_update=is_partial_update, **kwargs)

    def delete(self, policy_id, **kwargs):
        """
        delete an existing Notable Event Aggregation Policy
        @type policy_id: basestring
        @param policy_id: a unique id for this given policy

        @type kwargs: dict
        @param kwargs: other k-v arguments which will never be used.
            Mentioned here because of the way we wire things up.
        """
        # no validations needed here
        return super(NotableEventAggregationPolicy, self).delete(policy_id,
                **kwargs)

    def delete_bulk(self, policy_ids, **kwargs):
        """
        delete existing Notable Event Aggregation Policy objects in bulk
        @type policy_ids: list
        @param policy_ids: ids of policies to delete

        @type kwargs: dict
        @param kwargs: any filter criteria can be passed in keyed by
            `filter_data`
        """
        # no validations needed
        return super(NotableEventAggregationPolicy, self).delete_bulk(
                policy_ids, **kwargs)

    def get(self, policy_id, **kwargs):
        """
        @type policy_id: basestring
        @param policy_id: a unique id for this given policy

        @type kwargs: dict
        @param kwargs: other k-v arguments which will never be used.
            Mentioned here because of the way we wire things up.
        """
        # no validations needed here
        ret = super(NotableEventAggregationPolicy, self).get(policy_id,
                **kwargs)
        if not ret:
            raise ResourceNotFound(_("Object %s does not exist.") % policy_id)
        return ret

    def get_bulk(self, policy_ids, **kwargs):
        """
        @type policy_ids: list
        @param policy_ids: list of policy ids to fetch

        @type kwargs: dict
        @param kwargs: might contain filter criteria keyed by `filter_data`
        """
        # no validations needed here
        return super(NotableEventAggregationPolicy, self).get_bulk(policy_ids,
                **kwargs)
