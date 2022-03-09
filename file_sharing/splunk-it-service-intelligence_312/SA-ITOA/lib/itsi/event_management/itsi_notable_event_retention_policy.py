#Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.event_management.notable_event_retention_policy import RetentionPolicy
from ITOA.itoa_common import get_current_utc_epoch
from ITOA.setup_logging import setup_logging


class ItsiNotableEventRetentionPolicy(RetentionPolicy):

    def __init__(self, session_key, owner='nobody', app='SA-ITOA'):
        self.app = app
        self.owner = owner
        self.session_key = session_key
        self.logger = setup_logging('itsi_event_management.log', 'itsi.notable_event.retention_policy')
        # HEC Init has those details like index, host, source, sourcetype of index...
        super(ItsiNotableEventRetentionPolicy, self).__init__(session_key, 'itsi_notable_event_retention',
                                                              token_name='Auto Generated ITSI Notable Event Retention Policy Token',
                                                              app=self.app, owner=self.owner, logger=self.logger)
        self.retention_time_key = 'retentionTimeInSec'

    def get_filter_string(self, retention_policy, time_key='mod_time'):
        """
        Return filter to move events from kvstore to index

        @type retention_policy: dict
        @param retention_policy: retention policy dict

        @type time_key: basestring
        @param time_key: which hold key name which is time based key

        @rtype: String
        @return: FilterString to get only expired object from KV
        """
        if not retention_policy.get(self.retention_time_key):
            self.logger.error('Could not find retention time in settings=%s, key=%s', retention_policy,
                              self.retention_time_key)
            raise ValueError(_('Invalid retention time={0}, expected key={1}.').format(str(retention_policy),
                                                                                  self.retention_time_key))

        filter_data = {time_key:
                           {'$lte': get_current_utc_epoch() - float(retention_policy.get(self.retention_time_key))}}
        return filter_data
