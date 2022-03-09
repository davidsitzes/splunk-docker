# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import time
from abc import ABCMeta, abstractmethod
import splunk.rest as splunk_rest
from splunk.util import safeURLQuote
from splunk.appserver.mrsparkle.lib import i18n

# We have used interface defined in ITOA for KV store, user may need it this file as well whenever this sdk moved
# to common component
from ITOA.storage import itoa_storage
from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_current_utc_epoch
from push_event_manager import PushEventManager


class RetentionPolicy:
    __metaclass__ = ABCMeta

    def __init__(self, session_key, conf_file_name, owner='nobody', app='SA-ITOA',
                 token_name='Auto Notable Event Retention Policy Token', logger=None):
        """
        Initialize class which fetch retention policy from conf file and identify
        @param session_key: session key
        @param conf_file_name: conf file name
        @return: instance
        """
        if not session_key:
            raise TypeError(_('Session key is not defined, session_key=%s'), session_key)
        self.session_key = session_key
        self.conf_file_name = conf_file_name
        self.owner = owner
        self.app = app
        self.logger = logger if logger else setup_logging('notable_event_retention_policy.log',
                                                          'notable.retention_policy')
        self.retention_policies = self.get_conf_data()
        self.event_pusher = PushEventManager(self.session_key, token_name)

    @abstractmethod
    def get_filter_string(self, retention_policy, time_key='mod_time'):
        """
        Return filter to move events from kvstore to index

        @type retention_policy: int
        @param retention_policy: retention policy in sec for that collection

        @type time_key: basestring
        @param time_key: which hold key name which is time based key

        @rtype: String
        @return: FilterString to get only expired object from KV
        """
        raise NotImplementedError(_('Function has not been implemented by inherit class'))

    def execute(self):
        """
        Invoke this function to perform operation

        @return: None
        """
        for collection_name, retention_policy_settings in self.retention_policies.iteritems():
            try:
                storage_interface = itoa_storage.ITOAStorage(collection=collection_name)
                object_type = retention_policy_settings.get('object_type', None)
                if not object_type:
                    self.logger.error(
                        'Invalid object type, hence removing skipping retention settings=%s',
                        retention_policy_settings)
                    continue
                filter_data = self.get_filter_string(retention_policy_settings)
                self.logger.info('Filter string=%s for object_type=%s', str(filter_data),
                                 object_type)
                if not filter_data:
                    self.logger.error('Could not get filter string for object=%s, settings=%s',
                                      object_type,
                                      str(retention_policy_settings))
                    continue
                events = storage_interface.get_all(self.session_key, self.owner, object_type,
                                                   sort_key='mod_time',
                                                   sort_dir='asc', filter_data=filter_data)
                self.logger.info('Fetched %s events from collection=%s', len(events),
                                 collection_name)

                self.event_pusher.push_events(events)
                storage_interface.delete_all(self.session_key, self.owner, object_type,
                                             filter_data=filter_data)
                self.logger.info('Successfully moved events=%s,object_type=%s, filter_string=%s',
                                 len(events),
                                 object_type, str(filter_data))
            except Exception as e:
                self.logger.error('Failed to remove objects from collection=%s, settings=%s',
                                  collection_name, str(retention_policy_settings))
                self.logger.exception(e)

    def get_conf_data(self):
        """
        Get data from conf file and return back retention policy for each collection

        @rtype: dict
        @return: dict which contain retention policy for each collection. dict key would be collection name
        """
        retention_policy_dict = {}
        uri = safeURLQuote(
            '/servicesNS/' + self.owner + '/' + self.app + '/configs/conf-' + self.conf_file_name)
        res, contents = splunk_rest.simpleRequest(uri, sessionKey=self.session_key,
                                                  getargs={'output_mode': 'json',
                                                           'count': -1,
                                                           'search': 'disabled=0'})
        if res.status == 200:
            json_contents = json.loads(contents)
            for entry in json_contents.get('entry', []):
                retention_policy_dict[entry.get('name')] = entry.get('content', {})
            self.logger.debug('Retention policy="%s"', retention_policy_dict)
            self.logger.info('Successfully fetch retention policy information from conf file="%s"',
                             self.conf_file_name)
            return retention_policy_dict
        else:
            self.logger.error('Failed to get data from uri="%s", response="%s", contents="%s"', uri,
                              res, contents)
            raise Exception(_('Failed to get data from uri="%s"') % uri)
