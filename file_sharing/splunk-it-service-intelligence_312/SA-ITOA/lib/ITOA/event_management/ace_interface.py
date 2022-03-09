# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from ITOA.controller_utils import ITOAError
from ITOA.setup_logging import setup_logging
from ITOA.event_management.notable_event_seed_group import NotableEventSeedGroup


logger = setup_logging("itsi.log", "itsi.rest_handler_splunkd.ace_interface")


class AceInterfaceProvider(ItoaInterfaceProviderBase):

    def __init__(self, session_key, current_user, rest_method):
        self.session_key = session_key
        self.current_user = current_user
        self.rest_method = rest_method.upper()

    def handle_save_seed_groups_from_search_id(self, sid):
        """
        Will save seed groups to the kvstore based on a search id of a search that has already been executed

        @type: basestring
        @param sid: the search id of the search which has the seed group information
        """
        path = '/servicesNS/nobody/SA-ITOA/search/jobs/{}/results'.format(sid)
        offset = 0
        results = []

        # ACE returns a maximum of 200 events, so this loop will break when no more results are found
        while True:
            params = {
                "output_mode": "json",
                "count": 50,
                "offset": offset
            }

            try:
                response, content = rest.simpleRequest(
                    path,
                    sessionKey=self.session_key,
                    method="GET",
                    getargs=params
                )
            except Exception as e:
                logger.exception(e)
                logger.info('Could not find search with sid: {}, seed group save failed'.format(sid))
                raise ITOAError(status='400', message=_('Could not find search with sid: {}, seed group save failed.').format(sid))
            try:
                content = json.loads(content)
                data_list = content.get('results', [])
                # if there are no results returned, then we are done reading results
                if len(data_list) == 0:
                    break
                data_list = [json.loads(data['_raw']) for data in data_list]
                seed_group = NotableEventSeedGroup(self.session_key)
                for data in data_list:
                    seed_group.convert_search_data_to_group_data(data)
                # if this is the first iteration, begin by deleting existing seed groups in KV store
                if offset == 0:
                    if data_list:
                        data = data_list[0]
                        policy_id = data.get("policy_id")
                        if policy_id:
                            filter_data = {"policy_id":policy_id}
                            logger.info("Deleting seed groups from KV store of policy %s", policy_id)
                            seed_group.delete_bulk(None, filter_data=filter_data)
                        else:
                            seed_group.delete_bulk(None)
                results += seed_group.create_bulk(data_list)
                logger.info("Saving seed groups to KV store, current offset: %s", offset)
            except Exception as e:
                message = str(e)
                logger.error('saving seed groups failed with: %s', message)
                logger.exception(e)
                raise ITOAError(status='500', message=message)

            # increment results reader offset by our count
            offset += params.get("count")

        # response will be an array of group ids
        return results
