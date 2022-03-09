# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json

from .itoa_change_handler import ItoaChangeHandler
from ITOA.saved_search_utility import SavedSearch


#TODO: Rename this class to be more generic.  It will now handle more than one kpi update
class KpiCreateUpdateHandler(ItoaChangeHandler):
    """
    Source:
        this job only applies when a service has more than 10 kpis

    This handler does the following
        - Get kpi and its saved search settings
        - create or update existing search for that kpi
    """

    def deferred(self, change, transaction_id=None):
        """
        Locates and updates searches related to this change

        @param change: dict
        @param change: The object describing the change that occurred
            {
                _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: String identifier of the object type in the changed_object
                change_type: The type of change that occurred
                object_type: 'refresh_job'
                change_detail: dict of kpi and its saved search settings
            }

        @rtype Boolean
        @return: True or False depending on the operation
        """
        saved_searches = {}
        for key, value in change.get('change_detail', {}).iteritems():
            # TODO ITOA-6192: search data should probably be generated here rather than
            # being pulled from queue. Doing it here would mean that the job
            # size reduces significantly.
            # Also, saving KPIs numbering greater than 11 should become a faster process.
            search_data = json.loads(value.get('search_data'))
            search_name = search_data.get('name')
            saved_searches[search_name] = search_data
            kpi_title = value.get('kpi_title')
            self.logger.info("Creating/updating saved search for kpi=%s, saved_search_name=%s", kpi_title, search_name)

        is_successful = True
        for search_name, search_data in saved_searches.iteritems():
            try:
                acl_update = search_data.pop('acl_update', True)
                SavedSearch.update_search(self.session_key, search_name, 'itsi', 'nobody', **search_data)
                if acl_update:
                    SavedSearch.update_acl(
                            self.session_key,
                            search_name,
                            'nobody')
                self.logger.info("Successfully saved search=%s", search_name)
            except Exception:
                self.logger.exception("Failed to saved search=%s", search_name)
                is_successful = False
        return is_successful
