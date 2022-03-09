# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Contains the classes related to kpi base searches.  Namely the following
- KpiBaseSearchUpdateHandler - whenever a KPIBaseSearch is updated, we update the dependent services
- KpiBaseSearchDeleteHandler - whenever a KPIBaseSearch is deleted, we update a single KPI so that
  the KPI no longer reference the base search
NOTE: As of the time of this writing (1/14/2015) These are the only workflows we are expecting.
We are NOT expecting the user to currently be able to associate kpis with kpi base search templates
when a user modifies or creates a base search
"""
import json
from .itoa_change_handler import ItoaChangeHandler
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch
from ITOA import itoa_common as utils


class KpiBaseSearchUpdateHandler(ItoaChangeHandler):
    """
    This handler updates the associated KPIs for a service when the base handler change,
    and it does so in the following steps
    1) Get the base search associated with the KPI, change the search and invoke the KpiCreateUpdateHandler
       So that the search and all other artifacts get updated appropriately
    """

    def deferred(self, change, transaction_id=None):
        """
        The change should only cover one impacted object, but we'll make sure that it can cover
        multiple kpi base searches

        Updated impacted object
        @type change: dict
        @param change: as describe in assess_impacted_objects

        @rtype bool
        @return: Return True or False
        """
        existing_ids = []
        bs_ids = change.get("changed_object_key")

        change_detail = change.get("change_detail")
        if change_detail:
            existing_ids = change_detail.get("existing_ids", [])

        if not isinstance(bs_ids, list):
            self.logger.error("No base search list passed into handler - skipping")
            return True
        for bs_id in bs_ids:
            # For each base search id, get the services and update
            self.logger.debug("Updating shared base search for base_search_id=%s" % bs_id)
            adhoc_search = ItsiSharedAdhocSearch(self.session_key, bs_id)
            if len(adhoc_search.services) > 0:
                self.logger.debug("Creating base search for base_search_id=%s", bs_id)
                if bs_id in existing_ids:
                    acl_update = False
                else:
                    acl_update = True
                status = adhoc_search.create_splunk_search(acl_update=acl_update)
            else:
                self.logger.debug("Deleting base search for base_search_id=%s", bs_id)
                status = adhoc_search.delete_splunk_search()

        return status

    def should_remove_duplicates(self, change):
        """
        In the event of a entity/service update, base search updates will be triggered multiple times
        This could be avoided by removing duplicate jobs to make it handled only once at the end of change chain
        @param change: The object describing the change that occurred
        @return: Always return True
        """
        return True
