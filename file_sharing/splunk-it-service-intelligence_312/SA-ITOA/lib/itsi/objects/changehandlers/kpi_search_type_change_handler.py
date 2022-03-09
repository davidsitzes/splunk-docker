# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from .itoa_change_handler import ItoaChangeHandler
from ITOA.saved_search_utility import SavedSearch
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_kpi import ItsiKpi


class KpiSearchTypeHandler(ItoaChangeHandler):
    """
        Handler to delete old saved search because user changed from adhoc/datamodel to shared based
        search
    """
    def deferred(self, change, transaction_id=None):
        """
        Handler which access what kpi is being changed from ad-hoc/datamodel to shared based
        And deletes the appropriate saved searches if required
        @type change: dict
        @param change: dict which hold job information
        {       _key: system generated key
                create_time: epoch time of the CUD event that occurred
                changed_object_key: [key(s) of the changed object(s)]
                changed_object_type: String identifier of the object type in the changed_object
                change_type: The type of change that occurred
                object_type: 'refresh_job'
                change_detail:
        }
        @return: True if all operations were successful, False otherwise
        @rtype: Boolean
        """
        # Access if given set of kpis still on shared search before we delete savedsearch entry
        change_detail = change.get('change_detail') if change.get('change_detail') else {}
        service_object = ItsiService(self.session_key, 'nobody')

        if len(change_detail):
            filter_data = {'$or': [{'_key': service_id} for service_id in change_detail.iterkeys()]}
            fetched_services = service_object.get_bulk(
                'nobody', fields=['_key', 'kpis.base_search_id', 'kpis.search_type', 'kpis._key'],
                filter_data=filter_data, transaction_id=transaction_id)
        else:
            fetched_services = []

        is_still_shared_search = {}
        for service in fetched_services:
            is_still_shared_search.update(service_object.get_shared_search_type(service))

        valid_kpi_ids = []
        for kpi_ids in change_detail.itervalues():
            for kpi_id in kpi_ids:
                if kpi_id not in is_still_shared_search:
                    self.logger.info('kpi id=%s is no longer a shared based search', kpi_id)
                    continue
                valid_kpi_ids.append(kpi_id)
        self.logger.debug('%s kpis ids=%s changed to ad-hoc/datamodel to shared search',
                          len(valid_kpi_ids), valid_kpi_ids)

        ret = True
        for kpi_id in valid_kpi_ids:
            search_name = ItsiKpi.get_kpi_saved_search_name(kpi_id)
            try:
                ret = ret and SavedSearch.delete_search(self.session_key, search_name)
                if ret:
                    self.logger.info('Successfully deleted kpi=%s', search_name)
                else:
                    self.logger.error('Failed to delete %s search', search_name)
            except Exception as e:
                self.logger.error('Failed to delete saved search=%s, which has changed to ad-hoc/datamodel type to'
                                  'shared type. This could cause deduplicate entry in summary index', search_name)
                self.logger.exception(e)
                ret = False
        return ret
