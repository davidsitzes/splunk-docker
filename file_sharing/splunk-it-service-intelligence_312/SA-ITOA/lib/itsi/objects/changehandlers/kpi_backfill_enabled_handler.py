# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
This change handler generates backfill data for the summary index.
'''
from . import itoa_change_handler

from splunk.appserver.mrsparkle.lib import i18n
from itsi.searches.itsi_searches import ItsiKpiSearches
from ITOA.itoa_common import get_current_utc_epoch
from itsi.backfill.itsi_backfill_requests import BackfillRequestModel
from itsi.objects.itsi_service import ItsiService


class KpiBackfillEnabledHandler(itoa_change_handler.ItoaChangeHandler):
    """
    If a KPI has backfill enabled, this change handler will potentially request a backfill
    If the earliest event in the summary index for the KPI is earlier than the request backfill time, nothing is done
    If there is existing events in the summary index but requesting earlier backfill we backfill up to that event
    """

    def deferred(self, change, transaction_id=None):
        """
        Create and update searches when we have determined that the user has backfill enabled
        @param change: Must have changed_object_type == service and change_type == 'service_kpi_backfill_enabled'
        @return: Boolean
        """
        if change.get('changed_object_type') != 'service':
            raise Exception(_('Expected changed_object_type to be "service"'))

        if change.get('change_type') != 'service_kpi_backfill_enabled':
            raise Exception(_('Expected change_type to be "service_kpi_backfill_enabled"'))

        service_interface = ItsiService(self.session_key, 'nobody')

        # Get backfill request data
        interface = BackfillRequestModel.initialize_interface(self.session_key)
        backfill_requests = []
        change_detail = change.get("change_detail", {})
        for service_key, detail in change_detail.iteritems():
            service = service_interface.get('nobody', service_key, transaction_id=transaction_id)
            if service is None:
                self.logger.warning("Skipping service - missing from kvstore service_key=%s tid=%s", service_key, transaction_id)
                continue
            kpi_ids = detail['kpis']
            kpis = []
            for kpi in service.get('kpis', []):
                if kpi.get('_key') in kpi_ids:
                    kpis.append(kpi)
            for kpi in kpis:
                kpi['service_id'] = service.get('_key')
                kpi['service_title'] = service.get('title')
                itsi_searches = ItsiKpiSearches(self.session_key, kpi, sec_grp=service.get('sec_grp'))

                latest_epoch_time = get_current_utc_epoch()
                earliest_epoch_time = latest_epoch_time - self.get_epoch_time_from_relative_time(kpi.get('backfill_earliest_time'))
                backfill_search = itsi_searches.gen_backfill_search()

                # create backfill request
                backfillData = {
                    "earliest": earliest_epoch_time,
                    "latest": latest_epoch_time,
                    "search": backfill_search['backfill_search'],
                    "kpi_id": kpi.get("_key"),
                    "kpi_title": kpi.get("title"),
                    "kpi_alert_period": int(kpi.get("alert_period", 5)),
                    "status": "new"
                }

                request_model = BackfillRequestModel(backfillData, interface=interface)
                backfill_requests.append(request_model)

        impacted_objects = {'backfill_requests': backfill_requests}

        if impacted_objects is None:
            return True  # Noop

        if len(impacted_objects.get('backfill_requests', [])) == 0:
            return True  # Noop

        for backfill_request in impacted_objects.get('backfill_requests', []):
            backfill_request.save()

        status_ok = True
        return status_ok

    @staticmethod
    def get_epoch_time_from_relative_time(relative_time):
        """
        Convenience method to convert a set of relative_time to seconds
        @param relative_time:
        @return:
        """
        second_multiplier = 24 * 60 * 60
        seconds = 0
        if relative_time == '-7d':
            seconds = 7 * second_multiplier
        elif relative_time == '-14d':
            seconds = 14 * second_multiplier
        elif relative_time == '-30d':
            seconds = 30 * second_multiplier
        elif relative_time == '-60d':
            seconds = 60 * second_multiplier

        return seconds
