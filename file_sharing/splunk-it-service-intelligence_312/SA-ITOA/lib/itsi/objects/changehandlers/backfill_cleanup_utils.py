# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import logging
from splunk.clilib.bundle_paths import make_splunkhome_path

from itsi.backfill import BackfillStatus
from itsi.backfill.itsi_backfill_requests import BackfillRequestCollection


def get_backfill_records(session_key, backfill_enabled_kpis):
    '''
    Get a list of backfill records from a list of KPI IDs
    @param session_key
    @param backfill_enabled_kpis: array of KPI IDs
    @returns array of `BackfillRequestModel`s
    '''
    if len(backfill_enabled_kpis) > 0:
        backfill_collection = BackfillRequestCollection(session_key=session_key)
        kpifilter = {'$or': [{"kpi_id": x} for x in backfill_enabled_kpis]} if len(backfill_enabled_kpis) else None
        backfill_collection.fetch(filters=kpifilter)
        return backfill_collection.models
    else:
        return []


def cancel_or_delete_backfill_records(backfill_records, logger=None):
    '''
    If the backfill is done, delete that record, else send cancellation request
    @param backfill_records: array of `BackfillRequestModel`s
    @returns True if function completes without exceptions
    '''
    def log_exception(e, message):
        if logger is not None:
            logger.exception(message)

    delete_list = []
    cancel_list = []
    for backfill_request in backfill_records:
        if backfill_request.get('status') == BackfillStatus.STATUS_DONE:
            delete_list.append(backfill_request)
        else:
            cancel_list.append(backfill_request)
    for x in delete_list:
        try:
            x.delete()
        except Exception as e:
            log_exception(e, "Failed to delete backfill record")
    for x in cancel_list:
        try:
            x.update({'cancellation_flag': BackfillStatus.STATUS_CANCELLATION_REQUESTED})
        except Exception as e:
            log_exception(e, "Failed to update backfill record")
    return True
