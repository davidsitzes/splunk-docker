# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from ITOA.itoa_common import get_itoa_logger, get_current_utc_epoch
from maintenance_services.constants import (
    MAINTENANCE_CALENDAR_OBJECT_TYPE,
    OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE
)
from maintenance_services.maintenance_manifest import SUPPORTED_MAINTENANCE_OBJECT_TYPES
from maintenance_services.objects.maintenance_calendar import MaintenanceCalendar
from maintenance_services.objects.operative_maintenance_record import OperativeMaintenanceRecord

logger = get_itoa_logger('maintenance_services.OperativeMaintenanceLog', 'maintenance_services.log')

class OperativeMaintenanceLog(object):
    def __init__(self, session_key, app="SA-ITOA", user='nobody'):
        '''
        Constructor

        @type: string
        @param session_key:

        @type: string
        @param app: context of app invoking the request

        @type: string
        @param owner: "owner" user invoking this call

        @rtype: None
        @return: None
        '''
        self._session_key = session_key
        self._app = app
        self._user = user

    def populate_operative_maintenance_log(self):
        '''
        Looks up all calendar entries that match criteria for currently being operative
        and populates them in currently operative maintenance log

        @rtype: None
        @return: None
        '''

        # First save away existing records and clear existing operative maintenance log

        operative_maintenance_record_object = OperativeMaintenanceRecord(
            self._session_key,
            self._user
        )

        operative_maintenance_record_object.delete_bulk(self._user)

        # Identify currently operative calendar entries

        maintenance_calendar_object = MaintenanceCalendar(
            self._session_key,
            self._user
        )

        time_now = get_current_utc_epoch()
        operative_maintenance_calendars = maintenance_calendar_object.get_bulk(
            self._user,
            fields = ['_key', 'start_time', 'end_time', 'objects'],
            filter_data = {'$and': [
                {'start_time': {'$lte': time_now}},
                {'end_time': {'$gt': time_now}}
            ]}
        )

        # Now populate newly identified operative maintenance records

        new_operative_maintenance_records = []
        for operative_maintenance_calendar in operative_maintenance_calendars:
            for object_entry in operative_maintenance_calendar.get('objects', []):
                new_operative_maintenance_records.append(
                    {
                        'maintenance_object_type': object_entry['object_type'],
                        'maintenance_object_key': object_entry['_key'],
                        'start_time': operative_maintenance_calendar['start_time'],
                        'end_time': operative_maintenance_calendar['end_time'],
                        'calendar_origin': operative_maintenance_calendar['_key']
                    }
                    # Note that start_time and end_time are preserved for tracking in case originating calendar changes
                )
        if len(new_operative_maintenance_records) > 0:
            operative_maintenance_record_object.save_batch(self._user, new_operative_maintenance_records, True)

        logger.info(
            '[AUDIT] Operative maintenance log was overwritten with records: ' + str(new_operative_maintenance_records)
        )

