# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from maintenance_services.constants import (
    MAINTENANCE_CALENDAR_OBJECT_TYPE,
    OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE
)
from .maintenance_calendar import MaintenanceCalendar
from .operative_maintenance_record import OperativeMaintenanceRecord

'''
Object manifest is used currently to control which objects are supported in ITSI via ItoaObject implementation.
Deprecated objects like link_table, are specifically handled during migration by directly instantiating ItoaObject.
This works for now, but in future if the list of deprecated objects go up/need specific implementations, we will add
them here. Obviously, when something currently present here moves to deprecated list, consider the proposal above.
'''
object_manifest = {
    MAINTENANCE_CALENDAR_OBJECT_TYPE: MaintenanceCalendar,
    OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE: OperativeMaintenanceRecord
}
