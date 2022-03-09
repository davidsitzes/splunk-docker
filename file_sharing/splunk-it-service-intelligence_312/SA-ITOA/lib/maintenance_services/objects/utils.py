# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from maintenance_services.constants import (
    MAINTENANCE_CALENDAR_OBJECT_TYPE,
    OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE
)

object_collection_mapping = {
    MAINTENANCE_CALENDAR_OBJECT_TYPE: 'maintenance_calendar',
    OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE: 'operative_maintenance_log'
}