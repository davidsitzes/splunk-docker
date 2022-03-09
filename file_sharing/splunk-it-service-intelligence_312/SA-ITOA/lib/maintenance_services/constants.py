# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

# A collection of constants pertinent to maintenance services used across the code base

MAINTENANCE_CALENDAR_OBJECT_TYPE = 'maintenance_calendar'

OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE = 'operative_maintenance_record'

# The capability values defined here must match the ones exposed in authorize.conf
CAPABILITY_MATRIX = {
    'maintenance_calendar': {
        'read': 'read-maintenance_calendar',
        'write': 'write-maintenance_calendar',
        'delete': 'delete-maintenance_calendar'
    }
}