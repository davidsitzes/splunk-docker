# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
# This package contains packages specifically built for the ITSI app implementations

"""
    ITSI logger details

    The following loggers have been defined in the ITSI
    1. itsi ---> Itsi app Root logger
    2. itsi.command --> Root logger for command (itsi_commands.log file)
        - itsi.command.getservice -- get service command
        - itsi.command.storeentities -- get storeentities command
        - itsi.command.healthscore -- get health score command
        - itsi.command.suppressalert - suppress alert custom command
        - itsi.command.common - common utils logger
        - itsi.command.set_severity - set severity command
    3. itsi.object --> Logger for all ITSI object like entity and service etc (itsi_objects.log)
        - itsi.object.utils -- object utils
        - itsi.object.correlation_search -- correlation_search_object
            - itsi.object.correlation_search.search_generation
        - itsi.object.deep_dive
        - itsi.object.entity
        - itsi.object.deep_dive
        - itsi.object.home_view
        - itsi.object.kpi
            - itsi.object.kpi.search
            - itsi.object.kpi.set_severity
        - itsi.object.kpi_template
        - itsi.object.kpi_threshold_template
        - itsi.object.service
        - itsi.object.searches
        - itsi.object.saved_page
    4. itsi.object.refresher --> Logger for refresher log name itsi_refresher.log
    5. itsi.migration --> Root logger for all migration task, log file name itsi_migration.log
    6. itsi.install --> Root logger for install, log file name is itsi_install.log
    7. itsi.configurator --> Root logger for all configuration steps (itsi_configurator.log)
    8. itsi.datamodel --> Logger for data model interface (itsi_datemodel_interface.log)
    9. itsi.controllers --> Root logger for all itsi controllers
        - itsi.controllers.backfill_services -- back fill services, log file itsi_backfill_services.log
        - itsi.controllers.deep_dive_services -- deep dive services, log file itsi_deep_dive_services.log
        - itsi.controllers.health_services -- health services, log file itsi_health_service_provider.log
        - itsi.controllers.itoa_interface -- itoa interface log file itsi_interface.log
    10. itsi.csv --> Root logger for any csv operation (itsi_csv_operations.log)
        - itsi.csv.loader --> Root logger for csv load
        - itsi.csv.import --> Root logger for csv import
    11. itsi.backfill ---> Backfill module (itsi_backfill.log)
"""
