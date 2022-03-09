# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from .itoa_migration_interface import ITOAMigrationInterface
from .service_migration_interface import ServiceMigrationInterface
from .useraccess_migration_interface import UserAccessMigrationInterface
from .notable_migration_interface import NotableMigrationInterface
from .filesave_migration_interface import FilesaveMigrationInterface
from .iconcollection_migration_interface import IconCollectionMigrationInterface
from .noop_migration_interface import NoopMigrationInterface
from .correlation_search_migration_interface import CorrelationSearchMigrationInterface

# Base returns the respective object interface class for migration.
# Handler returns a set of handlers that needs to be run for a particular object as part of the migration.
migration_manifest = {
        'service': {
                'base': ServiceMigrationInterface,
                'handlers': {}
        },
        'team': {
                'base':ITOAMigrationInterface,
                'handlers': {}
        },
        'deep_dive': {
                'base':ITOAMigrationInterface,
                'handlers': {}
        },
        'entity': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'base_service_template': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'glass_table': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'home_view': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'kpi': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'kpi_base_search': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'kpi_template': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'kpi_threshold_template': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'saved_page': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'temporary_kpi': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'migration': {
                'base': NoopMigrationInterface,
                'handlers': {}
        },
        'backup_restore': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'event_management_state': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'app_acl': {
                'base': UserAccessMigrationInterface,
                'handlers': {}
        },
        'app_capabilities': {
                'base': UserAccessMigrationInterface,
                'handlers': {}
        },
        'notable_event_comment': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'notable_event_tag':{
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'external_ticket': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'notable_event_group': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'notable_aggregation_policy': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'notable_event_seed_group': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'notable_event_state': {
                'base': NotableMigrationInterface,
                'handlers': {}
        },
        'glass_table_images': {
                'base': FilesaveMigrationInterface,
                'handlers': {}
        },
        'glass_table_icons': {
                'base': IconCollectionMigrationInterface,
                'handlers': {}
        },
        'maintenance_calendar': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'operative_maintenance_record': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'correlation_search': {
                'base': CorrelationSearchMigrationInterface,
                'handlers': {}
        },
        'noop': {
                'base': NoopMigrationInterface,
                'handlers': {}
        },
        'entity_relationship': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        'entity_relationship_rule': {
                'base': ITOAMigrationInterface,
                'handlers': {}
        },
        "backup_restore":{
                "base": ITOAMigrationInterface,
                "handlers": {}
        }
}