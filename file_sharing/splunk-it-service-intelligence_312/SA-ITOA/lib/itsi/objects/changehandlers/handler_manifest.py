# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from .example_change_handlers import ExampleChangeHandler
from .service_entities_update_handler import ServiceEntitiesUpdateChangeHandler
from .kpi_delete_handler import KpiDeleteHandler
from .kpi_at_ad_update_handler import KpiAtAdUpdateHandler
from .kpi_cohesive_ad_update_handler import KpiCohesiveAdUpdateHandler
from .kpi_ad_update_handler import KpiAdUpdateHandler
from .service_delete_handler import ServiceDeleteHandler
from .entity_services_update_handler import EntityServicesUpdateChangeHandler
from .kpi_backfill_enabled_handler import KpiBackfillEnabledHandler
from .service_dependency_handler import ServiceDependencyHandler
from .kpi_saved_search_create_update_handler import KpiCreateUpdateHandler
from .kpi_thresholds_template_update_handler import KpiThresholdsTemplateUpdateHandler
from .kpi_thresholds_template_delete_handler import KpiThresholdsTemplateDeleteHandler
from .kpi_alert_period_update_handler import KpiAlertPeriodUpdateHander
from .kpi_base_search_handler import KpiBaseSearchUpdateHandler
from .kpi_search_type_change_handler import KpiSearchTypeHandler
from .base_service_template_update_handler import BaseServiceTemplateUpdateHandler
from .base_service_template_delete_handler import ServiceTemplateDeleteHandler

#TODO: when we have real handlers for testing with, we won't need the test handler anymore.
handler_manifest = {
    "test_change": ExampleChangeHandler,
    "service_entities_update": ServiceEntitiesUpdateChangeHandler,
    "service_kpi_deletion": KpiDeleteHandler,
    "service_kpi_ad": KpiAdUpdateHandler,
    "service_kpi_cad": KpiCohesiveAdUpdateHandler,
    "service_kpi_at": KpiAtAdUpdateHandler,
    "delete_service": ServiceDeleteHandler,
    "entity_services_update": EntityServicesUpdateChangeHandler,
    "service_kpi_backfill_enabled": KpiBackfillEnabledHandler,
    "service_dependency_changed": ServiceDependencyHandler,
    "create_or_update_kpi_saved_search": KpiCreateUpdateHandler,
    "service_kpi_thresholds_template_update": KpiThresholdsTemplateUpdateHandler,
    "service_kpi_thresholds_template_delete": KpiThresholdsTemplateDeleteHandler,
    "update_shared_base_search": KpiBaseSearchUpdateHandler,
    "service_kpi_update_alert_period": KpiAlertPeriodUpdateHander,
    'modify_kpi_search_type': KpiSearchTypeHandler,
    'base_service_template_update': BaseServiceTemplateUpdateHandler,
    'delete_base_service_template': ServiceTemplateDeleteHandler
    }
