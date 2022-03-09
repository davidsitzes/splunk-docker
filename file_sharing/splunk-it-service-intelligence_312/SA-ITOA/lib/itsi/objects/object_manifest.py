import sys
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from .itsi_deep_dive import ItsiDeepDive
from .itsi_entity import ItsiEntity
from .itsi_glass_table import ItsiGlassTable
from .itsi_home_view import ItsiHomeView
from .itsi_kpi import ItsiKpi
from .itsi_kpi_base_search import ItsiKPIBaseSearch
from .itsi_kpi_template import ItsiKpiTemplate
from .itsi_kpi_threshold_template import ItsiKpiThresholdTemplate
from .itsi_migration import ItsiMigration
from .itsi_saved_page import ItsiSavedPage
from .itsi_service import ItsiService
from .itsi_temporary_kpi import ItsiTemporaryKpi
from .itsi_event_management_state import ItsiEventManagementState
from .itsi_backup_restore import ItsiBackupRestore
from .itsi_security_group import ItsiSecGrp
from .itsi_entity_relationship import ItsiEntityRelationship
from .itsi_entity_relationship_rule import ItsiEntityRelationshipRule
from .itsi_service_template import ItsiBaseServiceTemplate

'''
Object manifest is used currently to control which objects are supported in ITSI via ItoaObject implementation.
Deprecated objects like link_table, are specifically handled during migration by directly instantiating ItoaObject.
This works for now, but in future if the list of deprecated objects go up/need specific implementations, we will add
them here. Obviously, when something currently present here moves to deprecated list, consider the proposal above.
'''
object_manifest = {
    'deep_dive': ItsiDeepDive,
    'entity': ItsiEntity,
    'glass_table': ItsiGlassTable,
    'home_view': ItsiHomeView,
    'kpi': ItsiKpi,
    'kpi_base_search': ItsiKPIBaseSearch,
    'kpi_template': ItsiKpiTemplate,
    'kpi_threshold_template': ItsiKpiThresholdTemplate,
    'migration': ItsiMigration,
    'saved_page': ItsiSavedPage,
    'service': ItsiService,
    'base_service_template': ItsiBaseServiceTemplate,
    'temporary_kpi': ItsiTemporaryKpi,
    'event_management_state': ItsiEventManagementState,
    'backup_restore': ItsiBackupRestore,
    'team': ItsiSecGrp,
    'entity_relationship': ItsiEntityRelationship,
    'entity_relationship_rule': ItsiEntityRelationshipRule
}
