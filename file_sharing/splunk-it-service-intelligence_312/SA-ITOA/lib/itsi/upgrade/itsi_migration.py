# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import re
import copy
import json
import time
from datetime import datetime
from string import maketrans
import traceback
from splunk.util import normalizeBoolean, safeURLQuote

import splunk
import splunk.rest as rest
from splunk import ResourceNotFound
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess

from ITOA.storage import itoa_storage
from ITOA.itoa_exceptions import ItoaDatamodelContextError
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from ITOA.itoa_object import ItoaObject

from ITOA.setup_logging import setup_logging
from ITOA.version_check import VersionCheck
from ITOA.saved_search_utility import SavedSearch
from ITOA.itoa_factory import instantiate_object
from ITOA import itoa_common
from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import get_supported_itoa_object_types
from ITOA.itoa_config import get_collection_name_for_itoa_object
from ITOA.event_management.notable_event_utils import NotableEventConfiguration
from .migration_handlers_2_4_0 import BackupRestoreJobsMigrationChangeHandler_from_2_3_0
from migration.migration import MigrationFunctionAbstract, Migration, MigrationBaseMethod
from . import (
    migration_handlers_2_5_0,
    migration_handlers_2_6_0,
    migration_handlers_3_0_0,
    migration_handlers_3_1_0,
    migration_handlers_3_1_1,
)

from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import ItsiSettingsImporter
from itsi.searches.itsi_searches import ItsiKpiSearches
from itsi.objects.itsi_home_view import ItsiHomeView
from itsi.objects.itsi_kpi_template import ItsiKpiTemplate
from itsi.objects.itsi_kpi_threshold_template import ItsiKpiThresholdTemplate
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_migration import ItsiMigration
from itsi.objects.itsi_deep_dive import ItsiDeepDive
from itsi.objects.itsi_entity import ItsiEntity

import kvstore_backup_restore
from itsi.upgrade.itsi_module_related_migration import MigrateModuleKPIsToSharedBaseSearch, AddItsiRoleEntityRuleToServices, \
    UpdateChangedDatamodelKPIs_2_2_0_to_2_3_0

# FIXME: Revert this change after APPSC-1175 is fixed, append app_common in sys.path.
# Adding current app's lib/app_common to sys.path
# Only for Ember. Galaxy should have no such problems with make_splunkhome_path
# injecting bin/ of all apps in PYTHONPATH"
from SA_ITOA_app_common.apifilesave.filesave import ApifilesaveService

logger = setup_logging("itsi_migration.log", "itsi.migration")

##################################### Migration Utils #################################

class HandleAppVisibility(MigrationFunctionAbstract):
    '''
        Handle app visibility
        Migration step which handle app visibility
    '''

    def __init__(self, session, app, user, is_disable_ui_access, restore=False):
        '''
        Initialized
        :param {string} session: session_key
        :param {string} app: app
        :param {string} user: user/owner
        :param {boolean} is_disable_ui_access: flag to either disable or enable UI
        :return:
        '''
        self.session = session
        self.app = app
        self.user = user
        self.restore = restore
        self.is_disable_ui_access = is_disable_ui_access
        if self.user is None:
            self.user = "nobody"

    def rollback(self):
        '''
        Opposite operation then execution
        :return: flag for status of operation
        :rtype boolean
        '''
        if self.is_disable_ui_access:
            is_visible = True
        else:
            is_visible = False
        return self.toggle_app_ui_access(is_visible)

    def execute(self):
        '''
        Perform operation
        :return: flag for status of operation
        :rtype boolean
        '''
        if self.restore:
            # Skipping the UI enable/disable for restoring
            return True
        if self.is_disable_ui_access:
            is_visible = False
        else:
            is_visible = True
        return self.toggle_app_ui_access(is_visible)

    def get_app_conf_rest_path(self):
        '''
        Rest end point for app.conf
        :return: rest end point
        '''
        return rest.makeSplunkdUri() + 'servicesNS/' + self.user + '/' + self.app + '/configs/conf-app'

    def get_app_ui_rest_path(self):
        '''
        Rest end point for ui stanza for app.conf
        :return: rest end point
        :rtype string
        '''
        return self.get_app_conf_rest_path() + '/ui'

    def toggle_app_ui_access(self, is_visible):
        '''
        Return application ui access
        :param is_visible: True|False to enable or disable UI access for app
        :return: True|False
        :rtype boolean
        '''
        try:
            postargs = {'is_visible': is_visible}
            response, content = rest.simpleRequest(self.get_app_ui_rest_path(),
                                                   sessionKey=self.session,
                                                   postargs=postargs,
                                                   method='POST')
            if response.status != 200 and response.status != 201:
                logger.error("Failed to set UI access to:%s, error:%s", is_visible, response)
                return False
            else:
                if is_visible:
                    logger.info("Successful enabled UI access")
                else:
                    logger.info("Successful disabled UI accesss")
                return True
        except Exception as e:
            logger.exception(e)
            return False

class BackupRestore(MigrationFunctionAbstract):
    """
    Take backup before we perform anything.
    """

    def __init__(self, session_key, backup_dir_name, owner='nobody', restore=False):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type backup_dir_name: basestring
        @param backup_dir_name: name of the backup directory

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.restore = restore
        self.back_up_location = make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', backup_dir_name])

    def rollback(self):
        """
        Rollback
        @return: bool
        """
        restore = kvstore_backup_restore.KVStoreBackupRestore(self.session_key, self.back_up_location, False)
        restore.execute()
        return True

    def execute(self):
        """
        Taking a backup
        @return: bool
        """
        if self.restore:
            # Do nothing
            return True
        backup = kvstore_backup_restore.KVStoreBackupRestore(self.session_key, self.back_up_location, True)
        backup.execute()
        return True


################################ 2.0.0 to 2.1.0 Migration Handlers #############################

class UpdateServiceAnalyzer(MigrationFunctionAbstract):
    """
        Add _owner field in all service analyzer or home view object
    """

    def __init__(self, session_key, owner="nobody", app="itsi"):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

    @staticmethod
    def update_home_view_objects(home_views):
        """
        In place add _owner field to home view object if it does not exist

        @type home_views: list
        @param home_views: list of home view object

        @rtype: list
        @return: Update home views list
        """
        for home_view in home_views:
            logger.info('Found home_view %s owner field, forcing _owner field to nobody', home_view.get('_owner'))
            home_view['_owner'] = 'nobody'
        return home_views

    def get_and_update_home_views(self):
        """
        Add _owner fields in home view object

        @rtype: bool
        @return: True if everything goes fine other throws exception
        """
        logger.info('Updating all home view objects')
        # Get all
        home_view_object = ItsiHomeView(self.session_key, 'unknown')
        home_views = home_view_object.get_bulk(self.owner, req_source='home_view_migration')
        logger.info("There are %s home view settings in this environment", len(home_views))
        UpdateServiceAnalyzer.update_home_view_objects(home_views)
        # bulk save
        home_view_object.batch_save_backend(self.owner, home_views)

        logger.info('Successfully updated all home view objects')
        return True

    def execute(self):
        """
        Over write function

        @rtype: bool
        @return: True/False or throw exception
        """
        return self.get_and_update_home_views()

################################ 2.1.0 to 2.2.0 Migration Handlers #############################

class ACLHandler(MigrationFunctionAbstract):
    '''
    Handler to add default ACL info for shared objects of certain types
    '''
    def __init__(self,
                 session_key,
                 owner='nobody',
                 app='itsi',
                 default_acl={'read': ['*'], 'write': ['*'], 'delete': ['*']}):
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.object_types = ('glass_table', 'deep_dive', 'home_view')
        self.default_acl = default_acl

    def add_acl(self):
        '''
        Add default ACL value for each shared object in self.object_types
        Return `True` on success. `False` if we encountered any problems.
        '''
        object_app = self.app
        logger.debug('Default perms: %s', self.default_acl)
        success = False
        objects_exist = False # are there any objects existing? lets assume not.
        for object_type in self.object_types:
            o = instantiate_object(self.session_key, 'migration', object_type, logger)
            objects = o.get_bulk(self.owner,
                                 filter_data={'_owner': 'nobody'},
                                 fields=['_key'],
                                 req_source='acl_handler_migration')
            if not objects:
                # no objects found...move onto next object type
                continue
            objects_exist = True
            ids_ = itoa_common.extract(objects, '_key')
            try:
                success, rval = UserAccess.bulk_update_perms(ids_,
                                                             self.default_acl,
                                                             object_app,
                                                             object_type,
                                                             get_collection_name_for_itoa_object(object_type),
                                                             self.session_key,
                                                             logger)
            except Exception:
                logger.exception(('Permission update failed for `%s`. Aborted. Please re-run migration.'), object_type)
                return False
            if not success:
                logger.error('Unable to save default perms for: `%s`. %s', object_type, rval)
            else:
                logger.info(('Successfully saved default perms for: `%s`. %s') % (object_type, rval))
        if objects_exist is False:
            return True # there are no objects, no ACLs needed to be saved.
        return success

    def execute(self):
        '''
        Whatever needs to happen as part of this handler should be done in here
        '''
        return self.add_acl()

class ServiceMigrationChangeHandler(MigrationFunctionAbstract):
    '''
    The class handling service migrations
    '''

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner

    def migrate_kpi_saved_searches(self, all_services):
        """
        Migrate KPI saved searches to use new name, cleanup existing saved searches with the old name
        See ITOA-3416 for more details
        Deleting KPI searches named with old convention
        @return: bool
        """
        service_object = ItsiService(self.session_key, self.owner)
        kpi_old_names = []
        for service in all_services:
            for kpi in service.get('kpis'):
                if kpi.get('_key', '').find('SHKPI') > -1:
                    continue
                kpi_old_names.append('Indicator - ' + kpi.get('_key', '')  + ' - Rule')

        # Lets delete all old KPI saved searches. This will force KPIs to move to new naming convention
        # for saved searches. The need for this is for data accuracy explained in ITOA-3416
        if not service_object.delete_kpi_saved_searches(kpi_old_names):
            raise Exception(_('Migration could not delete some KPI saved searches named with the old convention. ' +
                            'Please delete them manually as soon as possible.' +
                            'They should be named "Indicator - <KPI key> - Rule."'))

        # On return the caller saves all the services
        # This ensures that saved searches are created for KPI with new names

        return True

    def update_kpi_search_type_to_2_2(self, kpi):
        '''
        Update a KPI search type from previous isadhoc definition to the later
        search_type definition
        NOTE: This does not save the KPI, that will need to be done separately
        @param kpi: The individual KPI to be updated
        '''
        isadhoc = kpi.get("isadhoc", None)
        search_type = kpi.get("search_type", None)
        if search_type is not None:
            #Here we're dealing with a current definition, keep the value
            #Make sure that isadhoc is deleted though
            if "isadhoc" in kpi:
                del kpi["isadhoc"]
            return True
        if isadhoc is None:
            #If there is a datamodel field, then we have a datamodel search, else assume adhoc
            message = _("KPI %s has no isadhoc field, introspecting kpi to determine search type") % kpi["_key"]
            logger.warning(message)
            if kpi.get("datamodel", None) is None:
                isadhoc = True
            else:
                isadhoc = False
        if isadhoc is True:
            kpi['search_type'] = 'adhoc'
        else:
            kpi['search_type'] = 'datamodel'
        return True

    def rollback_kpi(self, kpi):
        '''
        Rollback the kpi changes.  In this case
        They will only do with the `isadhoc` fields
        @param kpi: A KPI to update
        '''
        search_type = kpi.get("search_type", None)
        if search_type is None:
            return
        if search_type == "adhoc":
            kpi['isadhoc'] = True
        elif search_type == "datamodel":
            kpi['isadhoc'] = False
        del kpi["search_type"]

    def update_service_kpis(self, service):
        '''
        For each kpi in a service, update the kpis
        @param service: The service containing the KPIs we'll update
        '''
        kpis = service.get('kpis')
        if kpis is None:
            return True
        for kpi in kpis:
            #Short circuiting here
            if not self.update_kpi_search_type_to_2_2(kpi):
                return False

            # Support old way, where we allowed is_service_entity_filter is set with out entity rule
            is_service_entity_filter = kpi.get('is_service_entity_filter', False)
            service_entity_rules = service.get('entity_rules', [])
            if is_service_entity_filter and not service_entity_rules:
                # Set KPI filter to false
                logger.info('Found Kpi=%s of service=%s has service entity filter enable without entity rules, hence'
                            'we are turning service entity filter off', kpi.get('title'), service.get('title'))
                kpi['is_service_entity_filter'] = False

        return True

    def clear_kpi_thresholds_template_id(self, service):
        '''
        This handler is to migrate the threshold_template_id in KPI object.
        By default, this field is set to "custom" in older versions, with the
        new version, user can map the KPI threshold based on the threshold
        template, and the default value should be '' instead of custom if
        nothing is being set yet.

        This migration will make sure this field from an older version of
        the KPI object is set to ''.
        '''
        kpis = service.get('kpis')
        if kpis is None:
            return True
        for kpi in kpis:
            if kpi.get('_key', '').startswith('SHKPI-'):
                continue
            # Reset the kpi_threshold_template id
            kpi['kpi_threshold_template_id'] = ''

        return True

    def execute(self):
        '''
        @rtype boolean
        @return True on success. False otherwise.
        '''
        try:
            # fetch all existing services...
            service_obj = ItsiService(self.session_key, 'nobody')
            all_services = service_obj.get_bulk(self.owner, req_source='kpi_service_migration')

            for svc in all_services:
                self.update_service_kpis(svc)
            self.migrate_kpi_saved_searches(all_services)
            service_obj.save_batch('nobody', all_services, True, req_source="migration")

            for svc in all_services:
                self.clear_kpi_thresholds_template_id(svc)
            service_obj.save_batch('nobody', all_services, False, req_source="migration")

        except Exception as exc:
            logger.exception('Encountered an error. Details: ' + str(exc) +
                         '. Migration may not have updated service KPIs to new naming convention for' +
                         ' saved search names. ' +
                         'It is crucial to fix this as soon as possible.' +
                         'Please try this manually via UI or contact Splunk support.'
                        )
            return False
        return True

    def rollback(self):
        '''
        @rtype boolean
        @return True on success, False otherwise
        '''
        '''
        @rtype boolean
        @return True on success. False otherwise.
        '''
        try:
            # fetch all existing services...
            service_obj = ItsiService(self.session_key, 'nobody')
            all_services = service_obj.get_bulk(self.owner, req_source='kpi_ownership_migration')

            for svc in all_services:
                kpis = svc.get("kpis")
                if kpis is None:
                    continue
                for kpi in kpis:
                    self.rollback_kpi(kpi)
                    # Saved search updates cannot easily be rolled back, ignore since failures have detailed logs
            service_obj.save_batch('nobody', all_services, True, req_source="migration_rollback")
        except Exception as exc:
            logger.exception('Rollback failed. Please try this manually via UI or contact Splunk support.')
            return False
        return True

class KPITemplateMigrationChangeHandler(MigrationFunctionAbstract):
    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        KPI template schema is different from the threshold schema under the KPI.
        Starting from the new ITSI version 2.2.0.x, the schema should be consistent.
        This handler will transform the old version to the new version.
        @type session_key: basestring
        @param session_key: Splunkd session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

    def update_template_search_type(self, template):
        """
        For a single kpi template, update the search type
        @return: True if updated False otherwise
        """
        if template == None:
            return False
        kpis = template.get("kpis", [])
        for kpi in kpis:
            search_type = kpi.get("search_type")
            if search_type != None:
                #Key exists, skip this object
                continue
            #Search type is none, look for an adhoc search default to adhoc if None
            isadhoc = kpi.get("isadhoc", True)
            if isadhoc:
                kpi["search_type"] = "adhoc"
            else:
                kpi["search_type"] = "datamodel"
        return True

    def update_template_definitions(self):
        """
        Update all of the template definitions (keep the old keys so we don't need to rollback)
        """
        kpi_templates = ItsiKpiTemplate(self.session_key, 'nobody')
        all_templates = kpi_templates.get_bulk(self.owner)
        updated = []
        for template in all_templates:
            if self.update_template_search_type(template):
                updated.append(template)
        #In theory we've already passed title validation, so we can set this parameter to False
        if len(updated) == 0:
            return True
        try:
            kpi_templates.save_batch(self.owner, updated, False, req_source="migration")
        except Exception as exc:
            logger.exception('kpi templates upgrade error. Please try this manually via UI or contact Splunk support.')
            return False
        return True

    def execute(self):
        return self.update_template_definitions()

    def rollback(self):
        #No rollback necessary, if old objects failed to update, they are still retained
        return True

class KPIThresholdTemplateMigrationChangeHandler(MigrationFunctionAbstract):

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        KPI threshold template schema is different from the threshold schema under the KPI.
        Starting from the new ITSI version 2.2.0.x, the schema should be consistent.
        This handler will transform the old version to the new version.
        @type session_key: basestring
        @param session_key: Splunkd session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app


    def kpi_threshold_template_schema_update(self, schema):
        # if the specification field is not in the schema,
        # it is an old schema and needs to be migrated.
        if 'time_variate_thresholds_specification' not in schema:
            schema['adaptive_thresholding_training_window'] = schema.get('training_window')
            schema['adaptive_thresholds_is_enabled'] = schema.get('adaptive_thresholds_enabled')
            schema['time_variate_thresholds'] = schema.get('time_policies_enabled')
            schema['time_variate_thresholds_specification'] = {
                    'policies': schema.get('policies'),
                    'time_blocks': schema.get('time_blocks')
            }
            # Remove the old key pairs
            for delete_key in ['training_window', 'adaptive_thresholds_enabled', 'time_policies_enabled',
                                'policies', 'time_blocks']:
                if delete_key in schema:
                    del schema[delete_key]
            return True
        else:
            # template is already in the new format, no need to update.
            return False

    def kpi_threshold_template_schema_transformation(self):
        """
        If 'time_variate_thresholds_specification' is not in the schema,
        this schema is from an older version, and the transformation is needed.
        Since the transformation used the save_batch(), a refresh job will be
        triggered to update any KPI threshold value if the threshold template ID
        in the KPI is matched.
        """
        schema_obj = ItsiKpiThresholdTemplate(self.session_key, 'nobody')
        schema_collection = schema_obj.get_bulk(self.owner)
        updated = []
        try:
            for schema in schema_collection:
                if self.kpi_threshold_template_schema_update(schema):
                    updated.append(schema)
            schema_obj.save_batch(self.owner, updated, False, req_source="migration")
            logger.info('KPI threshold template schema transformation successfully!')
        except Exception as exc:
            logger.exception('Encountered an error. Please try this manually via UI or contact Splunk support.')
            return False
        return True

    def execute(self):
        return self.kpi_threshold_template_schema_transformation()

class EntityMigrationChangeHandler(MigrationFunctionAbstract):
    """
        The class handling entity migrations to ITSI version 2.2
    """

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner

    def execute(self):
        '''
        * A schema change to "services" field has been made. In this handler, clear "services" field for all entities
            which on save will kick off change handler to update service memberships with new schema
        @rtype boolean
        @return True on success. False otherwise.
        '''
        try:
            # fetch all existing entities...
            entity_obj = ItsiEntity(self.session_key, 'nobody')
            all_entities = entity_obj.get_bulk(self.owner, req_source='entity_migration')

            # Clear out services field for all entities
            # On save, service membership change handler will update to membership with new schema for all entities
            for entity in all_entities:
                entity['services'] = []
            entity_obj.save_batch('nobody', all_entities, False, req_source="migration")
        except Exception as exc:
            logger.exception(('Encountered an error trying to migrate entities. ',
                'Please try this manually by saving entities via UI or contact Splunk support.'))

            return False
        return True

    def rollback(self):
        '''
        @rtype boolean
        @return True on success, False otherwise
        '''
        '''
        @rtype boolean
        @return True on success. False otherwise.
        '''
        # We couldnt save entities => cant rollback. Ignore since migration log will have details of failure
        return True

class TitleValidationHandler(MigrationFunctionAbstract):
    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        @type session_key: basestring
        @param session_key: Splunkd session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

    def update_title(self, object_type, data_list):
        """
        Check title exists, if it is does not then get latest

        @type data_list: list
        @param data_list: data list

        @type object_type: basestring
        @param object_type:

        @rtype: list
        @return: return list
        """
        duplicated_key_list = []
        for single_obj in data_list:
            if 'title' not in single_obj:
                single_obj.update({'title': str('title-' + single_obj['_key'])})
            if object_type == 'service':
                for v in single_obj.itervalues():
                    if isinstance(v, dict) and 'title' not in v:
                        v.update({'title': str('title-' + single_obj['_key'])})
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict) and 'title' not in item:
                                item.update({'title': str('title-' + single_obj['_key'])})

        # For glass_table object:
        #   retrieve the top level 'title' field
        #   make sure there is no duplicated title within the glass_table object
        if object_type == 'glass_table':
            for single_obj in data_list:
                title = single_obj['title']
                if title in duplicated_key_list:
                    single_obj['title'] = str(title + '-' + single_obj['_key'])
                duplicated_key_list.append(title)

    def add_and_update_title_field_to_existing_payload(self):
        """
        Take care two migration scenarios:
        1. title field is mandatory for certain types of object, perform migration for those objects.
        2. duplicated title name for class table is no longer valid, perform migration for GT.
        @rtype boolean
        @return True on success. False otherwise.
        """
        try:
            # fetch the object types that needs to be migrated...
            object_type_list = get_supported_itoa_object_types()
            for object_type in object_type_list:
                mi_obj = instantiate_object(self.session_key, 'nobody', object_type, logger=logger)
                if mi_obj.title_validation_required:
                    # parsing through the payload from kvstore
                    # assumption is that _key should already exist
                    # and set default title to the _key value if title field does not exist.

                    my_obj = mi_obj.get_bulk(self.owner)

                    # For objects that supports title validations:
                    #   Just migrate the top level title field for supported objects.
                    #   Nested object migration only apply to service.
                    self.update_title(object_type, my_obj)

                    # For glass table, use the non-batch save
                    # For all other object types, use batch_save_backend to skip all the check
                    #    and save it directly back into the kvstore
                    if object_type == 'glass_table':
                        logger.info('Migrating title field for glass table object in no batch mode')
                        itoa_common.save_batch(mi_obj, 'nobody', my_obj, True)
                    else:
                        logger.info('Migrating title field for %s in batch mode' % object_type)
                        mi_obj.batch_save_backend(self.owner, my_obj)
            logger.info('Title field migrated!')
        except Exception as exc:
            logger.exception('Encountered an error. Please try this manually via UI or contact Splunk support. Details %s', str(exc))
            return False

        return True

    def execute(self):
        return self.add_and_update_title_field_to_existing_payload()

class ServiceMigrationChangeHandler_from_2_2_0(MigrationFunctionAbstract):
    '''
    The class handling service migrations
    '''

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner

    def clear_old_ad_fields(self, service):
        '''
        This handler is to migrate all old AD fields in KPI object.
        The following two fields will set to false:
            anomaly_detection_is_enabled
            anomaly_detection_alerting_enabled
        The following two fields will be removed:
            anomaly_detection_training_window
            anomaly_detection_sensitivity
        '''

        kpis = service.get('kpis')
        if kpis is None:
            return True
        for kpi in kpis:
            if kpi.get('_key', '').startswith('SHKPI-'):
                continue
            # Reset and delete the old AD fields
            kpi['anomaly_detection_is_enabled'] = False
            kpi['anomaly_detection_alerting_enabled'] = False
            for delete_key in ['anomaly_detection_training_window', 'anomaly_detection_sensitivity']:
                if delete_key in kpi:
                    del kpi[delete_key]

        return True

    def obtain_services_perform_migration(self, all_services):
        '''
        A helper function which perform the migration.
        This function will be invoked by both the migration execute() and kvstore migration code.
        Update the service dict. in place.
        @rtype None
        @return None
        '''

        for svc in all_services:
            self.clear_old_ad_fields(svc)

        '''
        One or more services could fail if KPI search generation fails potentially from changes to
        datamodels that are being used in KPIs.

        Attempt to identify these KPI in services and convert them to adhoc searches (to skip datamodel checks)
        and continue migrating the rest as is. Mark the searches as invalid to provide a cue to administrator, this
        is needed since an invalid datamodel search will fail saved search creation.
        '''
        post_user_message = False
        for service in all_services:
            for kpi in service.get('kpis', []):
                if ItsiKpiSearches.is_datamodel(kpi):
                    '''
                    Validate data model spec for threshold fields and init the object which validates
                    entity filtering fields if configured.
                    '''
                    try:
                        kpi['service_id'] = service.get('_key', '')
                        kpi['service_title'] = service.get('title')

                        # first validate the threshold field in datamodel spec is fine.
                        datamodel_spec = kpi.get('datamodel', {})
                        ItsiKpiSearches.get_datamodel_context(self.session_key,
                                                                        'nobody',
                                                                        datamodel_spec.get('field'),
                                                                        datamodel_spec.get('datamodel'),
                                                                        datamodel_spec.get('object'))

                        # validate other fields such as entity identifier that are referencing the data model
                        itsi_searches = ItsiKpiSearches(
                            session_key=self.session_key,
                            kpi=kpi,
                            service_entity_rules=service.get('entity_rules', []),
                            sec_grp=service.get('sec_grp')
                            )
                    except ItoaDatamodelContextError as e:
                        '''
                        Mark the searches as invalid adhoc searches to provide a cue in KPI config. Altering the search
                        is needed since an invalid datamodel search will fail saved search creation.

                        Note: leave datamodel spec unaltered for use by module migration tasks for intentional
                        datamodel changes.
                        '''
                        kpi['search_type'] = 'adhoc'
                        kpi['base_search'] = 'Invalid datamodel search "' + kpi.get('base_search', '') + '"'

                        logger.warning('Found KPI (Id: %s) with stale datamodel specification. Auto converting ' \
                            'this KPI to adhoc search type to prevent service failures.', kpi.get('_key'))
                        post_user_message = True
                    finally:
                        del kpi['service_id']
                        del kpi['service_title']

        if post_user_message:
            ITOAInterfaceUtils.create_message(
                self.session_key,
                _('Found one or more KPIs with stale datamodel specification. These KPIs were auto converted to adhoc ' \
                    'search type to prevent service failures.')
            )

    def execute(self):
        '''
        @rtype boolean
        @return True on success. False otherwise.
        '''
        try:
            # fetch all existing services...
            service_obj = ItsiService(self.session_key, 'nobody')
            all_services = service_obj.get_bulk(self.owner, req_source='kpi_service_migration')
            self.obtain_services_perform_migration(all_services)
            service_obj.save_batch('nobody', all_services, False, req_source="migration")

        except Exception as exc:
            logger.exception('Encountered an error. Please try this manually via UI or contact Splunk support. Details %s', str(exc))
            return False
        return True

class DeleteOldAdSearch(MigrationFunctionAbstract):
    """
        Delete old AD correlation search
    """
    def __init__(self, session_key, owner='nobody', app='itsi'):
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.search = ItsiCorrelationSearch(self.session_key, is_validate_service_ids=False)

    def post_message(self, type, search_name):
        """
        Post couple messages to end user
        @return: None
        """
        if type == 'delete':
            cs_message = _('Anomaly detection search: %s in $SPLUNK_HOME/etc/apps/itsi/local will be deleted.') % search_name
        elif type == 'disable_succ':
            cs_message = _('Unable to delete search: %s, disable it now. User will need to delete this search manually.') % search_name
        elif type == 'disable_fail':
            cs_message = _('Unable to disable search: %s, please delete the search manually if it is not done so.') % search_name
        elif type == 'other':
            cs_message = _('Something wrong in delete/disable old AD search: %s, please the search manually if it is not done so.') % search_name
        ITOAInterfaceUtils.create_message(self.session_key, cs_message)

    def delete_old_ad_search(self):
        """
        Get all the correlation searches and delete only the anomaly detection ones.
        @return: None
        """
        search_list = ['ITSI anomaly detection correlation search',
                       'itsi_ad_search_kpi_minus7d',
                       'itsi_ad_search_kpi_minus2d',
                       'itsi_ad_search_kpi_minus1d']
        try:
            for search_name in search_list:
                try:
                    self.search.delete(search_name)
                    message_type = 'delete'
                    self.post_message(message_type, search_name)
                except splunk.ResourceNotFound:
                    # This search is not found, continue
                    pass
                except:
                    # Try to disable if the delete failed due to whatever reasons
                    try:
                        message_type = 'disable_succ'
                        self.search.update(search_name, {'disabled': '1', 'name': search_name})
                        self.post_message(message_type, search_name)
                    except:
                        message_type = 'disable_fail'
                        self.post_message(message_type, search_name)

            logger.info('Old AD correlation searches has been deleted as part of the migration!')
        except Exception as exc:
            logger.exception(
                'Encountered an error. Please try this manually via UI or contact Splunk support. Details %s', str(exc))
            return False
        return True

    def execute(self):
        return self.delete_old_ad_search()


class DeepDiveMigrator(MigrationFunctionAbstract):
    """
    Migration handler for deep dives. Currently this class only has code for
    2.2.0 to 2.3.0 and 2.3.0 to 2.4.0.
    """
    def __init__(self, session_key, owner=None):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: current owner; usually `nobody`
        """
        super(DeepDiveMigrator, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner if owner else 'nobody'
        self.default_migration_version = '2.2.0'

    def _update_exclude_fields(self, deep_dive):
        """
        Update `excludeFields` for each lane setting in this deep dive.
        Deep dive should be updated by the end of this method.
        """
        if not isinstance(deep_dive, dict):
            logger.error('Cannot update fields for an invalid deep '
                    'dive=%s. Type=%s.', deep_dive, type(deep_dive).__name__)
            raise TypeError(_('Cannot update fields for an invalid '
                'deep dive=%s. Type=%s.') % (deep_dive, type(deep_dive).__name__))

        if 'lane_settings_collection' not in deep_dive:
            logger.error('Missing key `lane_settings_collection` in deep dive=%s.',
                    deep_dive.get('_key'))
            raise KeyError(_('Missing key `lane_settings_collection` in deep '
                    'dive=%s.') % deep_dive)

        collection = deep_dive.get('lane_settings_collection', [])

        if not isinstance(collection, list):
            raise TypeError(_('Invalid type=%s for `lane_settings_collection`.'
                ' Expecting list.') % type(collection).__name__)

        to_add = ['alert_error', 'alert_period', 'kpi', 'kpibasesearch',
        'urgency', 'is_entity_in_maintenance', 'is_service_in_maintenance']

        for setting in collection:
            if not setting.get('excludeFields'):
                logger.warning('Missing key `excludeFields` in lane setting=%s. Will add', setting)
                setting['excludeFields'] = []
            setting['excludeFields'].extend(to_add)
            setting['excludeFields'] = list(set(setting['excludeFields'])) #de-dup

        return deep_dive

    def _update_threshold_settings(self, deep_dive):
        """
        Enable threshold indication for all KPI lanes for unnamed saved deep dives
        @param: deep_dive
        @return: deep_dive
        """
        if not isinstance(deep_dive, dict):
            message = _('Cannot update threshold settings for an invalid '
                             'deep dive=%s. Type=%s') % (deep_dive, type(deep_dive).__name__)
            logger.error(message)
            raise TypeError(message)

        if 'lane_settings_collection' not in deep_dive:
            logger.error('Missing key `lane_settings_collection` in deep dive=%s.',
                         deep_dive.get('_key'))
            raise KeyError(_('Missing key `lane_settings_collection` in deep '
                            'dive=%s.') % deep_dive)

        collection = deep_dive.get('lane_settings_collection', [])

        if not isinstance(collection, list):
            raise TypeError(_('Invalid type=%s for `lane_settings_collection`.'
                             ' Expecting list.') % type(collection).__name__)
        isnamed = deep_dive.get('is_named')
        if isnamed is False:
            for setting in collection:
                if setting.get('laneType') == 'kpi':
                    if setting.get('thresholdIndicationEnabled') == 'disabled':
                        thresholdtype = 'stateIndication'
                        if setting.get('graphType') == 'distributionStream':
                            thresholdtype = 'levelIndication'
                        setting['thresholdIndicationEnabled'] = 'enabled'
                        setting['thresholdIndicationType'] = thresholdtype

        return deep_dive

    def _update_entity_overlay_settings(self, deep_dive):
        """
        Update lane overlay settings model for all KPI lanes for with enabled entity overlays
        @param: deep_dive
        @return: deep_dive
        """
        if not isinstance(deep_dive, dict):
            message = _('Cannot update overlay settings for an invalid '
                             'deep dive=%s. Type=%s.') % (deep_dive, type(deep_dive).__name__)
            logger.error(message)
            raise TypeError(message)

        if 'lane_settings_collection' not in deep_dive:
            logger.error('Missing key `lane_settings_collection` in deep dive=%s.',
                         deep_dive.get('_key'))
            raise KeyError(_('Missing key `lane_settings_collection` in deep '
                            'dive=%s.') % deep_dive)

        collection = deep_dive.get('lane_settings_collection', [])

        if not isinstance(collection, list):
            raise TypeError(_('Invalid type=%s for `lane_settings_collection`.'
                             ' Expecting list.') % type(collection).__name__)
        for setting in collection:
            if setting.get('laneType') == 'kpi':
                overlaysettingsmodel = setting.get('laneOverlaySettingsModel', None)
                if overlaysettingsmodel is not None and overlaysettingsmodel.get('isEnabled') == 'yes':
                    setting['laneOverlaySettingsModel']['overlayType'] = 'entity'

        return deep_dive

    def _migrate(self, deep_dives):
        """
        Migrate all deep dives.
        adding new keys to `excludeFields` in each lane setting in
        the `lane_settings_collection` which is a top level field in a deep dive
        object

        @type deep_dives: list
        @param deep_dives: deep dives we care about

        @rtype: boolean
        @return True on success (which is currently always, unless Exception)
        """
        logger.info('deep dive type=%s', type(deep_dives).__name__)

        try:
            dd_collection = []
            for dd in deep_dives:
                if not isinstance(dd, dict):
                    message = _('Invalid type for dd in deep dive. Expecting a dictionary.'
                        ' Received=%s. type=%s') % (dd, type(dd).__name__)
                    logger.error(message)
                    raise TypeError(message)
                # set the default to 2.2.0 since the deep dive line migration is required since 2.2.x
                dd_version = dd.get('_version', self.default_migration_version)
                if not dd_version:
                     # if _version is None, also set to 2.2.0
                     dd_version = self.default_migration_version
                if VersionCheck.compare(dd_version, '2.3.0') <= 0:
                    logger.debug('deep dive before=%s', dd)
                    self._update_exclude_fields(dd)
                    logger.debug('deep dive after=%s', dd)
                if VersionCheck.compare(dd_version, '2.4.0') <= 0:
                    logger.debug('deep dive before threshold indication changes=%s', dd)
                    self._update_threshold_settings(dd)
                    self._update_entity_overlay_settings(dd)
                    logger.debug('deep dive after threshold indication changes=%s', dd)
                dd_collection.append(dd)

            logger.debug('Committing updated deep dives=%s', dd_collection)
            status = self.save_object('deep_dive', dd_collection)

        except Exception, e:
            logger.exception('Failed to migrate deep dives to 2.3.0. Unable to save.')
            ITOAInterfaceUtils.create_message(
                self.session_key,
                _('Failed to migrate deep dives to 2.3.0. Unable to save. Please check ITSI internal logs.')
                ) # we probably need not return False here (which would fail migration).
        return status

    def fetch_and_migrate(self):
        """
        Fetch and migrate deep dives that already exist.
        """
        all_dds = self.get_object_iterator('deep_dive')
        logger.info('type=%s, fetched deep dives=%s', type(all_dds).__name__, all_dds)
        return self._migrate(all_dds)

    def execute(self):
        return self.fetch_and_migrate()


class UpdateATSearch(MigrationFunctionAbstract):
    """
        Update AT searches to exclude data generated during the maintenance window.
    """
    def __init__(self, session_key, owner='nobody', app='itsi'):
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.search = SavedSearch()

    def post_message(self, type, search_name):
        """
        Post messages to end user
        @return: None
        """
        if type == 'update_error':
            cs_message = _('A problem occurred when updating adaptive threshold search %s. To resolve this issue, please refer document') % search_name
        ITOAInterfaceUtils.create_message(self.session_key, cs_message)

    def add_alert_level(self, search_string):
        """
        Process search string to add alert level.
        Very specific case of adding alert_level!=-2, to filter out maintenance level data.
        @return: search string
        """
        condition = "alert_level!=-2"
        index = search_string.find("|")
        if index > 0:
            return search_string[:index] + " " + condition + " " + search_string[index:]
        raise Exception

    def update_old_at_search(self):
        """
        Update adaptive threshold searches to exclude data generated during the maintenance window.
        @return: None
        """
        search_list = ['itsi_at_search_kpi_minus7d',
                       'itsi_at_search_kpi_minus14d',
                       'itsi_at_search_kpi_minus30d',
                       'itsi_at_search_kpi_minus60d']

        for search_name in search_list:
            try:
                entity = self.search.get_search(self.session_key, search_name)
                if entity.get('search'):
                    new_search_string = self.add_alert_level(entity.get('search'))
                    data = {'search': new_search_string}
                    self.search.update_search(self.session_key,
                                              search_name,
                                              self.app,
                                              self.owner,
                                              raise_if_exist=False,
                                              **data)

                    logger.info('The AT saved search: %s was successfully updated to exclude data generated during the maintenance window.', search_name)
            except ResourceNotFound:
                pass
            except Exception as e:
                logger.exception(
                    'Encountered error updating adaptive threshold saved search for %s. Details: %s', search_name, str(e))
                self.post_message('update_error', search_name)
        return True

    def execute(self):
        return self.update_old_at_search()


class ShowDeprecatedFilesMessages(MigrationFunctionAbstract):
    """
    Show message for deprecates files message like correlation searches and SA-ThreatIntelligence and SA-Ticketing
    and SA-Utils.
    """
    def __init__(self, session_key, messages, owner='nobody', app='itsi'):
        """
        Initialize DeleteCorrelationSearchConf

        @type session_key: basestring
        @param session_key: session key

        @type messages: list
        @param messages: list of messages to display

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.messages = messages

    def post_message(self):
        """
        Post couple messages to end user
        @return: None
        """
        if not self.messages:
            return # nothing to do here.

        for msg in self.messages:
            ITOAInterfaceUtils.create_message(self.session_key, msg)

    def show_migration_messages(self):
        """
        Show couple of message to users about deprecated files or app
        @return: True or False
        """
        try:
            response, content = rest.simpleRequest('/servicesNS/nobody/SA-ITOA/configs/conf-itsi_settings',
                                                   sessionKey=self.session_key, getargs={'output_mode': 'json',
                                                                                         'search': 'name=cloud'})
            if response.status == 200:
                entries = json.loads(content).get('entry')
                is_found_cloud_settings = False
                for entry in entries:
                    name = entry.get('name')
                    if name != 'cloud':
                        continue
                    is_found_cloud_settings = True
                    content = entry.get('content', {})
                    is_show_message = content.get('show_migration_message', 1)
                    if normalizeBoolean(is_show_message):
                        self.post_message()
                    else:
                        logger.info('We are not showing the message because flag is set to false')
                    break
                if not is_found_cloud_settings:
                    logger.info('Could not found cloud settings, hence switching to default behavior')
                    self.post_message()
            else:
                logger.error('Failed to get settings, hence defaulting to show message, response=%s, content=%s',
                             response, content)
                self.post_message()

        except Exception as e:
            logger.exception('Failed to get cloud setting, issue=%s, hence we are defaulting to show message', e.message)
            self.post_message()

        return True

    def execute(self):
        return self.show_migration_messages()


class CorrelationSearchMigration(MigrationFunctionAbstract):
    """
        Migrate from old notable events to new event management system
    """
    SEARCH_SCHEMA = {
        'disabled': '0',
        'cron_schedule': '*/5 * * * *',
        'dispatch.earliest_time': '-15m',
        'dispatch.latest_time': 'now',
        'description': '',
        'search':'',
        'name':'',
        'is_scheduled': '1',
        # Notable event specific properties
        'action.itsi_event_generator.param.title': '',
        'action.itsi_event_generator.param.description':'',
        'action.itsi_event_generator.param.status': '',
        'action.itsi_event_generator.param.owner':'',
        'action.itsi_event_generator.param.severity':'',
        'action.itsi_event_generator.param.drilldown_search_title': '',
        'action.itsi_event_generator.param.drilldown_search_search':'',
        'action.itsi_event_generator.param.drilldown_search_latest_offset': '300',
        'action.itsi_event_generator.param.drilldown_search_earliest_offset': '-300',
        'action.itsi_event_generator.param.drilldown_title': '',
        'action.itsi_event_generator.param.drilldown_uri': '',
        'action.itsi_event_generator.param.event_identifier_fields': 'source, title, description',
        'action.itsi_event_generator.param.service_ids': '',
        'action.itsi_event_generator.param.entity_lookup_field': '',
        # Composite KPIs based search special properties
        'action.itsi_event_generator.param.search_type': 'basic',
        'action.itsi_event_generator.param.meta_data': {},
        'action.itsi_event_generator.param.editor': 'advance_correlation_builder_editor',
        'action.itsi_event_generator': 1,
        'actions': 'itsi_event_generator',
        # Group by
        'alert.suppress': 0,
        'alert.suppress.fields': '',
        'alert.suppress.period': '',
        # Actions
        'action.rss': 0,
        # Email
        'action.email': 0,
        'action.email.to': '',
        'action.email.subject': '',
        'action.email.sendcsv': 0,
        'action.email.sendpdf': 0,
        'action.email.inline': 0,
        'action.email.format': 'pdf',
        'action.email.sendresults': 0,
        # Script
        'action.script': 0,
        'action.script.filename': ''
    }

    # Note if field does not exists then we will drop it
    SEARCH_META_FIELD_MAPPING = {
        'cron_schedule': 'cron_schedule',
        'start_time': 'dispatch.earliest_time',
        'end_time': 'dispatch.latest_time',
        'description': 'description',
        'search': 'search',
        'name': 'name',
        'gs_service_id': 'action.itsi_event_generator.param.service_ids',
        'default_status': 'action.itsi_event_generator.param.status',
        'default_owner': 'action.itsi_event_generator.param.owner',
        'severity': 'action.itsi_event_generator.param.severity',
        'drilldown_search': 'action.itsi_event_generator.param.drilldown_search_search',
        'drilldown_name': 'action.itsi_event_generator.param.drilldown_search_title',
        # Make sure earliest offset is set to negative instead of positive value
        'drilldown_earliest_offset': 'action.itsi_event_generator.param.drilldown_search_earliest_offset',
        'drilldown_latest_offset': 'action.itsi_event_generator.param.drilldown_search_latest_offset',
        'rule_title': 'action.itsi_event_generator.param.title',
        'rule_description': 'action.itsi_event_generator.param.description',
        'aggregate_duration': 'alert.suppress.period',
        'group_by': 'alert.suppress.fields',
        'rss_isenabled': 'action.rss',
        'script_isenabled': 'action.script',
        'script_filename': 'action.script.filename',
        'email_isenabled': 'action.email',
        'email_to': 'action.email.to',
        'email_subject': 'action.email.subject',
        'email_format': 'action.email.format',
        'email_sendresults': 'action.email.sendresults',
        'itsi_kpi_id': 'action.itsi_event_generator.param.ad_at_kpi_ids'
    }

    COMPOSITE_KPI_FIELD_MAPPING = {
        'kpis': 'score_based_kpis',
        'selected_services' : 'percentage_based_kpis'
    }

    COMPOSITE_PERCENTAGE_KPI_THRESHOLD_SCHEMA = {
        'severity': '',
        'percentage': 0,
        'percentage_operation': '>='
    }

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.old_search_type_key = 'search_type'
        self.old_storage = itoa_storage.ITOAStorage(collection="itsi_correlation_search")
        self.new_storage = ItsiCorrelationSearch(self.session_key, is_validate_service_ids=False)
        self.notable_event_configuration = NotableEventConfiguration(self.session_key, logger)
        # As need to provide only old field which support token replacement, but in new name format
        self.allow_token_replacement_fields = [
            'action.itsi_event_generator.param.title',
            'action.itsi_event_generator.param.description',
            'action.itsi_event_generator.param.drilldown_search_search',
            'action.itsi_event_generator.param.drilldown_search_title'
        ]
    @staticmethod
    def is_composite_score_kpi_type(search_type):
        """
        Check search composite kpi score based

        @type search_type: basestring
        @param search_type: search type

        @rtype: bool
        @return: True|False
        """
        return search_type and isinstance(search_type, basestring) and search_type == 'composite_kpi_score_type'

    @staticmethod
    def is_composite_percentage_kpi_type(search_type):
        """
        Check search composite kpi percentage based

        @type search_type: basestring
        @param search_type: search type

        @rtype: bool
        @return: True|False
        """
        return search_type and isinstance(search_type, basestring) and search_type == 'composite_kpi_percentage_type'

    def validate_dict(self, data):
        """
        Check if it is a valid dict

        @type data: dict
        @param data: object to validate

        @rtype: None
        @return: Raise Exception is not valid
        """
        if not isinstance(data, dict):
            msg = _('Invalid instance type for meta data. It has to be a valid dict')
            logger.error(msg)
            raise TypeError(msg)

    def _base_composite_kpi_transforms(self, meta_data):
        """
        Transform basic transform of old schem to new composite kpi schema

        @type meta_data: dict
        @param meta_data: old meta data to tranform

        @rtype: dict
        @return: Updated schema
        """
        self.validate_dict(meta_data)

        new_meta_data = {}
        for key, value in meta_data.iteritems():
            if not key:
                logger.warning('Found key empty, ignoring its value')
                continue
            # If it does not exist in transforms, take the same key
            new_key = self.COMPOSITE_KPI_FIELD_MAPPING.get(key, key)
            new_meta_data[new_key] = value
        return new_meta_data

    def transform_old_composite_kpi_data(self, meta_data):
        """
        Transform composite percentage based kpi schema to new format

        @type meta_data: dict
        @param meta_data: old meta data to tranform

        @rtype: dict
        @return: Updated schema
        """
        # base transform which transform top level keys for both kind of searches
        new_meta_data = self._base_composite_kpi_transforms(meta_data)
        # Convert selected_services to new format
        old_schema = new_meta_data.get('percentage_based_kpis')

        # Not defined, could be only score based
        if not old_schema:
            return new_meta_data

        # Old schema exist
        self.validate_dict(old_schema)

        # Remove old value
        new_meta_data.pop('percentage_based_kpis', None)

        percentage_based_kpis = []
        for service_id, old_thresholds_data in old_schema.iteritems():
            percentage_based_kpi = {}
            percentage_based_kpi['serviceid'] = service_id

            label_thresholds = {
                'operation': 'OR',
                'thresholds': []
            }
            for label_threshold in old_thresholds_data.get('kpis'):
                percentage_based_kpi['kpiid'] = label_threshold.get('kpi_id')
                # Transform old condition to structure way
                label_threshold_string = label_threshold.get('label_thresholds')
                # Example of condition is - (severity=medium AND percentage>=100) OR (severity=low AND percentage>=33)
                # ' OR (severity=normal AND percentage>=24)
                # Split with OR
                if not label_threshold_string:
                    # No label threshold, hence we does not need to add
                    logger.warning('No label thresholds for status based composite kpi search %s - ignoring', label_threshold.get('kpi_id'))
                    continue
                labels = label_threshold_string.split(' OR ')
                for label in labels:
                    label = label.strip().strip('()').strip()
                    if not label:
                        # very unlikely but check for safety
                        continue
                    severity_stmt, per_stmt = label.split(' AND ')
                    if not severity_stmt or not per_stmt:
                        # very unlikely but check for safety
                        continue
                    # Strip
                    severity_label, severity_value = severity_stmt.strip().split('=')
                    percentage_level, percentage_value = per_stmt.strip().split('>=')
                    threshold = copy.deepcopy(self.COMPOSITE_PERCENTAGE_KPI_THRESHOLD_SCHEMA)
                    threshold.update({
                        severity_label: severity_value,
                        percentage_level: percentage_value
                    })
                    label_thresholds.get('thresholds').append(threshold)
            percentage_based_kpi['label_thresholds'] = label_thresholds
            percentage_based_kpis.append(percentage_based_kpi)

        new_meta_data['percentage_based_kpis'] = percentage_based_kpis
        logger.info('Updated composite kpi search meta data is %s', new_meta_data)
        return new_meta_data

    def transform_search_data(self, search_data):
        """
        Convert old search data to new format

        @type search_data: dict
        @param search_data: search data

        @rtype: dict
        @return: new format of search parameters
        """
        self.validate_dict(search_data)

        new_search_schema = {}
        for key, value in search_data.iteritems():
            new_key = self.SEARCH_META_FIELD_MAPPING.get(key)
            if not new_key:
                # ignoring old value, it may be not related
                continue
            new_search_schema[new_key] = value

        if new_search_schema.get('alert.suppress.fields') and new_search_schema.get('alert.suppress.period'):
            new_search_schema['alert.suppress'] = 1
        if new_search_schema.get('action.itsi_event_generator.param.ad_at_kpi_ids'):
            new_search_schema['action.itsi_event_generator.param.is_ad_at'] = '1'

        # Check severity and status is defined properly
        severities = self.notable_event_configuration.severity_contents
        if severities:
            # Check severity in the given range
            old_severity = new_search_schema.get('action.itsi_event_generator.param.severity')
            if old_severity is None or old_severity == '' or old_severity not in severities.keys():
                is_set = False
                if old_severity:
                    # Check if we have it label
                    for key, content in severities.iteritems():
                        if content and content.get('label', '').lower() == old_severity.lower():
                            new_search_schema['action.itsi_event_generator.param.severity'] = key
                            is_set = True
                            logger.info('Old severity value %s is not compliance with new system, hence transforming'
                                        ' to value=%s ', old_severity, key)
                            break
                if not is_set:
                    # Set to default
                    new_search_schema['action.itsi_event_generator.param.severity'] = self.notable_event_configuration.get_default_severity()
                    logger.info('Old severity %s is not compliance with new system, setting to default', old_severity)
        # Check status
        statuses = self.notable_event_configuration.status_contents
        if statuses:
            old_status = new_search_schema.get('action.itsi_event_generator.param.status')
            if old_status is None or old_status == '' or old_status not in statuses.keys():
                is_set = False
                if old_status:
                    for key, content in statuses.iteritems():
                        if content and content.get('label', '').lower() == old_status.lower():
                            new_search_schema['action.itsi_event_generator.param.status'] = key
                            logger.info('Old status value %s is not compliance with new system, hence transforming'
                                        ' to value=%s ', old_status, key)
                            is_set = True
                            break

                if not is_set:
                    new_search_schema['action.itsi_event_generator.param.status'] = self.notable_event_configuration.get_default_status()
                    logger.info('Old status %s is not compliance with new system, setting to default', old_status)
        # Check owner
        owneres = self.notable_event_configuration.owner_contents
        if owneres:
            old_owner = new_search_schema.get('action.itsi_event_generator.param.owner')
            if old_owner is None or old_owner == '' or old_owner not in owneres.keys():
                is_set = False
                if old_owner:
                    for key, content in owneres.iteritems():
                        if content and content.get('realname', '').lower() == old_owner.lower():
                            is_set = True
                            new_search_schema['action.itsi_event_generator.param.owner'] = key
                            logger.info('Old owner value %s is not compliance with new system, hence transforming'
                                        'to user id=%s', old_owner, key)
                if not is_set:
                    new_search_schema['action.itsi_event_generator.param.owner'] =\
                        self.notable_event_configuration.get_default_owner()
                    logger.info('Old owner %s is not compliance with new system, setting to default', old_owner)

        # Earliest time
        ds_earliest_offset = new_search_schema.get('action.itsi_event_generator.param.drilldown_search_earliest_offset')
        if ds_earliest_offset:
            new_search_schema['action.itsi_event_generator.param.drilldown_search_earliest_offset'] = '-' + ds_earliest_offset

        # set title
        title = new_search_schema.get('action.itsi_event_generator.param.title')
        if not title or title == '':
            new_search_schema['action.itsi_event_generator.param.title'] = new_search_schema.get('name')


        # set sid as name which is needed for upgrade
        new_search_schema['sid'] = new_search_schema.get('name')

        regex = re.compile('\\$([\w.\s]+)\\$')
        for key, value in new_search_schema.iteritems():
            if not value:
                continue
            if key not in self.allow_token_replacement_fields:
                continue
            dynamic_fields = regex.findall(value)
            if dynamic_fields:
                new_value = value
                for field in dynamic_fields:
                    new_value = new_value.replace('$'+field+'$', '%'+field+'%')
                new_search_schema[key] = new_value

        logger.info('Updated search schema is %s', new_search_schema)
        return new_search_schema

    def update_correlation_search_schema(self, old_correlation_search):
        """
        Convert old correlation format to new one

        @type old_correlation_search: dict
        @param old_correlation_search: dict

        @rtype: dict
        @return: new format of correlation search
        """
        self.validate_dict(old_correlation_search)

        new_correlation_search_schema = copy.deepcopy(self.SEARCH_SCHEMA)

        # Update search meta data
        old_search_meta = old_correlation_search.get('search_meta_data')
        if not old_search_meta:
            logger.warning('Could not find search meta data of correlation search=%s', old_correlation_search)

        new_search_meta = self.transform_search_data(old_search_meta)

        new_correlation_search_schema.update(new_search_meta)

        # Update search type
        search_type = old_correlation_search.get('search_type')
        if search_type:
            new_correlation_search_schema['action.itsi_event_generator.param.search_type'] = search_type

        search_type = new_correlation_search_schema.get('action.itsi_event_generator.param.search_type')

        if self.is_composite_percentage_kpi_type(search_type) or self.is_composite_score_kpi_type(search_type):
            # Update meta_data
            old_meta_data = old_correlation_search.get('type_meta_data')
            if not old_meta_data:
                logger.warning('Could not find meta data though it is composite kpi search, hence reverting to basic')
                new_correlation_search_schema['action.itsi_event_generator.param.search_type'] = 'basic'
            else:
                new_meta_data = self.transform_old_composite_kpi_data(old_meta_data)
                new_correlation_search_schema['action.itsi_event_generator.param.meta_data'] = new_meta_data
                new_correlation_search_schema['action.itsi_event_generator.param.editor'] = 'advance_correlation_builder_editor, multi_kpi_alert_editor'
        else:
            new_correlation_search_schema.pop('action.itsi_event_generator.param.meta_data', None)

        # Update actions
        if normalizeBoolean(new_correlation_search_schema.get('action.email')):
            new_correlation_search_schema['actions'] += ',email'
        if normalizeBoolean(new_correlation_search_schema.get('action.rss')):
            new_correlation_search_schema['actions'] += ',rss'
        if normalizeBoolean(new_correlation_search_schema.get('action.script')):
            new_correlation_search_schema['actions'] += ',script'

        # Return
        # Set old fields to empty
        old_field_set_empyty = ['action.summary_index._name', 'action.summary_index.editor',
                               'action.summary_index.gs_service_id', 'action.summary_index.multikpialerts_info']
        for field in old_field_set_empyty:
            new_correlation_search_schema[field] = ''

        return new_correlation_search_schema

    def get_all_correlation_searches(self):
        """
        Get all corrlation searches
        @return:
        """
        return self.old_storage.get_all(self.session_key, self.owner, 'correlation_search')

    def upgrade_correlation_searches_schema(self, correlation_searches):
        """
        Upgrade correlation searches

        @type correlation_searches: list
        @param correlation_searches: list of correlation to upgrade

        @rtype: list
        @return: Updated list
        """
        updated_correlation_searches = []
        for cs in correlation_searches:
            new_cs = self.update_correlation_search_schema(cs)
            # Change name of Anomaly search to remove - Rule from search
            if new_cs.get('name') == 'ITSI anomaly detection correlation search - Rule':
                new_cs['name'] = 'ITSI anomaly detection correlation search'
            updated_correlation_searches.append(new_cs)
        return updated_correlation_searches

    def upgrade_correlation_searches(self):
        """
        Upgrade correlation searches to new schema

        @rtype: bool
        @return: True|False or exception
        """
        correlation_searches = self.get_all_correlation_searches()
        updated_correlation_searches = self.upgrade_correlation_searches_schema(correlation_searches)
        self.save_all_correlation_searches(updated_correlation_searches)
        # Delete it data from kv store
        self.old_storage.delete_all(self.session_key, self.owner, 'correlation_search', {'object_type': 'correlation_search'})
        return True

    def save_all_correlation_searches(self, correlation_searches):
        """
        Save correlation searches

        @type correlation_searches: list
        @param correlation_searches: list of correlation search to update

        @return: None
        """
        updated_correlation_searches = []
        for search_data in correlation_searches:
            # Anomaly has special case, where we need to delete - Rule search and create new one
            if search_data.get('name') == 'ITSI anomaly detection correlation search':
                # ITSI anomaly detection correlation search - Rule
                try:
                    SavedSearch.delete_search(self.session_key, 'ITSI anomaly detection correlation search - Rule')
                except ResourceNotFound:
                    logger.info('ITSI anomaly detection correlation search - Rule does not exist')
                self.new_storage.create(search_data, raise_if_exist=False)
            else:
                updated_correlation_searches.append(search_data)

        search_keys = [search.get('name') for search in updated_correlation_searches]
        results = self.new_storage.update_bulk(search_keys, updated_correlation_searches)
        logger.info('Updated search names=%s', results)
        logger.info('Updated %s correlation searches successfully', len(results))

    def execute(self):
        """
        Execute a search which pull data from old system to new one
        @return:
        """
        return self.upgrade_correlation_searches()


class DeleteOldLBKPITemplateMigration(MigrationFunctionAbstract):

    TEMPLATES_TO_DELETE = [
        'DA-ITSI-LB-Client_Connections',
        'DA-ITSI-LB-Availability',
        'DA-ITSI-LB-Failover',
        'DA-ITSI-LB-Server_Throughput',
        'DA-ITSI-LB-SSL_Transactions_per_Second',
        'DA-ITSI-LB-Server_Connections',
        'DA-ITSI-LB-Client_Throughput',
        'DA-ITSI-LB-5XX_Responses_from_Server',
        'DA-ITSI-LB-Round_Trip_Time',
        'DA-ITSI-LB-Concurrent_Sessions',
        'DA-ITSI-LB-CPU_Utilization_%25_By_System',
        'DA-ITSI-LB-Memory_Used_%25_By_System',
        'DA-ITSI-LB-System_Storage_Used_%25_By_System'
    ]

    def __init__(self, session_key, owner="nobody", app="itsi"):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app

    def delete_old_templates(self):
        """
        Delete Old Templates. We continue if we failed to delete one or more template

        @rtype: bool
        @return: True/False
        """
        kpi_template_object = ItsiKpiTemplate(self.session_key, self.owner)
        for delete_template in self.TEMPLATES_TO_DELETE:
            try:
                logger.info('Trying to deleting old lb kpi template="%s"', delete_template)
                result = kpi_template_object.delete(self.owner, delete_template, 'migration')
                logger.info('Successfully delete LB kpi template="%s", result=%s', delete_template, result)
            except Exception:
                # Ignoring exception
                logger.exception('Failed to delete kpi template="%s"', delete_template)
        return True

    def execute(self):
        """
        Perform action
        @rtype: bool
        @return: True/False
        """
        return self.delete_old_templates()

class MigrateToCommonGlassTable(MigrationFunctionAbstract):
    """
    Migrate from Old Glass table content string, to a content object
    and move from old filesave storage to the app common one
    """
    DEFAULT_STAT_MODEL = {
        'whereClause': '',
        'assetId': None,
        'thresholdSettingModel': {
            'isMaxStatic': False,
            'renderBoundaryMax': 100,
            'baseSeverityLabel': 'normal',
            'comparator': '>=',
            'renderBoundaryMin': 0,
            'gaugeMax': 100,
            'baseSeverityColor': '#99D18B',
            'isMinStatic': True,
            'search': '',
            'metricField': 'count',
            'baseSeverityValue': 2,
            'thresholdLevels': [
                {
                    'severityColor': '#99D18B',
                    'severityValue': 2,
                    'severityLabel': 'normal',
                    'severityColorLight': '#DCEFD7',
                    'dynamicParam': 0,
                    'thresholdValue': 0
                },
                {
                    'severityColor': '#FCB64E',
                    'severityValue': 4,
                    'severityLabel': 'medium',
                    'severityColorLight': '#FEE6C1',
                    'dynamicParam': 0,
                    'thresholdValue': 50
                },
                {
                    'severityColor': '#B50101',
                    'severityValue': 6,
                    'severityLabel': 'critical',
                    'severityColorLight': '#E5A6A6',
                    'dynamicParam': 0,
                    'thresholdValue': 75
                }
            ],
            'baseSeverityColorLight': '#DCEFD7',
            'gaugeMin': 0
        },
        'dataModel': {
            'owner_field': '',
            'object': '',
            'datamodel': '',
            'field': ''
        },
        'severityField': '',
        'earliest': '-15m',
        'sparklineEarliest': -3600,
        'searchSource': 'adhoc',
        'severityColor': '#3c3c3c',
        'useGenerated': False,
        'latest': 'now',
        'search': 'index=_internal | timechart count',
        'searches': {
            'base': {
                'generated': 'index=_internal | timechart count',
                'raw': 'index=_internal | timechart count'
            },
            'timecompare': {
                'generated': 'index=_internal | timechart count',
                'raw': 'index=_internal | timechart count'
            },
            'timeseries': {
                'generated': 'index=_internal | timechart count',
                'raw': 'index=_internal | timechart count'
            }
        },
        'thresholdMode': False,
        'severityLabel': 'NA',
        'dataModelStatOp': '',
        'thresholdLabel': 'count'
    }
    ICON_DEFAULT_MAP = {
        'ActiveDirectoryIcon': {
            'w': 118.882,
            'h': 118.914
        },
        'AppIcon': {
            'w': 102.244,
            'h': 105.852
        },
        'CloudIcon': {
            'w': 105,
            'h': 66
        },
        'DatacenterIcon': {
            'w': 75,
            'h': 105
        },
        'DatacentersIcon': {
            'w': 105,
            'h': 105
        },
        'DataModelIcon': {
            'w': 105,
            'h': 105
        },
        'DatastoreIcon': {
            'w': 69,
            'h': 105
        },
        'DatastoresIcon': {
            'w': 105,
            'h': 105
        },
        'DesktopIcon': {
            'w': 102,
            'h': 98
        },
        'DirectoryIcon': {
            'w': 104.654,
            'h': 84
        },
        'DocumentIcon': {
            'w': 81,
            'h': 105
        },
        'EnvelopeIcon': {
            'w': 105,
            'h': 75
        },
        'FirewallIcon': {
            'w': 105,
            'h': 79.214
        },
        'ForwarderIcon': {
            'w': 105,
            'h': 105
        },
        'GearIcon': {
            'w': 105,
            'h': 105
        },
        'GearsIcon': {
            'w': 105,
            'h': 105
        },
        'GlobeIcon': {
            'w': 105,
            'h': 105
        },
        'GroupIcon': {
            'w': 105,
            'h': 59.522
        },
        'HomeIcon': {
            'w': 115.673,
            'h': 102.969
        },
        'IndexerIcon': {
            'w': 105,
            'h': 105
        },
        'InternetOfThingsIcon': {
            'w': 105,
            'h': 105
        },
        'IPhoneIcon': {
            'w': 51,
            'h': 105
        },
        'LaptopIcon': {
            'w': 105,
            'h': 96
        },
        'LoadBalancerIcon': {
            'w': 102,
            'h': 102
        },
        'MagnifyingGlassIcon': {
            'w': 105,
            'h': 105
        },
        'NetworkIcon': {
            'w': 105,
            'h': 105
        },
        'NetworkSwitchIcon': {
            'w': 105,
            'h': 105
        },
        'PersonIcon': {
            'w': 95.996,
            'h': 104.825
        },
        'PersonAltIcon': {
            'w': 96.689,
            'h': 105
        },
        'RouterIcon': {
            'w': 105,
            'h': 105
        },
        'ScriptIcon': {
            'w': 79.719,
            'h': 105
        },
        'SearchHeadIcon': {
            'w': 105,
            'h': 105
        },
        'ServerIcon': {
            'w': 105,
            'h': 105
        },
        'ServerAltIcon': {
            'w': 105,
            'h': 105
        },
        'ToolsIcon': {
            'w': 102,
            'h': 104.169
        },
        'VirtualIndexerIcon': {
            'w': 104.999,
            'h': 104.998
        },
        'VirtualServerIcon': {
            'w': 105,
            'h': 105
        }
    }
    VIZTYPE_MAP = {
        0: {
            'vizType': 'single_value',
            'name': 'SingleValue'
        },
        1: {
            'vizType': 'gauge',
            'name': 'Gauge'
        },
        2: {
            'vizType': 'sparkline',
            'name': 'Sparkline'
        },
        3: {
            'vizType': 'svd',
            'name': 'SingleValueDelta'
        },
        4: {
            'vizType': 'circular',
            'name': 'CircularWidget'
        },
        5: {
            'vizType': 'square',
            'name': 'SquareWidget'
        }
    }

    SEVERITY_LEVEL_MAP = {
        'INFO': {
            'severityLabel': "info",
            'severityColor': "#AED3E5",
            'severityColorLight': "#E3F0F6",
            'severityValue': 1
        },
        'NORMAL': {
            'severityLabel': "normal",
            'severityColor': "#99D18B",
            'severityColorLight': "#DCEFD7",
            'severityValue': 2
        },
        'LOW': {
            'severityLabel': "low",
            'severityColor': "#FFE98C",
            'severityColorLight': "#FFF4C5",
            'severityValue': 3
        },
        'MEDIUM': {
            'severityLabel': "medium",
            'severityColor': "#FCB64E",
            'severityColorLight': "#FEE6C1",
            'severityValue': 4
        },
        'HIGH': {
            'severityLabel': "high",
            'severityColor': "#F26A35",
            'severityColorLight': "#FBCBB9",
            'severityValue': 5
        },
        'CRITICAL': {
            'severityLabel': "critical",
            'severityColor': "#B50101",
            'severityColorLight': "#E5A6A6",
            'severityValue': 6
        }
    }

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initializes the Migration object with the necessary
        default values and lookup maps

        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.gt_coll = itoa_storage.ITOAStorage(collection='itsi_pages')
        self.service_storage = ItoaObject(session_key=self.session_key, current_user_name=self.owner, object_type='service')
        self.api_filesave_service = ApifilesaveService(app_name='SA-ITOA', session_id=self.session_key, user_name=self.owner, collection_name='SA-ITOA_files')
        self.tool_conversion_map = {
            'PolyRect': self.convert_rectangle,
            'PolyEllipse': self.convert_ellipse,
            'ExtLine': self.convert_line,
            'ExtLabel': self.convert_textbox,
            'PolyIcon': self.convert_icon,
            'ExtConnection': self.convert_connection,
            'PolyImage': self.convert_image
        }
        self.kpi_map = None

    def get_generated_search(self, kpi_id):
        """
        Generates a search based on the summary index
        @type kpi_id: string
        @param kpi_id: the content object to be changed

        @return: string
        """
        to_return = '`get_full_itsi_summary_kpi({0})` `service_level_kpi_only` | ' \
                    'head 1 | table alert_value, alert_severity, alert_color | ' \
                    'rename alert_value AS aggregate, alert_severity AS aggregate_severity, ' \
                    'alert_color AS aggregate_color'.format(kpi_id)
        return to_return

    def get_generated_time_series_search(self, kpi_id):
        """
        Generates a time series search based on the summary index
        @type kpi_id: string
        @param kpi_id: the id of the kpi

        @return: string
        """
        to_return = '`get_full_itsi_summary_kpi({0})` `service_level_kpi_only` | ' \
                    'stats latest(alert_value) AS aggregate, latest(alert_severity) ' \
                    'AS aggregate_severity, latest(alert_color) AS aggregate_color BY _time'.format(kpi_id)
        return to_return

    def get_generated_time_compare_search(self, kpi_id):
        """
        Generates a time compare search based on the summary index
        @type kpi_id: string
        @param kpi_id: the id of the kpi

        @return: string
        """
        to_return = '`get_full_itsi_summary_kpi({0})` `service_level_kpi_only` | ' \
                    'addinfo | eval mid_time = (info_max_time + info_min_time) / 2 | ' \
                    'eval bucket=if(_time < mid_time, "last_window", "current_window") | ' \
                    'stats latest(alert_value) AS aggregate, latest(alert_severity) ' \
                    'AS aggregate_severity, latest(alert_color) AS aggregate_color BY bucket | ' \
                    'reverse | delta aggregate AS window_delta | search bucket=current_window | ' \
                    'eval window_direction=if(window_delta > 0, "increase", ' \
                    'if(window_delta < 0, "decrease", "none"))'.format(kpi_id)

        return to_return

    def common_conversion(self, content, name, searchFigure=False):
        """
        @type content: dict
        @param content: the content object to be changed

        @type name: string
        @param name: the name of the figure

        @type searchFigure: bool
        @param searchFigure: indicates whether or not figure is search figure
        """
        content.pop('ports', None)
        content.pop('type', None)
        content.pop('radius', None)
        content.pop('cssClass', None)
        content.pop('userData', None)
        content.pop('outlineStroke', None)
        content.pop('outlineColor', None)
        content.pop('policy', None)
        content.pop('router', None)
        content.pop('alpha', None)
        content['locked'] = content.pop('is_locked', False)
        content['name'] = name
        content['vizType'] = None
        content['statModel'] = None
        content['drilldownModel'] = None
        content['searchFigure'] = searchFigure
        content['labelFlag'] = True
        content['label'] = ''
        content['unit'] = ''
        content['isDeleted'] = False
        content['parent'] = ''

    def convert_rectangle(self, content):
        """
        Modifies the rectangle object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'Rectangle')

    def convert_ellipse(self, content):
        """
        Modifies the ellipse object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'Ellipse')
        content.pop('vertices', None)
        content['alpha'] = 1

    def convert_line(self, content):
        """
        Modifies the line object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'Line')
        content['vertices'] = content.pop('vertex')
        content['assetId'] = None
        content['type'] = None
        content['width'] = 30
        content['height'] = 30
        content['startX'] = content['vertices'][0]['x']
        content['startY'] = content['vertices'][0]['y']
        content['endX'] = content['vertices'][1]['x']
        content['endY'] = content['vertices'][1]['y']
        content['x'] = content['vertices'][0]['x']
        content['y'] = content['vertices'][0]['y']

    def convert_textbox(self, content):
        """
        Modifies the textbox object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'Text')
        content['padding'] = 0
        content['statModel'] = self.DEFAULT_STAT_MODEL

    def convert_icon(self, content):
        """
        Modifies the icon object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'PolyIcon')
        content['statModel'] = self.DEFAULT_STAT_MODEL
        content['defaultWidth'] = self.ICON_DEFAULT_MAP[content['iconId']]['w']
        content['defaultHeight'] = self.ICON_DEFAULT_MAP[content['iconId']]['h']
        content['vizType'] = 'single_value'

    def convert_connection(self, content):
        """
        Modifies the connection object to use the new app_common data format
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        label = content['label']
        self.common_conversion(content, 'Connection')
        content.pop('vertex', None)
        content.pop('startPt', None)
        content.pop('endPt', None)
        content['bgColor'] = '#FFFFFF'
        content['sourceId'] = content.pop('source')['node']
        content['targetId'] = content.pop('target')['node']
        content['assetId'] = None
        content['locked'] = not content['locked']
        content['label'] = label
        content.update(dict.fromkeys(['x', 'y', 'height', 'width'], 30))

    def convert_image(self, content):
        """
        Modifies the image to use app common data format
        and moves the image to the new filesave collection
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        self.common_conversion(content, 'PolyImage')
        content['statModel'] = self.DEFAULT_STAT_MODEL
        content['vizType'] = 'single_value'
        # move to new filesave collection
        new_image_obj = {}
        new_image_obj['acl'] = copy.deepcopy(self.curr_acl)
        new_image_obj['acl']['perms']['read'] = ['*']
        new_image_obj['acl']['perms']['write'] = ['*']
        img_data = content.pop('path', None)
        img_data = img_data.split(',')
        new_image_obj['data'] = img_data[1]
        new_image_obj['name'] = 'name'

        # This regex pulls the type of image format from the data string
        exp = re.compile('.*?:(.+)?;')
        result = exp.match(img_data[0])
        if result.group(1):
            new_image_obj['type'] = result.group(1)
        response = self.api_filesave_service.create(new_image_obj)
        response_obj = json.loads(response)
        content['fileModel'] = {
            'type': new_image_obj['type'],
            '_key': response_obj['_key']
        }

    def convert_search_widget(self, content):
        """
        Changes the search widgets to use the new app common data format
        It will alter the statmodel and drilldown model to ensure that
        the functionality on gt remains the same
        @type content: dict
        @param content: the content object to be changed

        @return:
        """
        persistent_attributes = content.pop('persistentAttributes', None)
        widget_attributes = content.pop('widgetAttributes', None)
        if not persistent_attributes or not widget_attributes:
            raise Exception(_('Old glasstable data in an invalid format'))
        self.common_conversion(content, self.VIZTYPE_MAP[int(widget_attributes['vizType'])]['name'], True)
        content['vizType'] = self.VIZTYPE_MAP[int(widget_attributes['vizType'])]['vizType']
        content['id'] = persistent_attributes.get('id', ITOAInterfaceUtils.generate_backend_key())
        content['x'] = persistent_attributes.get('x', 0)
        content['y'] = persistent_attributes.get('y', 0)
        content['width'] = persistent_attributes.get('width', 0)
        content['height'] = persistent_attributes.get('height', 0)
        content['labelFlag'] = bool(int(widget_attributes.get('labelFlag', 1)))
        content['unit'] = widget_attributes.get('unit', '')
        content['label'] = widget_attributes.get('labelVal', '')
        content['assetId'] = None

        # Convert Drilldown Model Values
        old_dd_settings_model = widget_attributes.get('drilldownSettingsModel', {})
        new_drilldown_model = {
            'useCustomDrilldown': bool(int(widget_attributes.get('useCustomDrilldown', 0))),
            'drilldownSettingsModel': {
                'objPage': 'search',
                'objType': old_dd_settings_model.get('objType', 'default'),
                'objId': old_dd_settings_model.get('objId', ''),
                'objOwner': old_dd_settings_model.get('objOwner', 'nobody'),
                'params': old_dd_settings_model.get('params', {}),
                'customUrl': old_dd_settings_model.get('customUrl', ''),
            }
        }
        content['drilldownModel'] = new_drilldown_model

        # Convert Stat Model Values
        new_stat_model = copy.deepcopy(self.DEFAULT_STAT_MODEL)
        new_stat_model['severityField'] = 'aggregate_color'
        new_stat_model['searches']['base']['raw'] = widget_attributes.get('search', new_stat_model['searches']['base']['raw'])
        new_stat_model['searches']['timeseries']['raw'] = widget_attributes.get('search_time_series_aggregate', new_stat_model['searches']['timeseries']['raw'])
        new_stat_model['searches']['timecompare']['raw'] = widget_attributes.get('search_time_compare', new_stat_model['searches']['timecompare']['raw'])
        new_stat_model['search'] = widget_attributes.get('search', new_stat_model['search'])
        new_stat_model['searchManagerId'] = content['id'] + '_manager'
        new_stat_model['useGenerated'] = False if widget_attributes.get('useKPISummary', 'yes') == 'no' else True
        new_stat_model['thresholdMode'] = widget_attributes.get('isThresholdEnabled', False)
        new_stat_model['severityLabel'] = 'NA'
        new_stat_model['searchSource'] = 'datamodel' if widget_attributes.get('searchSource', 'adhoc') == 'datamodel' else 'adhoc'
        new_stat_model['whereClause'] = widget_attributes.get('dataModelWhereClause', '')
        new_stat_model['latest'] = 'now'
        new_stat_model['earliest'] = '-60m'
        if new_stat_model['searchSource'] == 'datamodel':
            new_stat_model['timeSeriesSearch'] = new_stat_model['search']
            new_stat_model['timeCompareSearch'] = new_stat_model['search']
            new_stat_model['dataModel'] = widget_attributes['dataModelSpecification']
            new_stat_model['dataModelStatOp'] = widget_attributes['dataModelStatOp']
        new_threshold_setting_model = {}
        new_threshold_setting_model['comparator'] = widget_attributes.get('threshold_comparator', '>=')
        new_threshold_setting_model['search'] = ''
        new_threshold_levels = []
        if persistent_attributes['userData']['name'] == 'ContextItem':
            self.set_kpi_widget_properties(content, widget_attributes, new_stat_model, new_threshold_setting_model)
        else:
            self.set_adhoc_widget_properties(widget_attributes, new_stat_model, new_threshold_setting_model, new_threshold_levels)
        new_threshold_setting_model['thresholdLevels'] = new_threshold_levels
        new_stat_model['thresholdSettingModel'] = new_threshold_setting_model
        content['statModel'] = new_stat_model

    def set_adhoc_widget_properties(self, widget_attributes, new_stat_model, new_threshold_setting_model, new_threshold_levels):
        """
        Sets the properties for an adhoc search widget
        @type widget_attributes: dict
        @param widget_attributes: the list of widget attributes in the old schema

        @type new_stat_model: dict
        @param new_stat_model: the new stat model to be converted

        @type new_threshold_setting_model: dict
        @param new_threshold_setting_model: the new threshold settings model to be added to

        @type new_threshold_levels: dict
        @param new_threshold_levels: the list of new threshold levels

        @return:
        """
        new_stat_model['useGenerated'] = False
        threshold_field = widget_attributes.get('threshold_field', '')
        new_stat_model['thresholdLabel'] = 'count' if threshold_field == '' else threshold_field
        new_stat_model['sparklineEarliest'] = int(widget_attributes['search_alert_earliest'][:-1]) * 60 if 'search_alert_earliest' in widget_attributes and isinstance(widget_attributes['search_alert_earliest'], str) else new_stat_model['sparklineEarliest']
        # Add threshold Levels
        if all(k in widget_attributes for k in ('threshold_values', 'threshold_labels', 'search_aggregate', 'search_time_compare', 'search_time_series_aggregate')):
            for i in range(2, len(widget_attributes['threshold_values']) - 1):
                new_level = copy.deepcopy(self.SEVERITY_LEVEL_MAP[widget_attributes['threshold_labels'][i - 1].upper()])
                new_level['thresholdValue'] = widget_attributes['threshold_values'][i]
                new_level['dynamicParam'] = 0
                new_threshold_levels.append(new_level)
            # Convert Threshold Setting Model Values
            new_threshold_setting_model['baseSeverityValue'] = self.SEVERITY_LEVEL_MAP[widget_attributes['threshold_labels'][0].upper()]['severityValue']
            new_threshold_setting_model['baseSeverityColor'] = self.SEVERITY_LEVEL_MAP[widget_attributes['threshold_labels'][0].upper()]['severityColor']
            new_threshold_setting_model['baseSeverityLabel'] = self.SEVERITY_LEVEL_MAP[widget_attributes['threshold_labels'][0].upper()]['severityLabel']
            new_threshold_setting_model['baseSeverityColorLight'] = self.SEVERITY_LEVEL_MAP[widget_attributes['threshold_labels'][0].upper()]['severityColorLight']
            new_threshold_setting_model['renderBoundaryMin'] = widget_attributes['threshold_values'][0]
            new_threshold_setting_model['renderBoundaryMax'] = widget_attributes['threshold_values'][-1]
            new_threshold_setting_model['gaugeMin'] = widget_attributes['threshold_values'][0]
            new_threshold_setting_model['gaugeMax'] = widget_attributes['threshold_values'][-1]
            new_threshold_setting_model['isMinStatic'] = True
            new_threshold_setting_model['isMaxStatic'] = False
        if new_stat_model['thresholdMode']:
            new_stat_model['searches']['base']['raw'] = widget_attributes['search_aggregate'] + widget_attributes['threshold_eval']
            new_stat_model['searches']['timecompare']['raw'] = widget_attributes['search_time_compare'] + widget_attributes['threshold_eval']
            new_stat_model['searches']['timeseries']['raw'] = widget_attributes['search_time_series_aggregate'] + widget_attributes['threshold_eval']
            new_threshold_setting_model['metricField'] = 'aggregate'
        else:
            new_threshold_setting_model['metricField'] = new_stat_model['thresholdLabel']

    def set_kpi_widget_properties(self, content, widget_attributes, new_stat_model, new_threshold_setting_model):
        """
        Sets the properties for a kpi search widget
        @type content: dict
        @param content: the overall figure content to be changed

        @type widget_attributes: dict
        @param widget_attributes: the list of widget attributes in the old schema

        @type new_stat_model: dict
        @param new_stat_model: the new stat model to be converted

        @type new_threshold_setting_model: dict
        @param new_threshold_setting_model: the new threshold settings model to be added to

        @return:
        """
        new_stat_model['sparklineEarliest'] = int(widget_attributes['sparkline_alert_earliest'][:-1]) * 60 if 'sparkline_alert_earliest' in widget_attributes else new_stat_model['sparklineEarliest']
        new_stat_model['thresholdLabel'] = widget_attributes.get('threshold_field', '')
        new_stat_model['assetId'] = widget_attributes.get('kpi_id', ITOAInterfaceUtils.generate_backend_key())
        content['assetId'] = widget_attributes.get('kpi_id', ITOAInterfaceUtils.generate_backend_key())
        content['parent'] = widget_attributes.get('context_id', ITOAInterfaceUtils.generate_backend_key())
        new_stat_model['searches']['base']['generated'] = self.get_generated_search(widget_attributes['kpi_id'])
        new_stat_model['searches']['timeseries']['generated'] = self.get_generated_time_series_search(widget_attributes['kpi_id'])
        new_stat_model['searches']['timecompare']['generated'] = self.get_generated_time_compare_search(widget_attributes['kpi_id'])
        new_stat_model['metricField'] = 'aggregate'
        # Convert Threshold Setting Model Values
        self.set_threshold_model_for_kpi(new_threshold_setting_model, content['assetId'])
        if new_stat_model['useGenerated']:
            new_threshold_setting_model['metricField'] = 'aggregate'
        else:
            new_threshold_setting_model['metricField'] = 'alert_value'
            new_stat_model['severityField'] = 'alert_color'

    def set_threshold_model_for_kpi(self, new_threshold_setting_model, kpi_id):
        """
        Sets the threshold model properties for a kpi
        @type content: dict
        @param widget_attributes: the list of widget attributes in the old schema

        @type new_threshold_setting_model: dict
        @param new_threshold_setting_model: the new threshold settings model to be added to

        @type kpi_id: string
        @param kpi_id: the new threshold settings model to be added to

        @return:
        """
        if not self.kpi_map:
            self.get_all_kpis()
        keys = ['baseSeverityValue', 'baseSeverityColor', 'baseSeverityLabel', 'baseSeverityColorLight', 'renderBoundaryMin', 'renderBoundaryMax', 'gaugeMin', 'gaugeMax', 'isMinStatic', 'isMaxStatic']
        for k in keys:
            if kpi_id in self.kpi_map:
                new_threshold_setting_model[k] = self.kpi_map[kpi_id]['aggregate_thresholds'][k]

    def convert_content_string(self, content_str):
        """
        Converts the old content string to the new svg object
        @type content_str: basestring
        @param content_str: the content string to be converted into an object
        @rtype: dict
        """
        if content_str == '':
            return content_str
        content = json.loads(content_str)
        if not isinstance(content, list):
            raise Exception(_('Old glasstable data in an invalid format'))
        for figure in content:
            if 'userData' in figure:
                self.tool_conversion_map[figure['userData']['name']](figure)
            else:
                self.convert_search_widget(figure)
        return content

    def get_all_gts(self):
        """
        Returns a list of all the services in json form
        @rtype: dict
        """
        return self.gt_coll.get_all(self.session_key, self.owner, 'glass_table')

    def get_all_kpis(self):

        """
        Fetches a list of kpis and hashes them by kpi_id for quick access
        @return:
        """
        service_coll = self.service_storage.get_bulk(self.owner, fields=['_key', 'kpis.aggregate_thresholds', 'kpis._key'])
        self.kpi_map = {}
        for s in service_coll:
            for k in s['kpis']:
                self.kpi_map[k['_key']] = k

    def convert_single_gt(self, gt):
        """
        Converts a single gt object to the new data format
        @type gt: dict
        @param gt: the glass table object to be converted

        @return:
        """
        # Converting top level attributes in GT Model
        svg_str = gt['svg_coordinates']
        try:
            gt['svg_coordinates'] = json.loads(svg_str)
        except:
            gt['svg_coordinates'] = ''
        gt.pop('source_itsi_da', None)
        self.curr_acl = gt['acl']
        # Converting Content String
        gt['content'] = self.convert_content_string(gt.pop('svg_content', '[]'))

    def migrate_to_common_gt(self):
        """
        Main Method for running this migration
        @rtype: bool
        @return: True/False
        """
        try:
            gts = self.get_all_gts()
            for gt in gts:
                # This is a hack to ensure that an already migrated GT doesn't get reconverted
                if 'content' in gt:
                    logger.info('GT with id: %s has already been migrated', gt['_key'])
                    continue
                self.convert_single_gt(gt)
                self.gt_coll.edit(session_key=self.session_key, owner=self.owner, objecttype='glass_table', identifier=gt['_key'], data=gt)
            logger.info('Successfully migrated to new GT Data Format')
        except Exception as e:
            logger.exception(
                'Encountered an error. Please try this manually via UI or contact Splunk support.')
            return False
        return True

    def execute(self):
        """
        Perform action
        @rtype: bool
        @return: True/False
        """
        return self.migrate_to_common_gt()

############################### Entity Deduplication ##################################

class EntityAliasDuplicateHandler(MigrationFunctionAbstract):

    def __init__(self, session_key, owner='nobody', app='itsi'):
        self.session_key = session_key
        self.owner = owner
        self.app = app

    def simple_dedup_entity(self, entity, seen_values, duplicate_values):
        """
        Go through an Entity and check the identifying key:value pairs.
        If the pair exists in seen_values, the move then append that field to
        the informational section
        :param entity:
        :param seen_values:
        :return:
        """
        id_fields = entity['identifier']['fields']
        id_values = entity['identifier']['values']
        info_fields = entity['informational']['fields']
        info_values = entity['informational']['values']

        def _detect_duplicate(field):
            alias_values = entity[field]
            ret_value = 1
            for value in alias_values:
                if value.lower() not in seen_values:
                    seen_values[value.lower()] = 1
                else:
                    logger.debug('Duplicate Identifying Value Found: %s', value)
                    # Keep track of the duplicate value encountered
                    if value.lower() in duplicate_values:
                        duplicate_values[value.lower()] = duplicate_values[value.lower()] + 1
                    else:
                        duplicate_values[value.lower()] = 1

                    info_fields.append(field)
                    info_values.extend(alias_values)
                    # Indicate that I've seen the value more than once in the seen_values dict
                    seen_values[value.lower()] = seen_values[value.lower()] + 1
                    for moved_value in alias_values:
                        # Remove ALL of the values in the identifying.values list from:
                        # identifying.values + seen_values dict
                        if moved_value.lower() in id_values:
                            id_values.remove(moved_value.lower())

                        if moved_value.lower() in seen_values:
                            if seen_values[moved_value.lower()] > 1:
                                seen_values[moved_value.lower()] = seen_values[moved_value.lower()] - 1
                            else:
                                del seen_values[moved_value.lower()]
                    ret_value = 0
                    break
            return ret_value

        id_fields[:] = [field for field in id_fields if _detect_duplicate(field)]
        entity['identifier']['fields'] = id_fields
        entity['identifier']['values'] = id_values
        entity['informational']['fields'] = info_fields
        entity['informational']['values'] = info_values

    def remove_alias_duplicates(self):
        """
        Main method for managing the deduplication of the aliases within entities
        :return: True/False
        """
        success = False
        traversed_values = {}
        duplicated_values = {}
        entity_obj = instantiate_object(self.session_key, 'nobody', 'entity', logger)
        entity_itr = entity_obj.get_bulk(self.owner, req_source='entity_dedup')
        logger.info('Running deduplication process')
        try:
            for entity in entity_itr:
                self.simple_dedup_entity(entity, traversed_values, duplicated_values)

            logger.info('Starting to save back modified entities')
            entity_obj.save_batch(self.owner, entity_itr, False, req_source='entity_dedup')
            logger.info('Save Complete. Entities should no longer contain duplicate aliases')
            success = True
        except:
            logger.exception(
                'Failed to deduplicate aliases for all entities. Please check the logs before you re-run this script'
            )
            return False
        return success

    def execute(self):
        """
        Perform the action
        :return: True/False
        """
        return self.remove_alias_duplicates()

############################### Migration caller ##################################

class ItsiMigration(object):
    '''
    Class for itsi migration
    '''

    BACKUP_FILE = make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', 'backup_kv_store.json'])
    BACKUP_FILE_GLOB_REGEX = make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', 'backup_kv_store*.json'])

    INITIAL_WARNING_MSG = _("Validating IT Service Intelligence configuration. While validation is in process, the application is not accessible.")
    UPDATE_SUCESSFUL_MSG = _("IT Service Intelligence minor version upgrade from {} to {} has completed successfully")
    FINAL_SUCCESSFUL_MSG = _("IT Service Intelligence upgrade has completed successfully.")
    FINAL_FAILED_MSG = _("IT Service Intelligence upgrade has failed.")

    def __init__(self,
                 session_key,
                 backup_file_path=None,
                 app="itsi",
                 owner='nobody',
                 backup_version=None,
                 dupname_tag=None):
        '''
        Initialize
        @param session_key: splunkd session key
        @param backup_file_path: file path where back is being stored
        @param app: app name
        @param owner: user or owner
        @return:
        '''
        self.session_key = session_key
        if backup_file_path:
            self.backup_file = backup_file_path
        else:
            self.backup_file = ItsiMigration.BACKUP_FILE
        self.app = app
        self.owner = owner
        self.backup_version = backup_version
        self.dupname_tag = dupname_tag

    def _create_migration_object(self, old_ver, new_ver):
        '''
        Constructor for migration class object
        @param old_ver: old version
        @param new_ver: new version
        @rtype: dict
        '''
        return Migration(old_ver, new_ver)

    def create_backup_directory(self, version):
        '''
        Creates a normalized, consistent backup directory
        that should work across different platforms (windows, linux, osx)
        @param version: The supplied backup version, usually 2_0_0 or 2_1_0
        @type version: String
        @return: a folder name to use as the string
        @retval: string
        '''
        #Replace any special characters with underscores
        #Modify the backup directory so that its a legal name for windows
        #Also remove some spaces and dots
        translation_table = maketrans(" :,.", "____")
        backup_dir_name = 'backup_' + version + "_" + itoa_common.get_current_timestamp_utc()
        return backup_dir_name.translate(translation_table)


    def _validate_and_post_message(self, old_ver, new_ver, is_show_message):
        '''
        Create migration object and validate if migration required
        @param old_ver: old version
        @param new_ver: new version
        @param is_show_message: set to true if message need to be shown in case of migration
        @return: a tuple if migration object and boolean flag if migration required
        '''
        logger.info("Migrating from version:%s, to version:%s", old_ver, new_ver)
        mi = self._create_migration_object(old_ver, new_ver)
        is_migration = mi._is_migration_required()
        if is_migration:
            logger.info("Migration required")
            if is_show_message:
                ITOAInterfaceUtils.create_message(self.session_key, self.INITIAL_WARNING_MSG)
        else:
            logger.info("Migration is not required from version:%s, to version:%s", old_ver, new_ver)
        return mi, is_migration

    def configure_itsi(self):
        """
        Import all ITSI setting.
        Combining the itsi_configurator and itsi_upgrade modular input into one.
        Since itsi_upgrade modular input runs on every restart, configure_itsi will run as well.
        @rtype: None
        @return: None
        """
        logger.info("Check and import data from conf to kv store")
        itsi_settings_importer = ItsiSettingsImporter(session_key=self.session_key)
        try:
            is_all_import_success = itsi_settings_importer.import_itsi_settings(owner='nobody')
            if not is_all_import_success:
                itoa_common.post_splunk_user_message(
                    _('Failures occurred while attempting to import some IT Service Intelligence settings from '
                    'configuration files for apps and modules. '
                    'Check the logs to get information about which settings failed to be imported.'),
                    session_key=self.session_key
                )
        except Exception as e:
            message = _("Importing IT Service Intelligence settings from conf files " \
                      "for apps and modules failed with: ") + str(e)
            logger.exception(message)
            itoa_common.post_splunk_user_message(message, session_key=self.session_key)

        logger.info("Successfully imported IT Service Intelligence settings from conf files for apps and modules.")

    def configure_team(self):
        """
        Import team setting from conf file.
        Team setting needs to be configured before import other settings.
        @rtype: boolean
        @return: status - if team configuration is successfully or fail
        """
        itsi_settings_importer = ItsiSettingsImporter(session_key=self.session_key)
        return itsi_settings_importer.import_team_setting(owner='nobody')

    def itsi_2_0_0_to_2_1_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True):
        '''
        Migration from 2.0.0 to 2.1.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
                It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
                status - if migration successful
                flag to create system msg
        '''
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        # Take backup
        logger.info("Adding backup restore handler")
        backup_dir_name = self.create_backup_directory('2.0.0')
        backup_restore = BackupRestore(self.session_key, backup_dir_name)
        mi.add(backup_restore)

        # Update home views
        logger.info("Adding handler to update home views")
        homeview_update_handler = UpdateServiceAnalyzer(self.session_key, self.owner, self.app)
        mi.add(homeview_update_handler)

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_1_0_to_2_2_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True):
        '''
        Migration from 2.1.0 to 2.2.0
        '''
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        # Take backup
        logger.info("Adding backup restore handler")
        backup_dir_name = self.create_backup_directory('2.1.0')
        backup_restore = BackupRestore(self.session_key, backup_dir_name)
        mi.add(backup_restore)

        # chown KPI Saved Searches to 'nobody' + update KPI attribute
        # `search_type`
        logger.info('Adding handler for KPI ownership change to nobody and updating KPI attribute "search_type"')
        service_migration_change = ServiceMigrationChangeHandler(self.session_key)
        mi.add(service_migration_change)

        # add ACL info for all shared objects
        logger.info('Adding handler to add a default ACL for shared objects.')
        add_acl = ACLHandler(self.session_key)
        mi.add(add_acl)

        # Entity schema change for service field needs update
        logger.info('Adding handler for entity migration to new schema')
        entity_migration_change = EntityMigrationChangeHandler(self.session_key)
        mi.add(entity_migration_change)

        # title validation
        logger.info('Adding handler for title validation')
        title_validation = TitleValidationHandler(self.session_key)
        mi.add(title_validation)

        # new KPI threshold template schema transformation
        logger.info('Adding handler for new KPI threshold template schema transformation')
        kpi_threshold_template_schema_transformation = KPIThresholdTemplateMigrationChangeHandler(self.session_key)
        mi.add(kpi_threshold_template_schema_transformation)

        # KPI template schema transformation
        logger.info('Adding handler for new KPI template schema transformation')
        kpi_template_schema = KPITemplateMigrationChangeHandler(self.session_key)
        mi.add(kpi_template_schema)

        # Delete LB old KPI template
        logger.info('Adding handler to delete old LB KPI template schema')
        old_lb_kpi_template_schema = DeleteOldLBKPITemplateMigration(self.session_key)
        mi.add(old_lb_kpi_template_schema)

        # Correlation Search Migration
        logger.info('Adding handler for correlation search migration')
        cs_migration = CorrelationSearchMigration(self.session_key)
        mi.add(cs_migration)

        # Delete Correlation Search Conf Entry
        logger.info('Adding handler to delete correlation search entry')
        messages = []

        cs_message = _('Please delete correlationsearches.conf file from $SPLUNK_HOME/etc/apps/itsi/default and' \
                 ' $SPLUNK_HOME/etc/apps/itsi/local. Note: If you want to migrate old Notable Events to the new' \
                 ' index: First follow the steps as specified in the documentation, then' \
                 ' delete the correlationsearches.conf files as described above.')
        messages.append(cs_message)

        sa_threat_msg = _('IT Service Intelligence version 2.2.0+ does not require the SA-ThreatIntelligence.' \
                ' With the following 2 exceptions, you can safely remove SA-ThreatIntelligence from' \
                ' $SPLUNK_HOME/etc/apps. Exception 1. The Splunk Enterprise Security app requires' \
                ' SA-ThreatIntelligence. If you are running Splunk Enterprise Security, do not remove' \
                ' SA-ThreatIntelligence. Exception 2. If you want to migrate old Notable Events to the new' \
                ' index: First, follow the steps as specified in the documentation. Once the migration is' \
                ' complete, you can safely remove SA-ThreatIntelligence from $SPLUNK_HOME/etc/apps.')
        messages.append(sa_threat_msg)

        sa_ticketing_msg = _('IT Service Intelligence version 2.2.0+ does not require the SA-Ticketing.' \
               ' You can safely remove SA-Ticketing from $SPLUNK_HOME/etc/apps.')
        messages.append(sa_ticketing_msg)

        cs_delete_conf = ShowDeprecatedFilesMessages(self.session_key, messages)
        mi.add(cs_delete_conf)

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_2_0_to_2_3_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True):
        '''
        Migration from 2.2.0 to 2.3.0
        '''
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        # Take backup
        logger.info("Adding backup restore handler")
        backup_dir_name = self.create_backup_directory('2.2.0')
        backup_restore = BackupRestore(self.session_key, backup_dir_name)
        mi.add(backup_restore)

        # Remove old AD correlation search entries
        logger.info("Adding handle to delete old AD correlation searches")
        ad_search_delete = DeleteOldAdSearch(self.session_key)
        mi.add(ad_search_delete)

        # do service level migrations
        logger.info('Adding handler for any service level migrations from 2.2.0')
        service_migration_change = ServiceMigrationChangeHandler_from_2_2_0(self.session_key)
        mi.add(service_migration_change)

        # Migrate KPIs that will be broken due to a structural datamodel change
        logger.info("Adding handler to migrate KPI datamodel settings for breaking changes")
        update_kpi_datamodel_settings = UpdateChangedDatamodelKPIs_2_2_0_to_2_3_0(self.session_key, logger)
        mi.add(update_kpi_datamodel_settings)

        # Migrate KPIs that came from modules to base-search-based ones
        logger.info("Adding handler to migrate module-created KPIs to base-search-based ones")
        migrate_module_kpis = MigrateModuleKPIsToSharedBaseSearch(self.session_key, logger)
        mi.add(migrate_module_kpis)

        # Add new entity rules to services that use old role field
        logger.info("Adding handler to update services with module roles entity rules with new field name")
        update_service_role_entity_rule = AddItsiRoleEntityRuleToServices(self.session_key, logger)
        mi.add(update_service_role_entity_rule)

        # Add new fields to each shared, deep dive (named and unnamed)
        logger.info("Adding handler to update `excludeFields` in deep dive lane settings.")
        deep_dive_migrator = DeepDiveMigrator(self.session_key)
        mi.add(deep_dive_migrator)

        # tell user about not needing sa-utils
        logger.info('Adding handler to post a message to Splunk web.')
        messages = []
        sa_utils_msg = _('IT Service Intelligence version 2.3.0+ does not require SA-Utils.'
            ' With the following exception, you can safely remove SA-Utils from'
            ' $SPLUNK_HOME/etc/apps : The Splunk Enterprise Security App,'
            ' Splunk App for VMware and Splunk App for Netapp Data Ontap'
            ' require SA-Utils. If you are using either of these Apps,'
            ' do not remove SA-Utils.'
            )
        messages.append(sa_utils_msg)
        show_msg = ShowDeprecatedFilesMessages(self.session_key, messages)
        mi.add(show_msg)

        # Upgrade to new app-common Glasstable
        logger.info('Adding action to upgrade Glasstable')
        common_gt_migration = MigrateToCommonGlassTable(self.session_key)
        mi.add(common_gt_migration)

        # Update AT searches to not include maintenance level data
        logger.info('Adding handler to update AT searches to exclude data generated during the maintenance window.')
        at_search_update = UpdateATSearch(self.session_key)
        mi.add(at_search_update)

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_3_0_to_2_4_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        '''
        Migration from 2.3.0 to 2.4.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
                It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
                status - if migration successful
                flag to create system msg
        '''

        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        # Take backup
        logger.info("Adding backup restore handler")
        backup_dir_name = self.create_backup_directory('2.3.0')
        backup_restore = BackupRestore(self.session_key, backup_dir_name, restore=restore)
        mi.add(backup_restore)

        # Migrate existing backup/restore jobs
        logger.info("Adding handler to perform needed backup/restore jobs migration")
        backup_restore_jobs = BackupRestoreJobsMigrationChangeHandler_from_2_3_0(self.session_key)
        mi.add(backup_restore_jobs)

        # Add new fields to each shared, deep dive (named and unnamed)
        logger.info("Adding handler to update threshold settings in deep dive lane settings.")
        deep_dive_migrator = DeepDiveMigrator(self.session_key, 'nobody')
        mi.add(deep_dive_migrator)

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_4_0_to_2_5_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        """
        Migration from 2.4.0 to 2.5.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
            It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
            status - if migration successful
            flag to create system msg
        """
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        logger.info("migration from 2.4.0 to 2.5.0")

        # Take backup
        logger.info("Adding backup restore handler")
        backup_dir_name = self.create_backup_directory('2.4.0')
        backup_restore = BackupRestore(self.session_key, backup_dir_name, restore=restore)
        mi.add(backup_restore)

        # Migrate maintenance windows
        logger.info("Adding maintenance windows migration handler")
        maintenance_window_migrator = migration_handlers_2_5_0.MaintenanceWindowMigrator(self.session_key, 'nobody')
        mi.add(maintenance_window_migrator)

        # Migrate maintenance windows
        logger.info("Adding backup/restore jobs migration handler")
        backup_restore_jobs_migrator = migration_handlers_2_5_0.BackupRestoreJobsMigrator(self.session_key, 'nobody')
        mi.add(backup_restore_jobs_migrator)

        # Optimize service schema for existing services
        logger.info('Adding handler for migration service schema.')
        mi.add(migration_handlers_2_5_0.ServiceSchemaMigrator(self.session_key, 'nobody'))

        # Migrate identifying names
        logger.info("Migrating identifying names for all objects")
        identifying_name_migrator = migration_handlers_2_5_0.IdentifyingNamesLowerCaseMigrator(self.session_key)
        mi.add(identifying_name_migrator)

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_5_0_to_2_6_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        """
        Migration from 2.5.0 to 2.6.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
            It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
            status - if migration successful
            flag to create system msg
        """
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False

        logger.info('migration from 2.5.0 to 2.6.0')

        # Move old time blocks to new time block schema
        logger.info('Adding handler for migration service schema (cron).')
        mi.add(migration_handlers_2_6_0.ServiceSchemaCronMigrator(self.session_key))

        # Delete itsi_group_alerts_sync_token token
        mi.add(migration_handlers_2_6_0.HecTokenHandler(self.session_key, "itsi_group_alerts_sync_token",
                                                        index='itsi_grouped_alerts', host=None,
                                                        source='itsi_group_alerts', sourcetype='stash', app='itsi',
                                                        is_use_ack=True))

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_2_6_0_to_3_0_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        """
        Migration from 2.6.0 to 3.0.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
            It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
            status - if migration successful
            flag to create system msg
        """
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False


        logger.info('migration from 2.6.0 to 3.0.0')

        # Move old objects to default security group
        # !!!!! THIS MUST RUN BEFORE ANYTHING ELSE !!!!!
        logger.info('Adding default security group migrator handler.')
        mi.add(migration_handlers_3_0_0.DefaultSecurityGroupMigrator(self.session_key))

        # Update old policies that modified Status, Severity, Owner to execute_on GROUP only
        logger.info('Adding handler for migration aggregation policy')
        mi.add(migration_handlers_3_0_0.AggregationPolicyMigrator(self.session_key))

        logger.info('Adding handler to add a default ACL for shared objects.')
        mi.add(migration_handlers_3_0_0.ACLHandler(self.session_key))

        logger.info('Adding handler to convert entity alias from upper case to lower case.')
        mi.add(migration_handlers_3_0_0.EntityUpperToLowerMigrator(self.session_key))

        logger.info('Adding handler to add a mod_time to external tickets.')
        mi.add(migration_handlers_3_0_0.ExternalTicketTimeHandler(self.session_key))

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_3_0_0_to_3_1_0_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        """
        Migration from 3.0.0 to 3.1.0

        @type old_ver: basestring
        @param old_ver: old version

        @type new_ver: basestring
        @param new_ver: new version

        @type id: basestring
        @param id: kv schema key which old version information

        @type is_initiate_upgrade: bool
        @param is_initiate_upgrade: set to false if this is not first upgrade which was initiated
            It is being used to show message only once in case of cascading upgrade from more than one version old

        @rtype: tuple
        @return: tuple
            status - if migration successful
            flag to create system msg
        """
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False


        logger.info('migration from 3.0.0 to 3.1.0')

        # Update old policies that modified Status, Severity, Owner to execute_on GROUP only
        logger.info('Adding handler for glass table objects')
        mi.add(migration_handlers_3_1_0.GlassTableMigrator(self.session_key))

        # Regenerate all shared base search
        logger.info('Adding handler to generate/update shared base search')
        mi.add(migration_handlers_3_1_0.UpdateSearchAndService(self.session_key))

        # run
        mi.run()
        return mi.is_execution_successful, True

    def itsi_3_1_0_to_3_1_1_migration(self, old_ver, new_ver, id, is_initiate_upgrade=True, restore=False):
        mi, is_migration = self._validate_and_post_message(old_ver, new_ver, is_initiate_upgrade)
        if not is_migration:
            return False, False
        logger.info('migration from 3.1.0 to 3.1.1')

        # validate the entities first
        logger.info('Validating entities first')
        if not migration_handlers_3_1_1.entity_valid(self.session_key):
            error_msg = 'Migration stopped due to inconsistent entities in the environmnet, please check migration.log for details.'
            ITOAInterfaceUtils.create_message(self.session_key,
                                              error_msg,
                                              severity='error')
            raise Exception('entity validation error')

        # Update the service template
        logger.info('Adding handler for service template migration')
        mi.add(migration_handlers_3_1_1.ServiceTemplateMigrationHandler(self.session_key))

        # Update service collection
        logger.info('Adding handler for service migration')
        mi.add(migration_handlers_3_1_1.ServiceMigrationHandler(self.session_key))

        # Update the MAD context kvstore collection
        logger.info('Adding handler for MAD context collection')
        mi.add(migration_handlers_3_1_1.MadUriMigrator(self.session_key))

        # Update entities which are in inconsistent state. In case of restore, save batch all the entities.
        logger.info('Adding Handler for Entities migration.')
        mi.add(migration_handlers_3_1_1.EntityMigrationHandler(self.session_key, restore))

        # run
        mi.run()
        return mi.is_execution_successful, True


    def run_migration(self):
        '''
        Perform migration. Only supports upgrades/migration from last two versions
        :return: nothing
        '''

        new_version = ITOAInterfaceUtils.get_app_version(self.session_key, self.app, self.owner, fetch_conf_only=True)
        migration_status = True
        restore = False
        is_create_msg = False
        multi_step_upgrade = True

        if self.backup_version:
            old_version = self.backup_version
            id_ = None
            restore = True
        else:
            old_version, id_ = ITOAInterfaceUtils.get_version_from_kv(self.session_key)

        mi_method = MigrationBaseMethod(self.session_key)

        # Make sure old version is valid
        if old_version:
            try:
                VersionCheck.validate_version(old_version)
            except Exception:
                logger.exception('Invalid old version=%s, hence we will skip migration now', old_version)
                old_version = None

        msg = ''


        try:
            # Do not lock the UI for restoring, lock it only for migration
            if not restore:
                logger.info("Disable UI for migration...")
                disable_app_ui = HandleAppVisibility(self.session_key, self.app, self.owner, True)
                disable_app_ui.execute()

                # import team setting before migration
                # non-restore == restart w or w/o migration
                logger.info('import team setting')
                retry = 0
                status = False
                while retry < 3:
                    status = self.configure_team()
                    if status:
                        break
                    retry += 1

                team_import_doc_url = 'http://docs.splunk.com/Documentation/ITSI/3.0.1/Configure/' \
                                      'Installationandconfigurationconsiderationsandissues' \
                                      '#Run_script_to_set_the_default_team_to_Global'

                error_msg = _('Failed to import Team settings. ITSI will not work properly until the Team settings are imported. ' \
                            'See [{} this documentation page] for instructions on how to resolve this issue.').format(team_import_doc_url)

                if not status:
                    ITOAInterfaceUtils.create_message(self.session_key,
                                                      error_msg,
                                                      severity='error')
                    raise Exception(error_msg)

                logger.info('team setting input status: %s', status)

            # There are couple of patch versions, so we are comparing 2.0.x
            if old_version and VersionCheck.compare(old_version, "2.1") < 0 and VersionCheck.compare(old_version, "1.2") > 0:
                ret, is_create_msg = self.itsi_2_0_0_to_2_1_0_migration(old_version, new_version, id_)
                if ret:
                    old_version = "2.1"  # could be a patch/minor version. hence 2.1
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, "2.2") < 0 and VersionCheck.compare(old_version, "2.1") >= 0:
                ret, is_create_msg = self.itsi_2_1_0_to_2_2_0_migration(old_version, new_version, id_, not multi_step_upgrade)
                if ret:
                    old_version = "2.2"  # could be a patch/minor version. hence 2.2
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, "2.3") < 0 and VersionCheck.compare(old_version, "2.2") >= 0:
                ret, is_create_msg = self.itsi_2_2_0_to_2_3_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade)
                if ret:
                    old_version = "2.3"  # could be a patch/minor version. hence 2.3
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, "2.4") < 0 and VersionCheck.compare(old_version, "2.3") >= 0:
                # set this flag to true only at the last version migration
                ret, is_create_msg = self.itsi_2_3_0_to_2_4_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = "2.4"  # could be a patch/minor version. hence 2.4
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, "2.5") < 0 and VersionCheck.compare(old_version, "2.4") >= 0:
                ret, is_create_msg = self.itsi_2_4_0_to_2_5_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = "2.5"
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, '2.6') < 0 and VersionCheck.compare(old_version, '2.5') >= 0:
                ret, is_create_msg = self.itsi_2_5_0_to_2_6_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = '2.6'
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, '3.0') < 0 and VersionCheck.compare(old_version, '2.6') >= 0:
                ret, is_create_msg = self.itsi_2_6_0_to_3_0_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = '3.0'
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, '3.1') < 0 and VersionCheck.compare(old_version, '3.0') >= 0:
                ret, is_create_msg = self.itsi_3_0_0_to_3_1_0_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = '3.1'
                else:
                    new_version = old_version

            if old_version and VersionCheck.compare(old_version, '3.1.1') < 0 and VersionCheck.compare(old_version, '3.1.0') >= 0:
                # always mark the last version
                multi_step_upgrade = False
                ret, is_create_msg = self.itsi_3_1_0_to_3_1_1_migration(old_version,
                                                                        new_version,
                                                                        id_,
                                                                        not multi_step_upgrade,
                                                                        restore=restore)
                if ret:
                    old_version = '3.1.1'
                else:
                    new_version = old_version

            else:
                logger.info("IT Service Intelligence is up to date, no further migrations required")
                logger.info("Enable UI")
                enable_app_ui = HandleAppVisibility(self.session_key, self.app, self.owner, False)
                enable_app_ui.execute()

                # In fresh installation or future installation lets store version to KV Store
                if new_version is not None:
                    if not old_version:
                        # old_version is None, treat as the same version as the new version
                        old_version = new_version
                    is_update = ITOAInterfaceUtils.update_version_to_kv(self.session_key, id_,
                                                                        new_version, old_version, True)
                    if is_update and VersionCheck.compare(new_version, old_version) > 0 and not is_create_msg:
                        ITOAInterfaceUtils.create_message(self.session_key,
                                                          self.UPDATE_SUCESSFUL_MSG.format(old_version, new_version))
                if restore:
                    # In a restore workflow, bulk save is needed
                    ret = True

                else:
                    # Same version spl re-install, no migration is needed!
                    # Now load the conf into kvstore now
                    logger.info('Migration is not needed, import conf settings now.')
                    self.configure_itsi()
                    return

            if ret:
                save_status = mi_method.migration_bulk_save_to_kvstore(dupname_tag=self.dupname_tag)
                if save_status:
                    logger.info("Migration bulk save to kvstore successfully, update the version to %s!" % old_version)
                    # Update Version information to kv
                    logger.info("Adding version information...")
                    is_update = ITOAInterfaceUtils.update_version_to_kv(self.session_key, id_, new_version, old_version, True)
                    msg = self.FINAL_SUCCESSFUL_MSG
                    if not is_update:
                        logger.error("Failed to update version information to kv store")
                else:
                    msg = self.FINAL_FAILED_MSG
                    migration_status = False

                try:
                    # re-enable the UserAccess modular input to activate all the capabilities
                    uri = "/servicesNS/nobody/SA-ITOA/data/inputs/itsi_user_access_init/upgrade_capabilities/disable"
                    response, content = splunk.rest.simpleRequest(uri, method="POST",
                                                                  sessionKey=self.session_key,
                                                                  raiseAllErrors=False)
                    time.sleep(1)
                    uri = "/servicesNS/nobody/SA-ITOA/data/inputs/itsi_user_access_init/upgrade_capabilities/enable"
                    response, content = splunk.rest.simpleRequest(uri, method="POST",
                                                                  sessionKey=self.session_key,
                                                                  raiseAllErrors=False)
                except Exception:
                    logger.debug('Unable to reset UserAccess mod input, but still continue the restore')
            else:
                msg = self.FINAL_FAILED_MSG
                migration_status = False
        except Exception:
            logger.exception("Migration failed from version:%s, to version:%s", old_version, new_version)
            msg = self.FINAL_FAILED_MSG
            migration_status = False

        logger.info("Enable UI")
        enable_app_ui = HandleAppVisibility(self.session_key, self.app, self.owner, False)
        enable_app_ui.execute()

        if is_create_msg:
            logger.info("Creating system message")
            ITOAInterfaceUtils.create_message(self.session_key, msg)
        try:
            mi_method.cleanup_local_storage()
        except Exception:
            logger.exception("Local storage may have already been cleaned!")

        logger.info('Migration is completed, import conf setting!')
        self.configure_itsi()

        return migration_status
