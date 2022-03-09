# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time

from splunk.util import localTZ
from splunk.appserver.mrsparkle.lib import i18n

from ITOA.itoa_common import normalize_num_field, get_current_utc_epoch
from migration.migration import MigrationFunctionAbstract
from ITOA.setup_logging import setup_logging
from itsi.itsi_utils import ITOAInterfaceUtils
from ITOA.itoa_common import is_valid_str
from ITOA.itoa_factory import instantiate_object
from itsi.objects.itsi_security_group import ItsiSecGrp

from ITOA.event_management.event_management_object_manifest import object_manifest
from ITOA.event_management.notable_event_utils import get_collection_name_for_event_management_objects
from ITOA import itoa_common
from ITOA.storage import itoa_storage
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from user_access_utils import UserAccess

logger = setup_logging("itsi_migration.log", "itsi.migration")

class AggregationPolicyMigrator(MigrationFunctionAbstract):
    """
    Migration handler to update the execute_on criteria for action rules of old aggregation policies created on previous
    versions of ITSI (specifically action rules that modified the Status/Severity/Owner of events). Migrated aggregation
    policies will have have an execute_on criteria of 'GROUP' for the action rules.
    """

    def __init__(self, session_key):
        super(AggregationPolicyMigrator, self).__init__(session_key)
        self.session_key = session_key

    @staticmethod
    def update_policy_to_group_level_mutability(policy):
        """
        Utility method to update execute_on of execution criteria for action rules during migration
        For aggregation policies created 2.6.X or before, change execute_on
        from ALL, THIS, or FILTER to GROUP
        @type policy: dict
        @param policy: policy that contains the Action Rules that will be updated
        @return: None
        """
        for rule in policy.get('rules', []):
            if not isinstance(rule.get('actions'), list):
                logger.warn('Action rules for aggregation policy look invalid, skipping policy adjustment')
                continue
            # iterate through the execution criteria of a given action rule
            for action in rule.get('actions', {}):
                for item in action.get('items', {}):
                    # Update execute_on for select execution_criteria
                    if item['type'] == 'notable_event_change' and \
                                    item.get('execution_criteria', {}).get('execute_on') != 'GROUP':
                        if item.get('execution_criteria', {}).get('execute_on') == 'FILTER':
                            # delete the configuration details for the filter execute_on criteria
                            if isinstance(item.get('execution_criteria', {}).get('config'), dict):
                                del item['execution_criteria']['config']
                        item['execution_criteria']['execute_on'] = 'GROUP'
    @staticmethod
    def add_owner(policy):
        # add _owner field
        if policy.get('title') != 'Default Policy':
            policy['_owner'] = policy.get('owner', 'nobody')

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all aggregation policies that already exist.
        """
        status = None
        try:
            # get all aggregation policies
            policy_itr = self.get_object_iterator('notable_aggregation_policy')
            all_policies = []

            for policy in policy_itr:
                # Go through aggregation policies and update
                AggregationPolicyMigrator.update_policy_to_group_level_mutability(policy)
                AggregationPolicyMigrator.add_owner(policy)
                all_policies.append(policy)

            status = self.save_object('notable_aggregation_policy', all_policies)
        except Exception, e:
            logger.exception('Failed to migrate aggregation policies')
            message = _('Failed to update Aggregation Policies to include GROUP execute_on criteria')
            ITOAInterfaceUtils.create_message(self.session_key, message)
            status = False
        logger.info('No exceptions when saving. Save status=%s', status)
        return status

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._fetch_and_migrate()

class DefaultSecurityGroupMigrator(MigrationFunctionAbstract):
    """
    Migration handler for moving all existing objects from previous versions to "Default" security group
    Note that there existed no security groups in previous versions
    """
    def __init__(self, session_key):
        """
        @type session_key: basestring
        @param session_key: session key
        """
        super(DefaultSecurityGroupMigrator, self).__init__(session_key)

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all existing objects to be assigned to te "Default" security group.
        """
        object_types = [
            'entity',
            'kpi_base_search',
            'service',
            'kpi_threshold_template',
            'kpi_template'
        ]
        for object_type in object_types:
            object_iterator = self.get_object_iterator(object_type, get_raw=True)
            modified_object_collection = []
            for knowledge_object in object_iterator:
                knowledge_object['sec_grp'] = ItsiSecGrp.get_default_itsi_security_group_key()
                modified_object_collection.append(knowledge_object)
            self.save_object(object_type, modified_object_collection)

        # Special case for maintenance_calendar
        object_iterator = self.get_object_iterator('maintenance_calendar')
        modified_object_collection = []
        for maintenance_calendar_object in object_iterator:
            maintenance_calendar_object['sec_grp_list'] = [ItsiSecGrp.get_default_itsi_security_group_key()]
            modified_object_collection.append(maintenance_calendar_object)
        self.save_object('maintenance_calendar', modified_object_collection)
        return True

    def execute(self):
        return self._fetch_and_migrate()


class EntityUpperToLowerMigrator(MigrationFunctionAbstract):
    """
    Migration handler to convert all the entity alias value from upper case to lower case.
    """
    def __init__(self, session_key):
        """
        @type session_key: basestring
        @param session_key: session key
        """
        super(EntityUpperToLowerMigrator, self).__init__(session_key)

    def _fetch_and_migrate(self):
        """
        Fetch all entity objects and perform the case migration
        """
        object_iterator = self.get_object_iterator('entity')
        modified_object_collection = []
        for entity_object in object_iterator:
            identifier = entity_object.get('identifier', {})
            identifier['values'] = [s.lower() for s in identifier.get('values', [])]
            entity_object['identifier'] = identifier
            modified_object_collection.append(entity_object)
        self.save_object('entity', modified_object_collection)
        return True

    def execute(self):
        return self._fetch_and_migrate()


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
        self.object_types = ['notable_aggregation_policy',
                             'correlation_search']
        self.default_acl = default_acl
        super(ACLHandler, self).__init__(session_key)

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

            if object_type == 'notable_aggregation_policy':
                self.collection = get_collection_name_for_event_management_objects('notable_event_aggregation_policy')
            else:
                self.collection = get_collection_name_for_event_management_objects(object_type)

            # get object from cache
            object_iterator = self.get_object_iterator(object_type)
            objects = []

            if object_type == 'correlation_search':
                key = 'name'
            else:
                key = '_key'

            for object in object_iterator:
                objects.append(object)

            if not objects:
                # no objects found...move onto next object type
                continue
            objects_exist = True
            ids_ = itoa_common.extract(objects, key)
            try:
                success, rval = UserAccess.bulk_update_perms(ids_,
                                                             self.default_acl,
                                                             object_app,
                                                             object_type,
                                                             self.collection,
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

class ExternalTicketTimeHandler(MigrationFunctionAbstract):
    """
    Migration handler for adding mod_times to all existing tickets. mod_times will be the time of migration
    """
    def __init__(self, session_key):
        """
        @type session_key: basestring
        @param session_key: session key
        """
        super(ExternalTicketTimeHandler, self).__init__(session_key)

    def _fetch_and_migrate(self):
        """
        Fetch tickets and add a mod_time field to each object
        """
        try:
            status = True
            object_iterator = self.get_object_iterator('external_ticket')
            modified_object_collection = []
            for knowledge_object in object_iterator:
                knowledge_object['mod_time'] = time.time()
                knowledge_object['create_time'] = time.time()
                modified_object_collection.append(knowledge_object)
            self.save_object('external_ticket', modified_object_collection)

        except Exception, e:
            logger.exception('Failed to external_tickets')
            message = _('Failed to update external tickets to have mod_time added')
            ITOAInterfaceUtils.create_message(self.session_key, message)
            status = False
        logger.info('No exceptions when saving. Save status=%s', status)
        return status

    def execute(self):
        return self._fetch_and_migrate()
