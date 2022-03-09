# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json

from splunk.appserver.mrsparkle.lib import i18n
import splunk.rest as rest

import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from ITOA.storage import itoa_storage
from ITOA.itoa_factory import instantiate_object
from ITOA.itoa_exceptions import ItoaAccessDeniedError
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG, SECURABLE_OBJECT_SERVICE_CONTENT_KEY

logger = utils.get_itoa_logger('itsi.object.sec_grp')

class ItsiSecGrp(ItoaObject):
    """
    Implements ITSI Security Group configuration
    """
    collection_name = 'itsi_team'

    def __init__(self, session_key, current_user_name):
        super(ItsiSecGrp, self).__init__(
            session_key, current_user_name, 'team', collection_name=self.collection_name,
            title_validation_required=True, is_securable_object=True)

        self._all_roles_for_current_user = None
        self._sec_grp_acls_map = None

    def delete(self, owner, object_id, req_source='unknown', transaction_id=None):
        """
        Delete object by id
        @type owner: string
        @param owner: user who is performing this operation
        @type object_id: string
        @param object_id: id of object to delete
        @type req_source: string
        @param req_source: identified source initiating the operation
        @rtype: string
        @return: id of object deleted on success, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itsi_security_group.delete", transaction_id=transaction_id, owner=owner)
        if not utils.is_valid_str(object_id):
            self.raise_error_bad_validation(logger, 'ItsiSecGrp cannot delete object with invalid object id')

        if self.is_securable_object:
            stored_object = self.get(owner, object_id, req_source=req_source, transaction_id=transaction_id)
            if isinstance(stored_object, dict):
                results = self._get_security_enforcer().enforce_security_on_delete(owner, self, [stored_object],
                                                                                   transaction_id=transaction_id)
                if (not isinstance(results, list)) or (1 != len(results)):
                    raise ItoaAccessDeniedError(
                        _('Access denied. You do not have permission to delete this object.'),
                        logger
                    )

                # Default global security group cannot be deleted
                if results[0].get('_key') == self.get_default_itsi_security_group_key():
                    self.raise_error(
                        logger,
                        _('Global team cannot be deleted.')
                    )

                del results
                del stored_object

        self.instrument.push("itsi_security_group.idenfity_dependencies", transaction_id=transaction_id, owner=owner)
        is_refresh_required, refresh_jobs = self.identify_dependencies(
            owner, [{"_key": object_id, 'object_type': self.object_type}],
            CRUDMethodTypes.METHOD_DELETE,
            req_source="delete",
            transaction_id=transaction_id
        )
        self.instrument.pop("itsi_security_group.idenfity_dependencies", transaction_id)

        results = self.storage_interface.delete(
            self.session_key,
            owner,
            self.object_type,
            object_id,
            current_user_name=self.current_user_name
        )
        logger.debug('Object of type %s with id: %s deleted, request source: %s',
                     self.object_type,
                     object_id,
                     req_source
                     )
        if is_refresh_required:
            self.create_refresh_jobs(refresh_jobs)

        self.instrument.pop("itsi_security_group.delete", transaction_id)
        return results

    def delete_bulk(
            self,
            owner,
            filter_data=None,
            req_source='unknown',
            transaction_id=None
    ):
        """
        Deletes objects matching criteria, if no filtering specified, deletes all objects of this object type
        @type owner: string
        @param owner: user who is performing this operation
        @type filter_data: dictionary
        @param filter_data: json filter constructed to filter data. Follows mongodb syntax
        @type req_source: string
        @param req_source: identified source initiating the operation
        @return: none, throws exceptions on errors
        """

        # Get ids for object which is getting deleted
        transaction_id = self.instrument.push("itsi_security_group.delete_bulk", transaction_id=transaction_id, owner=owner)

        delete_objects = self.storage_interface.get_all(self.session_key,
                                                        owner,
                                                        self.object_type,
                                                        filter_data=filter_data,
                                                        current_user_name=self.current_user_name,
                                                        fields=['_key', 'acl', 'sec_grp', 'title'])
        if self.is_securable_object:
            # Enforce security on the identified objects to get current user's permissions for delete
            # The enforced security should be honored to filter to objects that are deletable by current user
            # since this is bulk delete hence dont fail call but just delete what user has access to
            if isinstance(delete_objects, list):
                delete_objects = self._get_security_enforcer().enforce_security_on_delete(
                    owner, self, delete_objects, transaction_id=transaction_id)

        delete_data = [
            {'_key': object_id.get('_key'), 'title': object_id.get('title'), 'object_type': self.object_type} for object_id in delete_objects
            if object_id.get('_key ') != self.get_default_itsi_security_group_key()
            ] if isinstance(delete_objects, list) else []
        del delete_objects

        if len(delete_data) > 0:

            self.instrument.push("itsi_security_group.identify_dependencies", transaction_id=transaction_id, owner=owner)
            is_refresh_required, refresh_jobs = self.identify_dependencies(
                owner,
                delete_data,
                CRUDMethodTypes.METHOD_DELETE,
                req_source="delete"
            )
            self.instrument.pop("itsi_security_group.identify_dependencies", transaction_id)

            # Construct filter to only delete objects that user has access for deleting
            deletable_objects_filter = self.get_filter_data_for_keys([object.get('_key') for object in delete_data])

            is_delete_needed = True
            if self.object_type == self._get_security_enforcer().object_type:
                if not (len(delete_data) == 1 and
                                delete_data[0].get(
                                    '_key') == self.get_default_itsi_security_group_key()):
                    deletable_objects_filter = self.get_filter_data_for_keys(
                        [object.get('_key') for object in delete_data
                         if object.get('_key') != self.get_default_itsi_security_group_key()])
                else:
                    # There is nothing to delete, return
                    is_delete_needed = False

                    logger.debug(
                        'No objects of type %s deleted, request source: %s',
                        self.object_type,
                        req_source
                    )

            if is_delete_needed:
                self.storage_interface.delete_all(
                    self.session_key,
                    owner,
                    self.object_type,
                    filter_data=deletable_objects_filter,
                    current_user_name=self.current_user_name
                )

                logger.debug(
                    'Objects of type %s deleted, request source: %s',
                    self.object_type,
                    req_source
                )
            if is_refresh_required:
                self.create_refresh_jobs(refresh_jobs)
        # else all objects got filtered out, dont delete any

        self.instrument.pop("itsi_security_group.delete_bulk", transaction_id)

    def update(self, owner, object_id, data, is_partial_data=False, dupname_tag=None, transaction_id=None):
        """
        Update object passed in
        @type owner: string
        @param owner: user who is performing this operation
        @type object_id: string
        @param object_id: id of object to update
        @type data: string
        @param data: object to update
        @type is_partial_data: bool
        @param is_partial_data: indicates if payload passed into data is a subset of object structure
            when True, payload passed into data is a subset of object structure
            when False, payload passed into data is the entire object structure
            Note that KV store API does not support partial updates
        @rtype: string
        @return: id of object updated on success, throws exceptions on errors
        """

        if not utils.is_valid_str(object_id):
            self.raise_error_bad_validation(logger, 'ItsiSecGrp cannot update object with invalid object id')

        json_data = self.extract_json_data(data)

        if not isinstance(json_data, dict):
            self.raise_error_bad_validation(logger, 'Invalid update payload found, must be a valid JSON dictionary')

        json_data['object_type'] = self.object_type

        if not utils.is_valid_str(json_data.get('_key')):
            json_data['_key'] = object_id

        # updates to default security group are allowed only for itoa_admin
        if json_data['_key'] == self.get_default_itsi_security_group_key() and \
                        "itoa_admin" not in self._get_all_roles_for_current_user():
            raise ItoaAccessDeniedError(
                _('Access denied. You do not have permission to update the Global team.'),
                logger)
        return super(ItsiSecGrp, self).update(owner, object_id, data, is_partial_data, dupname_tag, transaction_id)

    def do_additional_setup(self, owner, objects, req_source='unknown',
                            method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Any additional setup that is required to be done during create/update operations.
        Inheritance tree prevents repeated log N calls to KV store to identify access
        to a user when enforcing RBAC.

        Inheritance tree update works as follows for upserts:
            If B inherits from Global, C inherits from Global, the following info is saved on the nodeS:

            [
            {
                _key: itsi_default_security_group,
                inherits_from: None,
                parents: [],
                children: [{_key: B}, {_key: C}]
            },
            {
                _key: B,
                inherits_from: itsi_default_security_group,
                parents: [{_key: itsi_default_security_group}],
                children: []
            }
            {
                _key: C,
                inherits_from: itsi_default_security_group,
                parents: [{_key: itsi_default_security_group}],
                children: []
            }
            ]

        @type owner: basestring
        @param owner: request owner. 'nobody' or some username.

        @type objects: list
        @param objects: List of security group type objects

        @type req_source: basestring
        @param req_source: Source requesting this operation.

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.

        @rtype: None
        @return: Nothing
        """
        for json_data in objects:
            # Assume json_data is valid

            if method == CRUDMethodTypes.METHOD_CREATE or method == CRUDMethodTypes.METHOD_UPSERT:
                if json_data.get('_key') is None:
                    json_data['_key'] = ITOAInterfaceUtils.generate_backend_key()

                # non-default key would imply that this is a non-default security group, enforce inheritance from global
                if json_data.get('_key') != self.get_default_itsi_security_group_key():
                    json_data['inherit_from'] = self.get_default_itsi_security_group_key()

            sec_grp_key = json_data['_key']
            persisted_sec_grp = self.get('nobody', sec_grp_key, transaction_id=transaction_id)

            if json_data.get('acl') is not None and isinstance(json_data.get('acl'), dict):
                if (not isinstance(json_data['acl'].get('read'), list) or
                        not isinstance(json_data['acl'].get('write'), list) or
                        not isinstance(json_data['acl'].get('delete'), list)):
                    self.raise_error(
                        logger,
                        'Invalid ACLs in the team. Team cannot be created.'
                    )
                else:
                    if json_data.get('_key') != self.get_default_itsi_security_group_key() and 'itoa_admin' not in \
                            json_data['acl']['read']:
                        json_data['acl']['read'].append('itoa_admin')
                    if json_data.get('_key') == self.get_default_itsi_security_group_key() and '*' not in \
                            json_data['acl']['read']:
                        json_data['acl']['read'].append('*')
                    if 'itoa_admin' not in json_data['acl']['write']:
                        json_data['acl']['write'].append('itoa_admin')
                    if 'itoa_admin' not in json_data['acl']['delete']:
                        json_data['acl']['delete'].append('itoa_admin')
            else:
                self.raise_error(
                    logger,
                    'Cannot create team without valid ACL.'
                )

            # Cannot change title of default group
            if (
                str(sec_grp_key) == str(self.get_default_itsi_security_group_key()) and
                str(json_data.get('title')) != str(self.get_default_itsi_security_group_title())
            ):
                logger.warn('Cannot change title for default group, forcing %s', self.get_default_itsi_security_group_title())
                json_data['title'] = self.get_default_itsi_security_group_title()

            # Process all nodes that need updating in the tree for parent and child associations
            # When a node is being configured as inheriting from a parent, this node MUST store all new parents
            # and all its parents must update their children's list to include this node.
            json_data['children'] = persisted_sec_grp.get('children', []) if isinstance(persisted_sec_grp, dict) else []

            json_data['parents'] = []
            if isinstance(json_data.get('inherit_from'), basestring):
                parent_sec_grp_key = json_data['inherit_from']

                # Get both immediate parent and higher parents directly from backend storage since
                # only ACLs will be update and no access check is needed for updating inheritance info
                parent_sec_grps = self.storage_interface.get_all(
                    self.session_key,
                    'nobody',
                    objecttype=self.object_type,
                    filter_data={'$or': [{'_key': parent_sec_grp_key},
                                         {'children._key': parent_sec_grp_key}]},
                    current_user_name=self.current_user_name
                )

                parent_sec_grp = [sec_grp for sec_grp in parent_sec_grps if str(sec_grp['_key']) == str(parent_sec_grp_key)]
                if not (isinstance(parent_sec_grp, list) and len(parent_sec_grp) == 1):
                    self.raise_error(
                        logger,
                        'Global group does not seem to exist. Cannot create private groups')
                parent_sec_grp = parent_sec_grp[0]
                json_data['parents'] = parent_sec_grp.get('parents', []) + [{'_key': parent_sec_grp_key}]

                for parent_sec_grp in parent_sec_grps:
                    found = False
                    children_of_parent = parent_sec_grp.get('children', [])
                    for child_of_parent in children_of_parent:
                        if str(child_of_parent.get('_key')) == str(sec_grp_key):
                            found = True
                            break
                    if not found:
                        parent_sec_grp['children'] = children_of_parent + [{'_key': sec_grp_key}]

                # If this succeeds but the objects list fails to save, it should be okay since children being stale
                # should be okay - note inheritance cannot be changed
                self.batch_save_backend(owner, parent_sec_grps, transaction_id=transaction_id)

    def _update_inheritance_tree_for_delete(self, sec_grp_key, owner, transaction_id):
        """
        Internal method used when deleting a security group to update inheritance chain for
        inheritance tree update

        @type sec_grp_key: basestring
        @param sec_grp_key: key of security group being deleted

        @type owner: basestring
        @param owner: owner initiating call

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: None
        @return: None
        """
        # Validate no inherited members exist on this security group
        # Assume here that the inheritance info in the current config of the object is accurate
        # In future if needed, we may query the real inherit_from field in the child nodes

        persisted_sec_grp = self.get(owner, sec_grp_key, transaction_id=transaction_id)
        if isinstance(persisted_sec_grp.get('children'), list) and len(persisted_sec_grp.get('children')) > 0:
            # can only be global but check anyway
            if persisted_sec_grp.get('_key') != self.get_default_itsi_security_group_key():
                self.raise_error(
                    logger,
                    'Team "%s" cannot be deleted since it has objects ' \
                    'inheriting from it.' % persisted_sec_grp.get('title'))


        # Remove this group from inheritance trees, since only leaf nodes could be deleted,
        # update only children info
        # Query backend store directly since only inheritance hierarchy impacting ACLs are adjusted,
        # safe to bypass security checks
        parent_sec_grps = self.storage_interface.get_all(
            self.session_key,
            'nobody',
            objecttype=self.object_type,
            filter_data={'children._key': sec_grp_key},
            current_user_name=self.current_user_name
        )

        if not isinstance(parent_sec_grps, list):
            return

        for parent_sec_grp in parent_sec_grps:
            parent_sec_grp['children'].remove({'_key': sec_grp_key})

        # If this succeeds but the objects list fails to delete, it should be okay since children being stale
        # should be okay - note inheritance cannot be changed
        self.batch_save_backend(owner, parent_sec_grps, transaction_id=transaction_id)

    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        """
        Use the refresh jobs identifier method to prevent delete on security groups that are
        currently in use either via inheritance or via association with objects like services.

        @type: basestring
        @param owner: user who is performing this operation

        @type: list
        @param objects: list of objects being CUD-ed

        @type: basestring
        @param method: CUD method name

        @type: basestring
        @param req_source: request source

        @rtype: tuple
        @return:
            {boolean} set to true/false if dependency update is required
            {list} list - list of refresh job, each element has the following
                change_type: <identifier of the change used to pick change handler>,
                changed_object_key: <Array of changed objects' keys>,
                changed_object_type: <string of the type of object>
        """
        for json_data in objects:
            # Assume json_data is valid

            if method == CRUDMethodTypes.METHOD_DELETE:
                sec_grp_key = json_data.get('_key')

                if str(sec_grp_key) == str(self.get_default_itsi_security_group_key()):
                    logger.warn('Global team cannot be deleted, ignoring it ...')
                else:
                    # Validate no ITSI objects are associated with this security group
                    # Since we need to identify objects across object types, make a query directly to the collection
                    service_storage_interface = itoa_storage.ITOAStorage()
                    uri = '/servicesNS/' + owner + '/SA-ITOA/storage/collections/data/itsi_services'
                    get_args = {'query': json.dumps({'sec_grp': sec_grp_key}), 'limit': 1}
                    response, content = rest.simpleRequest(
                        uri, method='GET', sessionKey=self.session_key, raiseAllErrors=True, getargs=get_args)
                    associated_objects = json.loads(content) if isinstance(content, basestring) else None
                    if not (associated_objects is None or associated_objects == []):
                        raise ItoaAccessDeniedError(
                            _('Team with name: "%s" cannot be deleted because it contains services. Move or delete the services first.') % json_data.get('title'),
                            logger)

                self._update_inheritance_tree_for_delete(sec_grp_key, owner, transaction_id)
        return False, []

    def _get_all_roles_for_current_user(self):
        """
        Cache implementation to get all roles assigned to the current user. All roles here refers to
        name of roles that are assigned directly (user settings) and indirectly (via inheritance)

        @rtype: list of strings
        @return: list of all roles assigned to a user
        """
        if self._all_roles_for_current_user is None:
            roles_for_current_user, all_roles_for_current_user = utils.SplunkUser.get_roles_for_user(
                self.current_user_name, self.session_key, logger)
            self._all_roles_for_current_user = all_roles_for_current_user
        return self._all_roles_for_current_user

    @staticmethod
    def get_default_itsi_security_group_key():
        """
        Accessor method to return default group's key externally

        @rtype: basestring
        @return: name of default group
        """
        return GLOBAL_SECURITY_GROUP_CONFIG.get('key')

    @staticmethod
    def get_default_itsi_security_group_title():
        """
        Accessor method to return default group's title externally

        @rtype: basestring
        @return: title of default group
        """
        return GLOBAL_SECURITY_GROUP_CONFIG.get('title')

    @staticmethod
    def get_securable_object_required_fields():
        """
        Accessor method to get list of fields required for security enforcement to work. This is a pre-requisite
        when filtering to fields in get calls like get_bulk when they invoke enforce_security_on_get
        Returns:

        """
        return ['acl', 'inherit_from', 'parents', 'children', 'sec_grp']

    def enforce_security_on_get(self, owner, object_type_instance, results, transaction_id=None, upsert=False):
        """
        Method that evaluates permissions on an object and sets permission info in payload.

        @type: basestring
        @param owner: user who is performing this operation

        @type object_type_instance: object
        @param object_type_instance: the ItoaInstance for the object type being security checked

        @type results: JSON list
        @param results: results payload to enforce security and set permissions on

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON list
        @return: payload of results updated with permissions info
        """
        if not (hasattr(object_type_instance, 'is_securable_object') and object_type_instance.is_securable_object):
            # Do not enforce security
            return results

        if object_type_instance.object_type == self.object_type:
            return self.enforce_security_self(results)
        else:
            return self.enforce_security_foreign(owner, results, transaction_id=transaction_id, upsert=upsert)

    def enforce_security_on_delete(self, owner, object_type_instance, results, transaction_id=None):
        """
        Method that evaluates permissions on an object and filters payload to only those that can be deleted.

        @type: basestring
        @param owner: user who is performing this operation

        @type object_type_instance: object
        @param object_type_instance: the ItoaInstance for the object type being security checked

        @type results: JSON list
        @param results: results payload to enforce security and set permissions on

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON list
        @return: payload of results updated with permissions info
        """
        if not (hasattr(object_type_instance, 'is_securable_object') and object_type_instance.is_securable_object):
            # Do not enforce security
            return results

        if object_type_instance.object_type == self.object_type:
            # check if user has itoa_admin capability to perform this action
            if "itoa_admin" not in self._get_all_roles_for_current_user():
                return []

        results = self.enforce_security_on_get(owner, object_type_instance, results, transaction_id=transaction_id)
        if isinstance(results, list):
            results = [result for result in results if result['permissions']['delete']]

        return results

    def enforce_security_on_upsert(self, owner, object_type_instance, results, transaction_id=None):
        """
        Method that evaluates permissions on an object and filters payload to only those that can be created/updated.
        This method is used when results have been passed in by user.

        @type: basestring
        @param owner: user who is performing this operation

        @type object_type_instance: object
        @param object_type_instance: the ItoaInstance for the object type being security checked

        @type results: JSON list
        @param results: results payload to enforce security and set permissions on

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON list
        @return: payload of results updated with permissions info
        """
        if not isinstance(results, list):
            return results

        if not (hasattr(object_type_instance, 'is_securable_object') and object_type_instance.is_securable_object):
            # Do not enforce security
            return results

        if object_type_instance.object_type == self.object_type:

            # For updates, lookup permissions on existing instance of security groups to determine permissions
            sec_grp_perms_map = self._get_security_group_perms_map(owner, transaction_id=transaction_id)

            # Since this is upsert, for objects which dont exist in the store already, use the ACL passed in
            # to determine permissions to prevent user creating a security group that they dont have access to
            for result in results:
                result['permissions'] = self._get_default_permissions()

                if (result.get('_key') is None) or (result['_key'] not in self._get_sec_grp_acls_map()):
                    # Definitely a new object being created,
                    # Check if user has itoa_admin capability to create security group
                    if "itoa_admin" not in self._get_all_roles_for_current_user():
                        return []
                    # Use create ACL to determine permissions
                    self._evaluate_user_permissions_self(result)
                else:
                    if result['_key'] in sec_grp_perms_map:
                        result['permissions'] = sec_grp_perms_map[result['_key']]
        else:
            results = self.enforce_security_on_get(owner, object_type_instance, results, transaction_id=transaction_id, upsert=True)

        if not isinstance(results, list):
            return results

        # Filter out objects without access, let caller decide if they want to fail or proceed
        results = [
            result for result in results
            if result['permissions']['read'] and result['permissions']['write']
        ]

        return results

    def _is_acl_allowing_access(self, acl):
        """
        Given a R/W/D Splunk ACL, identify if it gives access to the current user

        @type acl: list of strings
        @param acl: R/W/D type Splunk ACL which is pretty much a list of role names or '*' for all

        @rtype: boolean
        @return: True if ACL allows access for the current user, False otherwise
        """
        if not isinstance(acl, list):
            return False

        if ('*' in acl) or (self.current_user_name == 'nobody'):
            # Some users like nobody are highest privilege and special splunk users - cannot lookup settings
            # for these users. Ignore enforcing security for this user
            return True

        # If atleast one role for the user is in the ACL, return the object
        for role in self._get_all_roles_for_current_user():
            if role in acl:
                return True

        return False

    def _get_default_permissions(self):
        """
        Method defining a default deny all access permissions

        @rtype: dict
        @return: a permissions structure returned in payload of objects to define deny all access
        """
        return {
                'user': self.current_user_name,
                'read': False,
                'write': False,
                'delete': False
            }

    def _evaluate_user_permissions_self(self, sec_grp):
        """
        Method to identify permissions for the current user on a security group

        @type: JSON dict
        @param sec_grp: a security group object with ACLs

        @rtype: JSON dict
        @return: the security group object updated with permissions info for current user
        """
        sec_grp['permissions'] = self._get_default_permissions()
        if 'acl' in sec_grp:
            sec_grp['permissions'] = {
                'user': self.current_user_name,
                'group': {
                    'read': self._is_acl_allowing_access(sec_grp['acl'].get('read')),
                    'write': self._is_acl_allowing_access(sec_grp['acl'].get('write')),
                    'delete': self._is_acl_allowing_access(sec_grp['acl'].get('delete'))
                }
            }
        else:
            sec_grp['permissions']['group'] = self._get_default_permissions()

        # Set effective permissions for user on security group
        def _set_effective_permissions(access_type):
            """
            Method to compute and set effective permissions (= self + inherited)
            Assumes security group is valid and has permissions defined for inheritance and self

            @type access_type: basestring
            @param access_type: R/W/D access type for which effective permissions are being calculated

            @rtype: dict
            @return: the updated security group
            """
            sec_grp['permissions'][access_type] = (
                sec_grp['permissions']['group'][access_type]
            )
        _set_effective_permissions('read')
        _set_effective_permissions('write')
        _set_effective_permissions('delete')

        return sec_grp


    def enforce_security_self(self, results):
        """
        Method that evaluates permissions on a security group object and sets permission info in payload. This
        method is used when results have been fetched from stored objects.

        @type results: JSON list
        @param results: results payload to enforce security and set permissions on

        @rtype: JSON list
        @return: payload of results updated with permissions info
        """
        if not isinstance(results, list):
            return results

        enforced_results = []
        for result in results:
            acl = result.get('acl')
            if not isinstance(acl, dict):
                logger.warn('Team "%s" found with no ACL, filtering it out.', result.get('title'))
                continue

            enforced_result = self._evaluate_user_permissions_self(result)
            # Redact objects without read access
            if enforced_result['permissions'].get('read'):
                enforced_results.append(enforced_result)
        return enforced_results

    def enforce_security_on_service_content(self, owner, result, transaction_id=None):
        """
        Method that filter on service inside specific object

        @type: basestring
        @param owner: user who is performing this operation

        @type results: JSON dict
        @param results: result payload to further filter out services

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON 
        @return: result payload with only services user has read access
        """
        if result.get('object_type') not in SECURABLE_OBJECT_SERVICE_CONTENT_KEY.keys():
            return result

        sec_grp_perms_map = self._get_security_group_perms_map(owner, transaction_id=transaction_id)

        service_content_key = SECURABLE_OBJECT_SERVICE_CONTENT_KEY.get(result.get('object_type'))

        if result.get(service_content_key, []):
            enforced_services = []
            try:
                if result.get('object_type') == 'base_service_template':
                    service_key_or = [{'_key': service} for service in result.get(service_content_key, [])]
                else:
                    service_key_or = [{'_key': service.get('_key')} for service in result.get(service_content_key, [])]

                service_op = instantiate_object(self.session_key, self.current_user_name, 'service', logger=logger)

                services = service_op.do_paged_get_bulk(owner, filter_data={'$or': service_key_or},
                                                        fields=['_key', 'title', 'sec_grp'],
                                                        skip_enforce_security=True, transaction_id=transaction_id)
                if services:
                    for original_object in services:
                        perms = self._get_default_permissions()
                        if original_object.get('sec_grp') in sec_grp_perms_map:
                            # we are use the sec grp from payload by default
                            perms = sec_grp_perms_map[original_object['sec_grp']]
                        if perms.get('read'):
                            if result.get('object_type') == 'base_service_template':
                                enforced_services.append(original_object.get('_key'))
                            else:
                                enforced_services.append({'_key':original_object.get('_key'), 'title': original_object.get('title')})

                    result[service_content_key] = enforced_services

            except:
                logger.warning('{}: {} contains services that do not exist or in a wrong format: {}'.format(result.get('object_type'),
                                                                                                            result.get('_key'),
                                                                                                            result.get(service_content_key, [])))

        return result

    def enforce_security_foreign(self, owner, results, transaction_id=None, upsert=False):
        """
        Method that evaluates permissions on an object and sets permission info in payload

        @type: basestring
        @param owner: user who is performing this operation

        @type results: JSON list
        @param results: results payload to enforce security and set permissions on

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON list
        @return: payload of results updated with permissions info
        """
        if not isinstance(results, list):
            return results

        sec_grp_perms_map = self._get_security_group_perms_map(owner, transaction_id=transaction_id)

        enforced_results = []
        for result in results:
            perms = self._get_default_permissions()
            if result.get('sec_grp') in sec_grp_perms_map:
                # we are use the sec grp from payload by default
                perms = sec_grp_perms_map[result['sec_grp']]

                # if sec_grp itself is changed, we should use the permission in kvstore
                if upsert and result.get('object_type') == 'service' and result.get('_key'):
                    uri = '/servicesNS/' + owner + '/SA-ITOA/storage/collections/data/itsi_services/' + result.get('_key')
                    try:
                        response, content = rest.simpleRequest(
                            uri, method='GET', sessionKey=self.session_key, raiseAllErrors=True)
                        original_object = json.loads(content) if isinstance(content, basestring) else None

                        # check if it's a sec grp update
                        if original_object and original_object.get('sec_grp') and original_object['sec_grp'] != result['sec_grp']:
                            # combine permissions from kvstore and payload
                            original_perms = sec_grp_perms_map[original_object['sec_grp']]
                            for key in perms:
                                if key not in ['group', 'user']:
                                    perms[key] = (original_perms.get(key) and perms.get(key))
                            if 'group' in perms:
                                perms['group']['read'] = perms.get('read')
                                perms['group']['write'] = perms.get('write')
                                perms['group']['delete'] = perms.get('delete')
                    except:
                        logger.debug('Creating new service {} instead of updating existing.'.format(result.get('_key')))

            result['permissions'] = perms

            # Redact objects without read access
            if result['permissions'].get('read'):
                if upsert:
                    enforced_results.append(result)
                else:
                    enforced_results.append(self.enforce_security_on_service_content(owner, result, transaction_id))

        return enforced_results

    def _get_security_group_perms_map(self, owner, transaction_id=None):
        """
        Method used to query stored permissions for all security groups
        Note that this method is considered expensive and so only invoked once per major operation

        @type: basestring
        @param owner: user who is performing this operation

        @type transaction_id: basestring
        @param transaction_id: transaction info for tracking for debugging

        @rtype: JSON map
        @return: map of all security groups and their permissions info
        """
        # Reminder that security groups are not expected to be large in number, hence lookup all at once
        sec_grps_for_user = self.get_bulk(owner, fields=['_key', 'permissions'], transaction_id=transaction_id)

        sec_grp_perms_map = {}

        if not isinstance(sec_grps_for_user, list):
            return sec_grp_perms_map

        for sec_grp in sec_grps_for_user:
            if sec_grp.get('_key') is not None:
                sec_grp_perms_map[sec_grp['_key']] = sec_grp.get('permissions', self._get_default_permissions())
        del sec_grps_for_user
        return sec_grp_perms_map

    def _get_sec_grp_acls_map(self):
        """
        Method to cache/lookup to store map of all existing security groups and their ACLs

        @rtype: map/dict
        @return: map of _key of security group to its ACL
        """
        if self._sec_grp_acls_map is None:
            persisted_sec_grps = self.storage_interface.get_all(
                self.session_key,
                'nobody',
                objecttype=self.object_type,
                fields=['_key'] + self.get_securable_object_required_fields(),
                current_user_name=self.current_user_name
            )

            self._sec_grp_acls_map = {}
            for persisted_sec_grp in persisted_sec_grps:
                self._sec_grp_acls_map[persisted_sec_grp['_key']] = persisted_sec_grp.get('acl', {})

        return self._sec_grp_acls_map

    def get_inheritance_info(self, sec_grp_ids):
        """
        Method to retrieve hierarchy info for requested security group keys.
        Note that this method bypasses ACL enforcement (= reads directly from KV store)

        @type sec_grp_ids: list of basestring
        @param sec_grp_ids: list of key values of secuity groups

        @rtype: dictionary with hierarchy info
        @return: dictionary with the following info for each security group key
            {
                _key ( = sec_grp_key: {
                    has_parents: True if sec grp has parents,
                    parents: list of parent sec grp keys,

                    has_children: True if sec grp has children,
                    children: list of child keys
                }
            }
        """
        sec_grps_map = {}
        sec_grp_ids_filter = self.get_filter_data_for_keys(object_ids=sec_grp_ids)
        sec_grps = self.storage_interface.get_all(self.session_key, 'nobody', self.object_type,
                                                  filter_data=sec_grp_ids_filter,
                                                  fields=['_key', 'parents', 'children', 'inherit_from'])

        if not isinstance(sec_grps, list):
            if isinstance(sec_grps, dict):
                sec_grps = [sec_grps]
            else:
                return sec_grps_map

        for sec_grp in sec_grps:
            sec_grp_parents = sec_grp.get('parents')
            has_parents = (
                isinstance(sec_grp.get('inherit_from'), basestring) and
                isinstance(sec_grp_parents, list) and
                len(sec_grp_parents) > 0
            )
            sec_grp_children = sec_grp.get('children')
            has_children = (
                isinstance(sec_grp_children, list) and
                len(sec_grp_children) > 0
            )

            sec_grps_map[sec_grp.get('_key')] = {
                'parents': sec_grp_parents,
                'has_parents': has_parents,
                'children': sec_grp_children,
                'has_children': has_children
            }

        return sec_grps_map

    def do_paged_get_bulk(self, owner, sort_key=None, sort_dir=None, filter_data=None, fields=None, skip=None,
                           limit=None, transaction_id=None):

        """
        This is an overridden method for security object only

        On securable objects(That are not global-only), paging needs to fill pages with readable objects since objects without read access
        need to be fully redacted. So load batches from KV store, apply security permissions on them and fill
        requested pages after redacting non-readable rows

        @type owner: string
        @param owner: user who is performing this operation

        @type sort_key: string
        @param sort_key: string defining keys to sort by

        @type sort_dir: string
        @param sort_dir: string defining direction for sorting - asc or desc

        @type filter_data: dictionary
        @param filter_data: json filter constructed to filter data. Follows mongodb syntax

        @type fields: list
        @param fields: list of fields to retrieve, fetches all fields if not specified

        @type skip: number
        @param skip: number of items to skip from the start

        @type limit: number
        @param limit: maximum number of items to return

        @rtype: list of dictionary
        @return: objects retrieved on success, throws exceptions on errors
        """

        if isinstance(fields, list):
            fields += self.get_securable_object_required_fields()

        # UI is the primary consumer of paged get API and usually operates around 10-50 objects per page
        true_page_batch_size = 2000  # True pages refer to pages read from KV store
        reached_true_page_end = False
        current_true_page_skip = 0

        requested_skip = 0
        try:
            if skip is not None:
                requested_skip = int(skip)
        except ValueError, TypeError:
            pass

        requested_count = 0  # < 1 indicates read till end, no limit on count
        try:
            if limit is not None:
                requested_count = int(limit)
        except ValueError, TypeError:
            pass

        requested_page = []
        skipped_so_far = 0

        while (requested_count > len(requested_page) or (requested_count < 1)) and (not reached_true_page_end):
            next_true_page = self.storage_interface.get_all(self.session_key, owner, objecttype=self.object_type,
                                                            sort_key=sort_key, sort_dir=sort_dir,
                                                            filter_data=filter_data, fields=fields,
                                                            limit=true_page_batch_size,
                                                            skip=current_true_page_skip,
                                                            current_user_name=self.current_user_name)

            current_true_page_skip += len(next_true_page)
            if len(next_true_page) < 1:
                reached_true_page_end = True


            next_true_page = self.enforce_security_on_get(owner, self,
                                                          next_true_page,
                                                          transaction_id=transaction_id)

            # Have reached current requested page, fill as much as possible by identifying start and end index from
            # from true page to fill requested page
            start_index = 0
            if len(requested_page) == 0:
                # First time page is starting to get filled, identify right index in results to start at
                # to fill requested page
                # If current page is overflowing for the skip limit needed, indicate by setting start to end of array
                start_index = min(requested_skip - skipped_so_far, len(next_true_page))
                skipped_so_far += start_index  # Accumulate in initially skipped rows

            end_index = len(next_true_page) - 1
            if requested_count > 0:
                # Only get as many rows as requested especially on the last true page
                end_index = min(end_index, start_index + requested_count - len(requested_page) - 1)

            if skipped_so_far < requested_skip:
                # Still not reached current page requested, fill this page by updating skip index and continue looking
                continue

            # Current requested page has been reached, fill it as much as possible with the fetched page
            requested_page.extend(next_true_page[start_index : end_index + 1])

        return requested_page
