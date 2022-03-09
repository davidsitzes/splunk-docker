# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.itoa_common import get_itoa_logger, normalize_num_field, is_valid_str, is_valid_list
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from ITOA.storage import itoa_storage
from ITOA.itoa_exceptions import ItoaAccessDeniedError
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity
from maintenance_services.maintenance_manifest import SUPPORTED_MAINTENANCE_OBJECT_TYPES
from maintenance_services.constants import MAINTENANCE_CALENDAR_OBJECT_TYPE
from .utils import object_collection_mapping
from ITOA.controller_utils import ITOAError

logger = get_itoa_logger('maintenance_services.object.maintenance_calendar', 'maintenance_services.log')

_OBJECT_TYPE = MAINTENANCE_CALENDAR_OBJECT_TYPE


class MaintenanceCalendar(ItoaObject):
    """
    Implements calendar configuration for moving objects into maintenance mode
    """

    log_prefix = '[Maintenance Calendar] '

    def __init__(self, session_key, current_user_name):
        super(MaintenanceCalendar, self).__init__(
            session_key,
            current_user_name,
            _OBJECT_TYPE,
            collection_name=object_collection_mapping[_OBJECT_TYPE],
            title_validation_required=True
        )

    def get_bulk(self,
                 owner,
                 sort_key=None,
                 sort_dir=None,
                 filter_data=None,
                 fields=None,
                 skip=None,
                 limit=None,
                 req_source='get_bulk',
                 transaction_id=None):
        """
        Overriding the itoa_object get_bulk function.
        The maintenance_window object type is not intended to be 'securable' but we can still enforce
        RBAC filtering.

        @type: string
        @param owner: "owner" user performing the config

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

        @type req_source: string
        @param req_source: identified source initiating the operation

        @type transaction_id: string
        @param transaction_id: unique identifier of a user transaction

        @rtype: list of dictionary
        @return: objects retrieved on success, throws exceptions on errors,
                list of of maintenance calendar objects filtering based on rbac
        """
        return self.do_rbac_filtering(owner,
                                      sort_key,
                                      sort_dir,
                                      filter_data,
                                      fields,
                                      skip,
                                      limit,
                                      req_source,
                                      transaction_id)

    def get(self, owner, object_id, req_source='unknown', transaction_id=None):
        """
        Overriding the itoa_object get function.
        The maintenance_window object type is not intended to be 'securable' but we can still enforce
        RBAC filtering.

        @type: string
        @param owner: "owner" user performing the config

        @type object_id: string
        @param object_id: id of object to retrieve

        @type req_source: string
        @param req_source: identified source initiating the operation

        @type transaction_id: string
        @param transaction_id: unique identifier of a user transaction

        @rtype: dictionary
        @return: object matching id on success, empty rows if object is not found, throws exceptions on errors
        """
        maintenance_object = ItoaObject.get(self,
                              owner,
                              object_id,
                              req_source,
                              transaction_id)

        if not maintenance_object:
            raise ITOAError(status="500", message=_("Object does not exist."))

        service_interface = ItsiService(self.session_key, self.current_user_name)
        entity_interface = ItsiEntity(self.session_key, self.current_user_name)

        objects = maintenance_object.get('objects')
        maintenance_object["can_edit"] = True
        for _object in objects:
            maintenance_object_type = _object.get('object_type')
            if maintenance_object_type == 'service':
                try:
                    service = service_interface.get(owner,
                                                    _object.get("_key"),
                                                    req_source="MaintenanceCalendarGet",
                                                    transaction_id=transaction_id)
                    # If service is None, it may have been deleted so it's should not affect
                    # the permissions of the MW
                    if service and 'permissions' in service and 'write' in service["permissions"] and not service["permissions"]['write']:
                        maintenance_object["can_edit"] = False
                        break
                except ItoaAccessDeniedError:
                    maintenance_object["can_edit"] = False

            if maintenance_object_type == 'entity':
                try:
                    entity = entity_interface.get(owner,
                                                  _object.get("_key"),
                                                  req_source="MaintenanceCalendarGet",
                                                  transaction_id=transaction_id)
                    # If entity is None, it may have been deleted so it's should not affect
                    # the permissions of the MW
                    if entity and 'permissions' in entity and 'write' in entity["permissions"] and not entity["permissions"]['write']:
                        maintenance_object["can_edit"] = False
                        break
                except ItoaAccessDeniedError:
                    maintenance_object["can_edit"] = False

        return maintenance_object

    def do_rbac_filtering(self,
                          owner,
                          sort_key=None,
                          sort_dir=None,
                          filter_data=None,
                          fields=None,
                          skip=None,
                          limit=None,
                          req_source='do_rbac_filtering',
                          transaction_id=None):
        """
        Filtering out the maintenance calendar objects which contains:
        - services that current user doesn't have access to
        - entities is in default sec_grp, all user will have access to it.
        How is this done?
        1. Fetch all the maintenance calendar objects without limit and offset
        2. Fetch the services visible to current user
        3. Fetch just the first entity to obtain the sec_grp info (which is global)
        4. Compare the security_groups_ids of objects in the maintenance calendar objects
           against the services security groups user can see.

        @type: string
        @param owner: "owner" user performing the config

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

        @type req_source: string
        @param req_source: identified source initiating the operation

        @type transaction_id: string
        @param transaction_id: unique identifier of a user transaction

        @rtype: list of dictionary
        @return: objects retrieved on success, throws exceptions on errors,
                list of of maintenance calendar objects filtering based on rbac
        """
        # get all the maintenance_calendar objects by
        # enforcing skip = None and limit = None to get them all
        maintenance_objects_full_list = ItoaObject.get_bulk(self,
                                                            owner,
                                                            sort_key,
                                                            sort_dir,
                                                            filter_data,
                                                            fields,
                                                            None,
                                                            None,
                                                            req_source,
                                                            transaction_id)
        if len(maintenance_objects_full_list) > 0:
            fields = ['_key', 'sec_grp', 'permissions']
            # get the services which current_user_name has access to.
            service_interface = ItsiService(self.session_key, self.current_user_name)
            services = service_interface.get_bulk(owner,
                                                  fields=fields,
                                                  req_source="MaintenanceCalendarGetBulk",
                                                  transaction_id=transaction_id)

            # get the entities which current_user_name has access to.
            entity_interface = ItsiEntity(self.session_key, self.current_user_name)
            entities = entity_interface.get_bulk(owner,
                                                 limit=1,
                                                 req_source="MaintenanceCalendarGetBulk",
                                                 transaction_id=transaction_id)
            services_sec_grp_ids = []
            services_by_ids = {}
            entities_by_ids = {}
            for service in services:
                sec_grp = service["sec_grp"]
                if sec_grp not in services_sec_grp_ids:
                    services_sec_grp_ids.append(sec_grp)
                if service["_key"] not in services_by_ids:
                    services_by_ids[service["_key"]] = service

            entities_sec_grp_ids = []
            for entity in entities:
                sec_grp = entity["sec_grp"]
                if sec_grp not in entities_sec_grp_ids:
                    entities_sec_grp_ids.append(sec_grp)
                if entity["_key"] not in entities_by_ids:
                    entities_by_ids[entity["_key"]] = entity

            maintenance_objects_filtered_list = []
            for maintenance_object in maintenance_objects_full_list:
                # default value
                maintenance_object_type = None
                objects = maintenance_object.get('objects',[])
                if objects:
                    first_object = objects[0]
                    if first_object:
                        # maintenance object are either all services or either all entities,
                        # evaluating the first object is enough.
                        maintenance_object_type = first_object.get('object_type')

                # default value
                maintenance_object_sec_grp_list = maintenance_object.get('sec_grp_list', [])

                # one service for which user have access to is enough to turn this flag True
                can_see_maintenance_object = False
                if maintenance_object_type == 'service':
                    for maintenance_object_sec_grp in maintenance_object_sec_grp_list:
                        if maintenance_object_sec_grp in services_sec_grp_ids:
                            can_see_maintenance_object = True
                elif maintenance_object_type == 'entity':
                    for maintenance_object_sec_grp in maintenance_object_sec_grp_list:
                        if maintenance_object_sec_grp in entities_sec_grp_ids:
                            can_see_maintenance_object = True

                if can_see_maintenance_object or len(maintenance_object_sec_grp_list) == 0:
                    # one service for which user doesn't have access to is enough to turn this flag False
                    can_edit_maintenance_object = True
                    for _object in objects:
                        if _object.get('object_type') == 'service':
                            if _object.get('_key') in services_by_ids:
                                service = services_by_ids[_object.get('_key')]
                                if not service["permissions"]['write']:
                                    can_edit_maintenance_object = False
                                    break
                            else:
                                # 2 scenarios:
                                # - service was deleted
                                # - service is not visible to current user
                                # only way to find out is one more request...
                                try:
                                    service = service_interface.get(owner,
                                                                    _object.get('_key'),
                                                                    req_source="MaintenanceCalendarGet",
                                                                    transaction_id=None)
                                    # If service is None, it may have been deleted so it's should not affect
                                    # the permissions of the MW
                                    if service is not None:
                                        # Actually should never go inside here. If the service is read only, it should
                                        # be in services_by_ids.
                                        if 'permissions' in service and 'write' in service["permissions"] and not service["permissions"]['write']:
                                            can_edit_maintenance_object = False
                                            break
                                except ItoaAccessDeniedError:
                                    can_edit_maintenance_object = False
                                    break
                        if _object.get('object_type') == 'entity':
                            # all entities belong to the Global team, just check one
                            if entities:
                                entity_permission = entities[0].get('permissions')
                                if entity_permission:
                                    write = entity_permission.get('write', False)
                                    if not write:
                                        can_edit_maintenance_object = False
                                        break
                                else:
                                    can_edit_maintenance_object = False
                                    break
                            else:
                                can_edit_maintenance_object = False
                                break
                    maintenance_object['can_edit'] = can_edit_maintenance_object
                    maintenance_objects_filtered_list.append(maintenance_object)


            skip = int(skip) if skip is not None else 0
            limit = int(limit) if limit is not None else 0
            if limit == 0 and skip == 0:
                return maintenance_objects_filtered_list
            else:
                return maintenance_objects_filtered_list[skip:limit + skip]
        return maintenance_objects_full_list

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
        transaction_id = self.instrument.push("itoa_object.delete_bulk", transaction_id=transaction_id, owner=owner)

        delete_objects = self.storage_interface.get_all(self.session_key,
                                                        owner,
                                                        self.object_type,
                                                        filter_data=filter_data,
                                                        current_user_name=self.current_user_name,
                                                        fields=['_key', 'acl', 'sec_grp'])

        delete_data = []
        if isinstance(delete_objects, list):
            for object in delete_objects:
                object_id = object.get('_key')

                deletable = True

                object = ItoaObject.get(self,
                        owner,
                        object_id,
                        req_source,
                        transaction_id)

                if not object:
                    raise ITOAError(status="500", message=_("Object does not exist."))

                maintenance_objects = object.get('objects')

                # check if user has read and write access to all the objects in maintenance window
                for maintenance_object in maintenance_objects:
                    maintenance_object_type = maintenance_object['object_type']

                    service_interface = ItsiService(self.session_key, self.current_user_name)
                    entity_interface = ItsiEntity(self.session_key, self.current_user_name)

                    if maintenance_object_type == 'service':
                        try:
                            service = service_interface.get(owner,
                                                            maintenance_object.get("_key"),
                                                            req_source="MaintenanceCalendarGet",
                                                            transaction_id=None)

                            # service will not be None unless Access Denied
                            if service is not None:
                                if 'permissions' in service and 'write' in service["permissions"] and not service["permissions"]['write']:
                                    deletable = False
                                    break

                        except ItoaAccessDeniedError:
                            deletable = False
                            logger.debug('Access denied. Object type: %s. Object id: %s. User: %s'%(maintenance_object_type,
                                                                                                    maintenance_object.get('_key'),
                                                                                                    self.current_user_name))

                    if maintenance_object_type == 'entity':
                        try:
                            entity = entity_interface.get(owner,
                                                          maintenance_object.get("_key"),
                                                          req_source="MaintenanceCalendarGet",
                                                          transaction_id=None)

                            # entity will not be None unless Access Denied
                            if entity is not None:
                                if 'permissions' in entity and 'write' in entity["permissions"] and not entity["permissions"]['write']:
                                    deletable = False
                                    break
                        except ItoaAccessDeniedError:
                            deletable = False
                            logger.debug('Access denied. Object type: %s. Object id: %s. User: %s'%(maintenance_object_type,
                                                                                                    maintenance_object.get('_key'),
                                                                                                    self.current_user_name))

                if deletable:
                    delete_data.append({'_key': object_id, 'object_type': self.object_type})

        del delete_objects

        if len(delete_data) > 0:

            # Construct filter to only delete objects that user has access for deleting
            deletable_objects_filter = self.get_filter_data_for_keys([object.get('_key') for object in delete_data])

            is_delete_needed = True
            if self.object_type == self._get_security_enforcer().object_type:
                if not (len(delete_data) == 1 and
                        delete_data[0].get('_key') == self._get_security_enforcer().get_default_itsi_security_group_key()):
                    deletable_objects_filter = self.get_filter_data_for_keys(
                        [object.get('_key') for object in delete_data
                         if object.get('_key') != self._get_security_enforcer().get_default_itsi_security_group_key()])
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
        # else all objects got filtered out, dont delete any

        self.instrument.pop("itoa_object.delete_bulk", transaction_id)


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
        transaction_id = self.instrument.push("itoa_object.delete", transaction_id=transaction_id, owner=owner)
        if not is_valid_str(object_id):
            self.raise_error_bad_validation(logger, 'ItoaObject cannot delete object with invalid object id')

        object = ItoaObject.get(self,
                                owner,
                                object_id,
                                req_source,
                                transaction_id)
        if not object:
            raise ITOAError(status="500", message=_("Object does not exist."))

        maintenance_objects = object.get('objects')

        # check if user has read and write access to all the objects in maintenance window
        for maintenance_object in maintenance_objects:
            maintenance_object_type = maintenance_object['object_type']

            service_interface = ItsiService(self.session_key, self.current_user_name)
            entity_interface = ItsiEntity(self.session_key, self.current_user_name)

            if maintenance_object_type == 'service':
                try:
                    service = service_interface.get(owner,
                                                    maintenance_object.get("_key"),
                                                    req_source="MaintenanceCalendarGet",
                                                    transaction_id=None)

                    # service will not be None unless Access Denied
                    if service is not None:
                        if 'permissions' in service and 'write' in service["permissions"] and not service["permissions"]['write']:
                            raise ITOAError(status="403", message=_("Permission denied"))

                except ItoaAccessDeniedError:
                    raise ITOAError(status="403", message=_("Permission denied"))

            if maintenance_object_type == 'entity':
                try:
                    entity = entity_interface.get(owner,
                                                  maintenance_object.get("_key"),
                                                  req_source="MaintenanceCalendarGet",
                                                  transaction_id=None)

                    # entity will not be None unless Access Denied
                    if entity is not None:
                        if 'permissions' in entity and 'write' in entity["permissions"] and not entity["permissions"]['write']:
                            raise ITOAError(status="403", message=_("Permission denied"))
                except ItoaAccessDeniedError:
                    raise ITOAError(status="403", message=_("Permission denied"))

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

        self.instrument.pop("itoa_object.delete", transaction_id)
        return results

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT,
                            transaction_id=None):
        """
        Additional setup performed during edit/create operations.
        Primarily involves validation of calendar schema.

        @type: string
        @param owner: "owner" user performing the config

        @type: list of dict
        @param objects: list of calendars being configured as an array of JSON specifications

        @type: string
        @param req_source: source initiating this operation, for tracking

        @type: string
        @param method: type of CRUD operation being performed

        @type transaction_id: string
        @param transaction_id: unique identifier of a user transaction

        @rtype: None
        @return: None
        """
        for json_data in objects:
            # Assume json_data is valid

            # Validate time fields, expected to be in epoch time format = float
            if (json_data.get('start_time') is None) or (json_data.get('end_time') is None):
                self.raise_error_bad_validation(
                    logger,
                    'Start time and end time are mandatory fields. Please specify both.'
                )

            normalize_num_field(json_data, 'start_time', numclass=float)
            normalize_num_field(json_data, 'end_time', numclass=float)

            start_time = json_data['start_time']
            end_time = json_data['end_time']

            if (
                (not isinstance(start_time, float)) or
                (not isinstance(end_time, float)) or
                (start_time < 0) or
                (end_time < 0)
            ):
                self.raise_error_bad_validation(
                    logger,
                    'Start time and end time must be valid epoch time. Please check the values.'
                )

            if start_time >= end_time:
                self.raise_error_bad_validation(
                    logger,
                    'Start time must be earlier than end time. Please check the values.'
                )

            # Validate objects
            maintenance_objects = json_data.get('objects')
            if (not isinstance(maintenance_objects, list)) or (len(maintenance_objects) < 1):
                self.raise_error_bad_validation(
                    logger,
                    'Objects specified must be a valid non-empty list. Please specify at least one object.'
                )

            associated_objects_keys = []
            for maintenance_object in maintenance_objects:
                if (
                    (not isinstance(maintenance_object, dict)) or
                    ('_key' not in maintenance_object) or
                    ('object_type' not in maintenance_object)
                ):
                    self.raise_error_bad_validation(
                        logger,
                        'At least one object specified in invalid. Please specify key and object type for each object.'
                    )

                if not is_valid_str(maintenance_object['_key']):
                    self.raise_error_bad_validation(
                        logger,
                        'At least one object specified with invalid key. Please specify a valid key.'
                    )

                maintenance_object_type = maintenance_object['object_type']
                if (
                    (not is_valid_str(maintenance_object_type)) or
                    (maintenance_object_type not in SUPPORTED_MAINTENANCE_OBJECT_TYPES)
                ):
                    self.raise_error_bad_validation(
                        logger,
                        'Invalid object types specified. Supported object types are: ' + str(
                            SUPPORTED_MAINTENANCE_OBJECT_TYPES
                        )
                    )

                # We will skip validation of whether objects specified actually exist since stale objects could exist in
                # stale/expired config and are better off being preserved for tracking purposes. Configuring maintenance
                # is also simpler to use this way.


                service_interface = ItsiService(self.session_key, self.current_user_name)
                entity_interface = ItsiEntity(self.session_key, self.current_user_name)

                if maintenance_object_type == 'service':
                    try:
                        service = service_interface.get(owner,
                                                        maintenance_object.get("_key"),
                                                        req_source="MaintenanceCalendarGet",
                                                        transaction_id=transaction_id)
                        if service is not None:
                            if 'permissions' in service and 'write' in service["permissions"] and not service["permissions"]['write']:
                                raise ITOAError(status="403", message=_("Permission denied"))
                            if service.get('sec_grp') and not service['sec_grp'] in associated_objects_keys:
                                associated_objects_keys.append(service['sec_grp'])

                    except ItoaAccessDeniedError:
                        raise ITOAError(status="403", message=_("Permission denied"))

                if maintenance_object_type == 'entity':
                    try:
                        entity = entity_interface.get(owner,
                                                      maintenance_object.get("_key"),
                                                      req_source="MaintenanceCalendarGet",
                                                      transaction_id=transaction_id)

                        if entity is not None:
                            if 'permissions' in entity and 'write' in entity["permissions"] and not entity["permissions"]['write']:
                                raise ITOAError(status="403", message=_("Permission denied"))
                            if entity.get('sec_grp') and not entity['sec_grp'] in associated_objects_keys:
                                associated_objects_keys.append(entity['sec_grp'])
                    except ItoaAccessDeniedError:
                        raise ITOAError(status="403", message=_("Permission denied"))

            # len(associated_objects_keys) == 0 should not append at maintenance_calendar creation
            # but it can happen when creating a maintenance_calendar with services and entities
            # that doesn't exist => test_maintenance_services_interface.py
            if len(associated_objects_keys) == 0:
                json_data['sec_grp_list'] = [self._get_security_enforcer().get_default_itsi_security_group_key()]
            else:
                json_data['sec_grp_list'] = associated_objects_keys
