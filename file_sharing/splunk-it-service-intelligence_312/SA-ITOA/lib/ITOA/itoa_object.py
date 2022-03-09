# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
itoa_object contains the main abstraction class for ITOA specific objects (ItoaObject)
as well as some support classes specific to ItoaObject
"""
import math
from splunk.appserver.mrsparkle.lib import i18n
from . import itoa_common as utils
from ITOA.storage import itoa_storage
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_ONLY_SECURABLE_OBJECT_LIST
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
from ITOA.setup_logging import setup_logging, InstrumentCall
from ITOA.itoa_config import get_secure_object_enforcer_cls
from ITOA.itoa_exceptions import ItoaAccessDeniedError

import itoa_refresh_queue_utils

logger = setup_logging("itsi.log", "itoa.object")

# TODO: Get the batch size from limits.conf - moved this TODO from itoa_csv_loader
BATCH_SIZE = 500
ENTITY_BATCH_SIZE = 50000


class CRUDMethodTypes(utils.ItoaBase):
    """
    CRUD method types
    Intended to be used like an enum
    """
    METHOD_CREATE = 'CREATE'
    METHOD_UPDATE = 'UPDATE'
    METHOD_DELETE = 'DELETE'
    METHOD_UPSERT = 'UPSERT'
    METHOD_GET = 'GET'


class ItoaObject(utils.ItoaBase):
    """
    Abstraction for all ITOA objects

    Implements CRUD operations for object REST end points
    """

    log_prefix = '[ITOA Object] '

    identifying_name_field = 'identifying_name'

    mod_method = 'REST'

    def __init__(self,
                 session_key,
                 current_user_name,
                 object_type,
                 collection_name=None,
                 title_validation_required=True,
                 is_securable_object=False):
        super(ItoaObject, self).__init__(session_key)
        self.current_user_name = current_user_name
        self.object_type = object_type
        self.title_validation_required = title_validation_required
        self.is_securable_object = is_securable_object

        kwargs = {}
        if collection_name:
            kwargs['collection'] = collection_name
        self.storage_interface = itoa_storage.ITOAStorage(**kwargs)
        self._security_enforcer = None

        self._version = ITOAInterfaceUtils.get_app_version(self.session_key)
        self.instrument = InstrumentCall(logger)

    def _get_security_enforcer(self):
        """
        Method to instantiate and cache security enforcer ItoaObject instance

        @rtype: ItoaObject
        @return: ItoaObject instance of the security enforcer object type
        """
        if self._security_enforcer is None:
            self._security_enforcer = get_secure_object_enforcer_cls()(self.session_key, self.current_user_name)
        return self._security_enforcer

    def resolve_duplicated_names(self, objects, duplicated_names, dupname_tag):
        """
        @type objects: list of dictionary
        @param objects: list of objects retrieved from the backup json file
        @type duplicated_names: set
        @param duplicated_names: set of duplicated names
        @type dupname_tag: string
        @param dupname_tag: a string tag defined in the commandline by user.
                            This is an optional param. It is set when user intents to
                            replace the duplicated service or entity names automatically
                            during the kv store restoring.
        @return: none, throws exceptions on errors
        """
        for json_data in objects:
            identifying_name = json_data.get(self.identifying_name_field)
            if identifying_name in duplicated_names:
                dupname_tag_with_time = str(dupname_tag) + '_' + str(int(utils.get_current_utc_epoch()))
                entity_title = json_data.get('title')
                json_data[self.identifying_name_field] = identifying_name + dupname_tag_with_time
                json_data['title'] = entity_title + dupname_tag_with_time

    def ensure_required_fields(self, objects):
        """
        Modify the objects passed in by reference to ensure they have the system generated required fields
        Update the specific fields for create, update and batch_save
        @type objects: list[dict]
        @param objects: list of dict
        @return: None
        """
        for json_data in objects:
            json_data['mod_source'] = self.mod_method
            json_data['mod_timestamp'] = utils.get_current_timestamp_utc()
            json_data['_version'] = self._version
            # Add identifying names here, even if the title is empty for use in sorting and comparison
            json_data[self.identifying_name_field] = str(json_data.get('title', '')).strip().lower()

            if self.is_securable_object and self.object_type != self._get_security_enforcer().object_type:
                # If none specified, assign to default security group
                if not isinstance(json_data.get('sec_grp'), basestring):
                    json_data['sec_grp'] = self._get_security_enforcer().get_default_itsi_security_group_key()

    def do_object_validation(self, owner, objects, validate_name=True, dupname_tag=None, transaction_id=None):
        """
        Generic object validation routine.
        Currently, it only consists of title related validation.
        All new object level validation should be invoked from here...
        @type objects: list[dict]
        @param objects: list of dict
        @return: None
        """
        self.storage_interface.check_payload_size(self.session_key, objects)

        if self.is_securable_object:
            for json_data in objects:
                if 'permissions' in json_data:
                    del json_data['permissions']

        if not self.title_validation_required:
            # Skip the below code as it is only used for title validation
            return

        for json_data in objects:
            if not utils.is_valid_name(json_data.get('title', None)):
                self.raise_error_bad_validation(logger, _('Invalid title specified for the object_type: %s. \
                Must be non-empty and cannot contain = " or \'.') % self.object_type)

        # Value of validate_name is set in the save_batch mode only.
        # User may not want to validate the identifying_name from save_batch mode,
        # for create and update case, validate_name is always set to true.
        if validate_name:
            transaction_id = self.instrument.push("itoa_object.validate_identifying_name", transaction_id=transaction_id, owner=owner)
            self.validate_identifying_name(owner, objects, dupname_tag, transaction_id)
            self.instrument.pop("itoa_object.validate_identifying_name", transaction_id)

    def validate_identifying_name(self, owner, objects, dupname_tag=None, transaction_id=None):
        """
        Check for valid and unique names for the objects, stored in the identifying_name
        @type owner: string
        @param owner: user who is performing this operation
        @type objects: list
        @param objects: list of objects
        @return: None, throws exceptions on validations failing
        """

        # First guard against duplicates within passed in objects
        unique_names = set()
        duplicate_names = set()
        invalid_names = set()
        name_filter = []
        for json_data in objects:
            identifying_name = str(json_data.get(self.identifying_name_field)).strip()
            if utils.is_valid_name(identifying_name):
                identifying_name = identifying_name.lower()
                if identifying_name not in unique_names:
                    unique_names.add(identifying_name)
                else:
                    duplicate_names.add(identifying_name)
                # Append to filter to identify existing objects later that have the same identifying name as this object
                name_based_filter = {'$and': [
                    {'identifying_name': identifying_name},
                    {'_key': {"$ne": json_data.get('_key', '')}}
                ]}
                if self.is_securable_object and self._get_security_enforcer().object_type != self.object_type:
                    name_based_filter['$and'].append({'sec_grp': json_data.get('sec_grp')})

                name_filter.append(name_based_filter)
            else:
                invalid_names.add(str(identifying_name))

        if len(invalid_names) > 0:
            self.raise_error_bad_validation(
                logger,
                _('Names cannot contain equal and quote characters. List of invalid names: %s.') % ', '.join(list(invalid_names))
            )
        del invalid_names

        if len(duplicate_names) > 0:
            self.raise_error_bad_validation(
                logger,
                _('Object names must be unique. List of duplicate names: %s.') % ', '.join(list(duplicate_names)),
                409
                )
        del duplicate_names
        del unique_names

        # Now guard against duplicates against saved objects
        persisted_objects = self.get_bulk(
            owner,
            filter_data={'$or': name_filter},
            fields=['_key', 'identifying_name'],
            transaction_id=transaction_id
        )

        if isinstance(persisted_objects, list) and len(persisted_objects) > 0:
            duplicate_names = set(
                [persisted_object.get('identifying_name', '') for persisted_object in persisted_objects])
            if dupname_tag:
                self.resolve_duplicated_names(objects, duplicate_names, dupname_tag)
            else:
                self.raise_error_bad_validation(
                    logger,
                    _('Duplicate object name(s) found: {}. Please rename the object(s) before proceeding.').format(', '.join(duplicate_names)),
                    409
                )
            del duplicate_names

    def create(self, owner, data, dupname_tag=None, transaction_id=None):
        """
        Create object passed in
        @type owner: string
        @param owner: user who is performing this operation
        @type data: dictionary
        @param data: object to create
        @rtype: string
        @return: id of object created if successful, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itoa_object.create", transaction_id=transaction_id, owner=owner)
        json_data = self.extract_json_data(data)

        if not isinstance(json_data, dict):
            self.raise_error_bad_validation(logger, _('Invalid create payload found, must be a valid JSON dictionary.'))

        json_data['object_type'] = self.object_type

        self.ensure_required_fields([json_data])
        # Deny Access if attempting to create securable object in non-default security group -for default-only objects
        if (self.is_securable_object and
                json_data.get('object_type', None) in GLOBAL_ONLY_SECURABLE_OBJECT_LIST and
                json_data.get('sec_grp', None) != GLOBAL_SECURITY_GROUP_CONFIG.get('key')):
            raise ItoaAccessDeniedError(
                _('Access denied. Object of type {} can only be created in Global team.')
                .format(json_data.get('object_type', None)),
                logger)

        if self.is_securable_object:
            results = self._get_security_enforcer().enforce_security_on_upsert(owner, self, [json_data], transaction_id=transaction_id)
            if (not isinstance(results, list)) or (len(results) != 1):
                raise ItoaAccessDeniedError(
                    _('Access denied. You do not have permission to create this object.'),
                    logger)

        self.instrument.push("itoa_object.do_object_validation", transaction_id=transaction_id, owner=owner)
        self.do_object_validation(owner, [json_data], True, dupname_tag, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.do_object_validation", transaction_id)

        self.instrument.push("itoa_object.do_additional_setup", transaction_id=transaction_id, owner=owner)
        self.do_additional_setup(owner, [json_data], method=CRUDMethodTypes.METHOD_CREATE, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.do_additional_setup", transaction_id)

        self.instrument.push("itoa_object.identify_dependencies", transaction_id=transaction_id, owner=owner)
        is_refresh_required, refresh_jobs = self.identify_dependencies(
            owner,
            [json_data],
            CRUDMethodTypes.METHOD_CREATE,
            req_source="create",
            transaction_id=transaction_id
            )
        self.instrument.pop("itoa_object.identify_dependencies", transaction_id)

        self.instrument.push("itoa_storage.create", transaction_id=transaction_id, owner=owner)
        results = self.storage_interface.create(
            self.session_key,
            owner,
            self.object_type,
            json_data,
            current_user_name=self.current_user_name
            )
        self.instrument.pop("itoa_storage.create", transaction_id)

        logger.debug('Object of type %s created with id: %s, request source: %s',
                self.object_type,
                results['_key'],
                json_data.get('mod_source', '')
            )
        self.instrument.push("itoa_object.post_save_setup", transaction_id=transaction_id, owner=owner)
        self.post_save_setup(owner, [results], [json_data], method=CRUDMethodTypes.METHOD_CREATE, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.post_save_setup", transaction_id)

        if is_refresh_required:
            self.create_refresh_jobs(refresh_jobs)

        self.instrument.pop("itoa_object.create", transaction_id)
        return results

    def save_batch(
            self,
            owner,
            data_list,
            validate_names,
            dupname_tag=None,
            req_source='unknown',
            ignore_refresh_impacted_objects=False,
            method=CRUDMethodTypes.METHOD_UPSERT,
            is_partial_data=False,
            transaction_id=None
        ):
        """
        Upsert objects passed in
        @type owner: string
        @param owner: user who is performing this operation
        @type data_list: list
        @param data_list: list of objects to upsert
        @type validate_names: bool
        @param validate_names: validate_names is a means for search commands and csv load to by pass
            perf hit from name validation in scenarios they can safely skip
        @type req_source: string
        @param req_source: string identifying source of this request
        @type is_partial_data: bool
        @param is_partial_data: indicates if payload passed into each entry in data_list is a subset of object structure
            when True, payload passed into data is a subset of object structure
            when False, payload passed into data is the entire object structure
            Note that KV store API does not support partial updates
            This argument only applies to update entries since on create, entire payload is a MUST
        @rtype: list of strings
        @return: ids of objects upserted on success, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itoa_object.save_batch", transaction_id=transaction_id, owner=owner)
        valid_data_list = []

        if not isinstance(data_list, list):
            self.raise_error_bad_validation(logger, _('Invalid upsert payload found, must be a valid JSON list.'))
        elif len(data_list) == 0:
            self.raise_error_bad_validation(
                logger,
                _('Are you sure you wanted to save a batch? Are you sure it wasn\'t NOTHING?!?!,'
                    ' cannot save empty payload, received {}').format(data_list)
            )

        for data in data_list:
            try:
                json_data = self.extract_json_data(data)
                json_data['object_type'] = self.object_type
                valid_data_list.extend([json_data])
            except Exception, e:
                # Skip saving this item, output will not contain an id for it
                logger.debug('Skipping object %s of type %s from bulk save since data passed in is invalid',
                        data,
                        self.object_type )
                logger.exception(e)

        if is_partial_data:
            self.instrument.push("itoa_object._patch_partial_data_list", transaction_id=transaction_id, owner=owner)
            self._patch_partial_data_list(owner, valid_data_list, transaction_id=transaction_id)
            self.instrument.pop("itoa_object._patch_partial_data_list", transaction_id)

        # Deny Access if attempting to create securable object in non-default security group -for default-only objects
        self.ensure_required_fields(valid_data_list)

        # Deny Access if attempting to create securable object in non-default security group -for default-only objects
        if (utils.is_valid_dict(json_data) and self.is_securable_object and
                    json_data.get('object_type', None) in GLOBAL_ONLY_SECURABLE_OBJECT_LIST and
                    json_data.get('sec_grp', None) != GLOBAL_SECURITY_GROUP_CONFIG.get('key')):
            raise ItoaAccessDeniedError(
                _('Access denied. Object of type %s can only be created in Global team.') %
                json_data.get('object_type', None),
                logger)

        if self.is_securable_object and isinstance(valid_data_list, list):
            results = self._get_security_enforcer().enforce_security_on_upsert(owner, self, valid_data_list,
                                                                               transaction_id=transaction_id)
            if (not isinstance(results, list)) or (len(valid_data_list) != len(results)):
                raise ItoaAccessDeniedError(
                    _('Access denied. You do not have permission to create this object.'),
                    logger)
            del results
        self.instrument.push("itoa_object.do_object_validation", transaction_id=transaction_id, owner=owner)
        self.do_object_validation(owner, valid_data_list, validate_names, dupname_tag, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.do_object_validation", transaction_id)

        self.instrument.push("itoa_object.do_additional_setup", transaction_id=transaction_id, owner=owner)
        self.do_additional_setup(owner, valid_data_list, method=method, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.do_additional_setup", transaction_id)

        if (not utils.is_valid_list(valid_data_list)) or (len(valid_data_list) < 1):
            logger.debug('save batch didnt find any rows to save, skipping save ...')
            return []

        self.instrument.push("itoa_object.idenfity_dependencies", transaction_id=transaction_id, owner=owner)
        is_refresh_required, refresh_jobs = self.identify_dependencies(owner, valid_data_list, method,
                                                                       req_source="save_batch", transaction_id=transaction_id)
        self.instrument.pop("itoa_object.identify_dependencies", transaction_id)

        result_ids = self.batch_save_backend(owner, valid_data_list, transaction_id=transaction_id)
        logger.debug('Batch save done for %s objects of type %s - save returned %s ids, request source: %s',
                len(valid_data_list),
                self.object_type,
                len(result_ids) if utils.is_valid_list(result_ids) else 0,
                req_source
            )

        self.instrument.push("itoa_object.post_save_setup", transaction_id=transaction_id, owner=owner)
        self.post_save_setup(owner, result_ids, valid_data_list, method=method, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.post_save_setup", transaction_id)

        if is_refresh_required and (not ignore_refresh_impacted_objects):
            self.create_refresh_jobs(refresh_jobs)

        self.instrument.pop("itoa_object.save_batch", transaction_id)
        return result_ids

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
        transaction_id = self.instrument.push("itoa_object.update", transaction_id=transaction_id, owner=owner)
        if not utils.is_valid_str(object_id):
            self.raise_error_bad_validation(logger, _('ItoaObject cannot update object with invalid object id.'))

        json_data = self.extract_json_data(data)

        if not isinstance(json_data, dict):
            self.raise_error_bad_validation(logger, _('Invalid update payload found, must be a valid JSON dictionary.'))

        json_data['object_type'] = self.object_type

        if not utils.is_valid_str(json_data.get('_key')):
            json_data['_key'] = object_id

        if is_partial_data:
            self.instrument.push("itoa_object._patch_partial_data_list", transaction_id=transaction_id, owner=owner)
            self._patch_partial_data_list(owner, [json_data], transaction_id=transaction_id)
            self.instrument.pop("itoa_object._patch_partial_data_list", transaction_id)

        self.ensure_required_fields([json_data])

        # Deny Access if attempting to update securable object in non-default security group -for default-only objects
        if (self.is_securable_object and
                json_data.get('object_type', None) in GLOBAL_ONLY_SECURABLE_OBJECT_LIST and
                json_data.get('sec_grp', None) != GLOBAL_SECURITY_GROUP_CONFIG.get('key')):
            raise ItoaAccessDeniedError(
                _('Access denied. Object of type %s can only be updated in the Global team.') %
                json_data.get('object_type', None),
                logger)

        if self.is_securable_object:
            results = self._get_security_enforcer().enforce_security_on_upsert(owner, self, [json_data],
                                                                               transaction_id=transaction_id)
            if (not isinstance(results, list)) or (1 != len(results)):
                raise ItoaAccessDeniedError(
                    _('Access denied. You do not have permission to update this object.'), logger)
            del results
        self.do_object_validation(owner, [json_data], True, dupname_tag, transaction_id=transaction_id)

        self.instrument.push("itoa_object.do_additional_setup", transaction_id=transaction_id, owner=owner)
        self.do_additional_setup(owner, [json_data], method=CRUDMethodTypes.METHOD_UPDATE, transaction_id=transaction_id)
        self.instrument.pop("itoa_object.do_additional_setup", transaction_id)

        self.instrument.push("itoa_object.identify_dependencies", transaction_id=transaction_id, owner=owner)
        is_refresh_required, refresh_jobs = self.identify_dependencies(owner, [json_data], CRUDMethodTypes.METHOD_UPDATE,
                                                                       req_source="update", transaction_id=transaction_id)
        self.instrument.pop("itoa_object.identify_dependencies", transaction_id)

        results = self.storage_interface.edit(
            self.session_key,
            owner,
            self.object_type,
            object_id,
            json_data,
            current_user_name=self.current_user_name
            )
        logger.debug('Object of type %s with id: %s updated, request source: %s',
                self.object_type,
                results['_key'],
                json_data.get('mod_source', '')
            )

        self.post_save_setup(owner, [results], [json_data], method=CRUDMethodTypes.METHOD_UPDATE, transaction_id=transaction_id)
        if is_refresh_required:
            self.create_refresh_jobs(refresh_jobs)

        self.instrument.pop("itoa_object.update", transaction_id)
        return results

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
        if not utils.is_valid_str(object_id):
            self.raise_error_bad_validation(logger, _('ItoaObject cannot delete object with invalid object id.'))

        stored_object = self.get(owner, object_id, req_source=req_source, transaction_id=transaction_id)
        if self.is_securable_object:
            if isinstance(stored_object, dict):
                results = self._get_security_enforcer().enforce_security_on_delete(owner, self, [stored_object],
                                                                                   transaction_id=transaction_id)
                if (not isinstance(results, list)) or (1 != len(results)):
                    raise ItoaAccessDeniedError(
                        _('Access denied. You do not have permission to delete this object.'),
                        logger)
                del results

        # added for kpi base search and kpi threshold template
        # could extend to other objects
        if isinstance(stored_object, dict):
            self.can_be_deleted(owner, [stored_object], raise_error=True, transaction_id=transaction_id)

        del stored_object

        self.instrument.push("itoa_object.idenfity_dependencies", transaction_id=transaction_id, owner=owner)
        is_refresh_required, refresh_jobs = self.identify_dependencies(
            owner, [{"_key": object_id, 'object_type': self.object_type}],
            CRUDMethodTypes.METHOD_DELETE,
            req_source="delete",
            transaction_id=transaction_id
        )
        self.instrument.pop("itoa_object.idenfity_dependencies", transaction_id)

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

        self.instrument.pop("itoa_object.delete", transaction_id)
        return results

    def templatize(self, owner, object_id, req_source='unknown'):
        """
        Templatize given object id
        @type owner: basestring
        @param owner: context of the request `nobody` vs an actual user

        @type object_id: basestring
        @param object_id: unique identifier of an object to templatize

        @type req_source: basestring
        @param req_source: indentified source initiating the operation.

        @rtype: dict/None
        @return: requested template
        """
        template = self.get(owner, object_id, req_source)
        if template is None:
            logger.error('Could not find object id=`%s`', object_id)
            return None

        # Make template, by removing some k-v s
        removed = set()

        # We cant modify a dictionary while iterating over it,
        # hence we will iterate over its keys
        for key in template.keys():
            # we will remove these keys
            if any([
                key.startswith('mod_'),
                key in ('acl', '_key', '_user', '_owner', 'identifying_name', 'sec_grp')
                ]):
                template.pop(key)
                removed.add(key)

        logger.debug('object_id=`%s`, removed keys=`%s`', object_id, removed)
        return template

    def get(self, owner, object_id, req_source='unknown', transaction_id=None):
        """
        Retrieves object by id
        @type owner: basestring
        @param owner: user who is performing this operation
        @type object_id: basestring

        @type object_id: string
        @param object_id: id of object to retrieve
        @type req_source: basestring

        @type req_source: string
        @param req_source: identified source initiating the operation

        @rtype: dictionary
        @return: object matching id on success, empty rows if object is not found, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itoa_object.get", transaction_id=transaction_id, owner=owner)
        if not utils.is_valid_str(object_id):
            self.raise_error_bad_validation(logger, _('ItoaObject cannot retrieve object with invalid object id.'))

        result = self.storage_interface.get(
            self.session_key,
            owner,
            self.object_type,
            object_id,
            current_user_name=self.current_user_name)

        if self.is_securable_object and isinstance(result, dict):
            results = self._get_security_enforcer().enforce_security_on_get(owner, self, [result],
                                                                            transaction_id=transaction_id)
            if isinstance(results, list) and len(results) == 1:
                # On get, so long as the object permissions could be evaluated, we will return object with
                # evaluated permissions. If there is no read access on the object, the payload would have been
                # updated for it with permissions info
                result = results[0]
            else:
                # Something has gone wrong majorly, so throw access denied error to be safe
                raise ItoaAccessDeniedError(
                    _('Access denied. You do not have permission to access this object.'),
                    logger)

        logger.debug('Object of type %s with id: %s retrieved, request source: %s',
            self.object_type, object_id, req_source )

        self.instrument.pop("itoa_object.get", transaction_id)
        return result

    def get_bulk(
            self,
            owner,
            sort_key=None,
            sort_dir=None,
            filter_data=None,
            fields=None,
            skip=None,
            limit=None,
            req_source='unknown',
            transaction_id=None
        ):
        """
        Retrieves objects matching criteria, if no filtering specified, retrieves all objects of this object type

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

        @type req_source: string
        @param req_source: identified source initiating the operation

        @rtype: list of dictionary
        @return: objects retrieved on success, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itoa_object.get_all", transaction_id=transaction_id, owner=owner)

        results = self.do_paged_get_bulk(owner, sort_key=sort_key, sort_dir=sort_dir, filter_data=filter_data,
            fields=fields, limit=limit, skip=skip, transaction_id=transaction_id)

        logger.debug('%s objects of type %s retrieved, request source: %s',
                len(results) if utils.is_valid_list(results) else 1 if utils.is_valid_dict(results) else 0,
                self.object_type,
                req_source
            )
        self.instrument.pop("itoa_object.get_all", transaction_id)
        return results

    def _get_sec_grp_filter(self, owner, filter_data=None, req_source='unknown', transaction_id=None):
        """
        This internal method merges the user's custom filter with the sec_grp filter.
        sec_grp filter is based on the sec_grp that a particular user has access to.  The combined filter will
        be applied in the ITOA object get_bulk, so that the result of the get_bulk only contains objects
        that the user has access to.

        @type owner: string
        @param owner: user who is performing this operation

        @type filter_data: dictionary
        @param filter_data: json filter constructed to filter data. Follows mongodb syntax

        @rtype: list of dictionary
        @return: objects retrieved on success, throws exceptions on errors
        """

        key_list = []
        sec_grp_instance = self._get_security_enforcer()
        sec_grp_result = sec_grp_instance.get_bulk(owner,
                                                   filter_data=None,
                                                   req_source=req_source,
                                                   transaction_id=transaction_id)
        final_result = sec_grp_instance.enforce_security_on_get(owner,
                                                                sec_grp_instance,
                                                                sec_grp_result,
                                                                transaction_id=transaction_id)
        for result in final_result:
            key_list.append(result.get('_key'))
        if key_list:
            sec_filter_data = {
                '$or': [{'sec_grp': key} for key in key_list]
            }
        else:
            sec_filter_data = None

        return ITOAInterfaceUtils.merge_with_sec_filter(filter_data, sec_filter_data)

    def do_paged_get_bulk(self, owner, sort_key=None, sort_dir=None, filter_data=None, fields=None, skip=None,
                           limit=None, skip_enforce_security=False, transaction_id=None):
        """
        KV store has a 50K limit on results it can return and does so without much warning. In order to not incur this
        limit, get_bulk should be paged.

        On securable objects(That are not global-only), paging needs to fill pages with readable objects since objects without read access
        need to be fully redacted. The batch get_all queries based on the security group filter.
        The assumption is that if the user is able to retrieve a particular set of security group, the user will
        have the read/write permission to the securable objects with the same security group

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

        if self.is_securable_object and isinstance(fields, list) and not skip_enforce_security:
            fields += self._get_security_enforcer().get_securable_object_required_fields()

        if self.object_type in ['entity']:
            batch_size = ENTITY_BATCH_SIZE
        else:
            batch_size = BATCH_SIZE

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

        if self.is_securable_object and not skip_enforce_security:
            filter_data = self._get_sec_grp_filter(owner,
                                                   filter_data=filter_data,
                                                   req_source='unknown',
                                                   transaction_id=transaction_id)

        if 0 < requested_count <= batch_size:
            requested_page = self.storage_interface.get_all(self.session_key, owner, objecttype=self.object_type,
                                                            sort_key=sort_key, sort_dir=sort_dir,
                                                            filter_data=filter_data, fields=fields,
                                                            limit=limit,
                                                            skip=skip,
                                                            current_user_name=self.current_user_name)
            if self.is_securable_object and not skip_enforce_security:
                requested_page = self._get_security_enforcer().enforce_security_on_get(owner, self,
                                                                                       requested_page,
                                                                                       transaction_id=transaction_id)
            return requested_page

        if requested_count == 0:
            while True:
                results = self.storage_interface.get_all(self.session_key, owner, objecttype=self.object_type,
                                                         sort_key=sort_key, sort_dir=sort_dir,
                                                         filter_data=filter_data, fields=fields,
                                                         limit=batch_size,
                                                         skip=requested_skip,
                                                         current_user_name=self.current_user_name)
                if not results or len(results) == 0:
                    break
                requested_skip += batch_size
                requested_page.extend(results)

            if self.is_securable_object and not skip_enforce_security:
                requested_page = self._get_security_enforcer().enforce_security_on_get(owner, self,
                                                                                       requested_page,
                                                                                       transaction_id=transaction_id)
            return requested_page

        if requested_count > batch_size:
            while requested_count > 0:
                results = self.storage_interface.get_all(self.session_key, owner, objecttype=self.object_type,
                                                         sort_key=sort_key, sort_dir=sort_dir,
                                                         filter_data=filter_data, fields=fields,
                                                         limit=min(requested_count, batch_size),
                                                         skip=requested_skip,
                                                         current_user_name=self.current_user_name)
                if not results or len(results) == 0:
                    break
                requested_count -= batch_size
                requested_skip += batch_size
                requested_page.extend(results)

            if self.is_securable_object and not skip_enforce_security:
                requested_page = self._get_security_enforcer().enforce_security_on_get(owner, self,
                                                                                       requested_page,
                                                                                       transaction_id=transaction_id)
            return requested_page

        return requested_page

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
        if self.is_securable_object:
            # Enforce security on the identified objects to get current user's permissions for delete
            # The enforced security should be honored to filter to objects that are deletable by current user
            # since this is bulk delete hence dont fail call but just delete what user has access to
            if isinstance(delete_objects, list):
                delete_objects = self._get_security_enforcer().enforce_security_on_delete(
                    owner, self, delete_objects, transaction_id=transaction_id)

        # added for kpi base search and kpi threshold template
        # could extend to other objects
        delete_objects = self.can_be_deleted(owner, delete_objects, raise_error=False, transaction_id=transaction_id)

        delete_data = [
            {'_key': object_id.get('_key'), 'object_type': self.object_type} for object_id in delete_objects
        ] if isinstance(delete_objects, list) else []
        del delete_objects

        if len(delete_data) > 0:

            self.instrument.push("itoa_object.identify_dependencies", transaction_id=transaction_id, owner=owner)
            is_refresh_required, refresh_jobs = self.identify_dependencies(
                owner,
                delete_data,
                CRUDMethodTypes.METHOD_DELETE,
                req_source="delete"
            )
            self.instrument.pop("itoa_object.identify_dependencies", transaction_id)

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
            if is_refresh_required:
                self.create_refresh_jobs(refresh_jobs)
        # else all objects got filtered out, dont delete any

        self.instrument.pop("itoa_object.delete_bulk", transaction_id)

    def batch_save_backend(self, owner, data_list, transaction_id=None):
        """
        Internal method used to batch upserts
        Note that there is no refresh job checks here.
        Note also that this direct write by-passes security checks
        In case if you need to add refresh_job check here then ServiceDelete Handler need to be changed
        @type owner: string
        @param owner: user who is performing this operation
        @type data_list: list of dictionary
        @param data_list: objects to upsert
        @type transaction_id: basestring
        @param transaction_id: unique identifier for trannsaction tracing
        @rtype: list of strings
        @return: ids of objects upserted on success, throws exceptions on errors
        """
        transaction_id = self.instrument.push("itoa_object.batch_save_backend", transaction_id=transaction_id, owner=owner)
        backend = self.storage_interface.get_backend(self.session_key)
        total_size = len(data_list)
        results = []
        if total_size > BATCH_SIZE:
            iterations = total_size / BATCH_SIZE
            start_index = 0
            for i in range(iterations+1):
                if i == iterations:
                    end_index = start_index + total_size - iterations * BATCH_SIZE
                else:
                    end_index = start_index + BATCH_SIZE
                if end_index <= start_index:
                    logger.debug('batch_save_backend skipping tid=%s start=%s end=%s total=%s', transaction_id, start_index, end_index, total_size)
                    continue
                logger.debug('batch_save_backend tid=%s start=%s end=%s total=%s', transaction_id, start_index, end_index, total_size)
                results += backend.batch_save(self.session_key, owner, data_list[start_index:end_index])
                start_index += BATCH_SIZE
        else:
            results = backend.batch_save(self.session_key, owner, data_list)

        self.instrument.pop("itoa_object.batch_save_backend", transaction_id)
        return results

    def _patch_partial_data(self, data_to_patch, existing_data, transaction_id=None):
        """
        Patch partial data for object by merging with existing object content
        Used to support partial updates since KV store API does not support partial updates directly
        @type data_to_patch: dict
        @param data_to_patch: data payload to be patched
        @type existing_data: dict
        @param existing_data: existing data payload to patch with
        @rtype: None
        @return: None
        """

        # Assume data_to_patch and existing_data are valid dicts

        marked_for_delete = data_to_patch.get('_marked_for_delete', {})
        if not utils.is_valid_dict(marked_for_delete):
            marked_for_delete = {}

        # First merge to patch existing data with new partial data
        for key, value in existing_data.iteritems():
            if key not in data_to_patch:
                data_to_patch[key] = value
            else:
                patched_value = data_to_patch[key]

                # All data types other than lists are replaced - all or nothing, not merged.
                # For lists alone, we support specifying subset of the list that will get merged with the
                # existing entries based on "_key" or "id" fields. This is required by RBAC to support ACL enforcement
                # on sub-objects that a user role may not have access to even if it has access to the parent object
                if utils.is_valid_list(value) and utils.is_valid_list(patched_value):
                    for list_entry in value:
                        if utils.is_valid_dict(list_entry):
                            # Indicates need to merge sub-object as a dict identified by "id" or "_key"
                            found = False
                            if 'id' in list_entry:
                                for patched_entry in patched_value:
                                    if patched_entry.get('id') == list_entry['id']:
                                        found = True
                                if not found:
                                    data_to_patch[key].append(list_entry)
                            elif '_key' in list_entry:
                                for patched_entry in patched_value:
                                    if patched_entry.get('_key') == list_entry['_key']:
                                        found = True
                                if not found:
                                    data_to_patch[key].append(list_entry)
                            # else skip - no other way to identify sub-objects to merge
                        # else skip - no other data types could be merged

        # Now process fields/values marked for delete
        for key, value in marked_for_delete.iteritems():
            if key == '_entire_fields':
                if not utils.is_valid_list(value):
                    continue
                for key_to_delete in value:
                    if utils.is_valid_str(key_to_delete) and (key_to_delete in data_to_patch):
                        del data_to_patch[key_to_delete]
            else:
                # All other delete markings are for values.
                # All data types other than lists do not support partial deletes in values.
                # For lists alone, we support specifying subset of the list that will get deleted
                # based on "_key" or "id" fields. This is required by RBAC to support ACL enforcement
                # on sub-objects that a user role may not have access to even if it has access
                # to the parent object
                if (not utils.is_valid_list(data_to_patch.get(key))) or (not utils.is_valid_list(value)):
                    # Ignore partial deletes for any non-list values
                    continue

                for value_to_delete in value:
                    if utils.is_valid_dict(value_to_delete):
                        # Indicates need to delete sub-objects as a collection of dicts
                        # identified by "id" or "_key"

                        if ('id' not in value_to_delete) and ('_key' not in value_to_delete):
                            # No sub-object identified, skip
                            continue

                        if ('id' in value_to_delete) and utils.is_valid_str(value_to_delete['id']):
                            data_to_patch[key] = [
                                value_to_keep for value_to_keep in data_to_patch[key]
                                if not ((('id' in value_to_keep) and
                                         utils.is_valid_str(value_to_keep['id']) and
                                         value_to_delete['id'] == value_to_keep['id']
                                        ))
                                ]
                        elif ('_key' in value_to_delete) and utils.is_valid_str(value_to_delete['_key']):
                            data_to_patch[key] = [
                                value_to_keep for value_to_keep in data_to_patch[key]
                                if not ((('_key' in value_to_keep) and
                                         utils.is_valid_str(value_to_keep['_key']) and
                                         value_to_delete['_key'] == value_to_keep['_key']
                                        ))
                                ]

                    # else skip - no other data types support partial deletes

        if '_marked_for_delete' in data_to_patch:
            del data_to_patch['_marked_for_delete']

    def _patch_partial_data_list(self, owner, objects, transaction_id=None):
        """
        Patch partial data for objects by merging with existing object content
        Used to support partial updates since KV store API does not support partial updates directly
        @type owner: string
        @param owner: user who is performing this operation
        @type objects: list[dict]
        @param objects: json payload of objects being updated
        @rtype: None
        @return: None
        """
        object_ids = []
        for json_data in objects:
            if utils.is_valid_str(json_data.get('_key')):
                # Only updates need to be patched, so skip data without keys indicating create payload
                object_ids.extend([json_data['_key']])
        ids_filter = self.get_filter_data_for_keys(object_ids=object_ids)

        existing_data_list = self.get_bulk(owner, filter_data=ids_filter, transaction_id=transaction_id)

        for existing_data in existing_data_list:
            data_to_patch = None

            # The object wasnt found in the latter portion of the array, search the first part of the array
            for obj in objects:
                if obj.get('_key') == existing_data.get('_key'):
                    data_to_patch = obj
                    break

            if data_to_patch is None:
                # No patchable data found, move on
                continue

            self._patch_partial_data(data_to_patch, existing_data, transaction_id=transaction_id)

    # pylint: disable = unused-argument
    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        """
        Identify dependency and create refresh jobs if it is required
        @type owner: string
        @param {string} owner: user which is performing this operation
        @type objects: list
        @param objects: the objects to validate for dependency
        @type method: string
        @param method: method name
        @type req_source: string
        @param req_source: request source
        @rtype: tuple
        @return:
            {boolean} set to true/false if dependency update is required
            {list} list - list of refresh job
        """
        # Default no dependency update required
        return False, []
    # pylint: enable = unused-argument

    def get_refresh_job_meta_data(self, change_type, changed_object_key, changed_object_type, change_detail=None, transaction_id=None):
        """
        Returns metadata for this object type for refresh operation
        @type change_type: str
        @param change_type: type of change operation needing refresh
        @type changed_object_key: list
        @param changed_object_key: id of object changed that is needing refresh
        @type changed_object_type: str
        @param changed_object_type: type of object changed that is needing refresh
        @type change_detail: dict
        @param change_detail: metadata for details of change needing refresh
        @type change_detail: dict
        @param transaction_id: The item which traces where a request comes from
        @type transaction_id: string
        @return: dictionary containing the metadata to aid refresh operation for the change, throws exceptions on errors
        """
        change_detail = {} if change_detail is None else change_detail
        return {
            'change_type': change_type,
            'changed_object_key': changed_object_key,
            'changed_object_type': changed_object_type,
            'change_detail': change_detail,
            'transaction_id': transaction_id
        }

    def create_refresh_jobs(self, refresh_jobs, synchronous=False):
        """
        Creates a refresh job for this object type based on passed in refresh requests
        @type refresh_jobs: list of dictionary
        @param refresh_jobs: refresh job metadata for jobs needed to be created
        @type synchronous: Boolean
        @param synchronous: Indicates whether or not to process these refresh jobs synchronously
        @return: none, throws exceptions on errors
        """
        adapter = itoa_refresh_queue_utils.RefreshQueueAdapter(self.session_key)
        for refresh_job in refresh_jobs:
            is_success = adapter.create_refresh_job(
                    refresh_job.get('change_type'),
                    refresh_job.get('changed_object_key'),
                    refresh_job.get('changed_object_type'),
                    change_detail=refresh_job.get('change_detail', {}),
                    transaction_id=refresh_job.get('transaction_id'),
                    synchronous=synchronous
            )
            if not is_success:
                logger.error("Failed tid=%s job=%s", refresh_job.get('transaction_id'), refresh_job.get('changed_object_key'))
            else:
                logger.info("Successfully create refresh tid=%s job=%s", refresh_job.get('transaction_id'), refresh_job.get('changed_object_key'))

    # pylint: disable = unused-argument
    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Optional method to be implemented in derived classes of specific object types to do additional setup
        before a write operation (create or update) is invoked on this object
        @type owner: string
        @param owner: user who is performing this operation
        @type objects: list of dictionary
        @param objects: list of objects being written
        @type req_source: string
        @param req_source: string identifying source of this request
        @return: none, throws exceptions on errors
        """
        return


    # pylint: disable = unused-argument
    def post_save_setup(self, owner, ids, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Optional method to be implemented in derived classes of specific object types to do additional setup
        after a write operation (create or update) is invoked on this object
        @type owner: string
        @param owner: user who is performing this operation
        @type ids: List of dict identifiers in format {"_key": <key>} returned by kvstore, pairity with objects passed in
        @param ids: list of dict
        @type objects: list of dictionary
        @param objects: list of objects being written
        @type req_source: string
        @param req_source: string identifying source of this request
        @return: none, throws exceptions on errors
        """
        return

    # pylint: disable = unused-argument
    def can_be_deleted(self, owner, objects, raise_error=False, transaction_id=None):
        """
        Optional method to be implemented in derived classes of specific object types to filter out objects that could not be deleted
        @type owner: string
        @param {string} owner: user which is performing this operation
        @type objects: list
        @param objects: the objects to validate for dependency
        @type raise_error: boolean
        @param raise_error:  if true, an error will be raised if no objects could be deleted
        @rtype: list
        @return: list - list of deletable objects
        """
        # Default return all objects
        return objects
    # pylint: enable = unused-argument

    # pylint: enable = unused-argument
    def extract_json_data(self, data):
        """
        Converts data passed in to valid json
        @type data: dictionary or basestring
        @param data: object being extracted
        @rtype: dictionary
        @return: json formatted data, throws exceptions on errors
        """
        json_data = utils.validate_json(self.log_prefix, data)

        def fix_mod_source(json_data_obj):
            if not utils.is_valid_str(json_data_obj.get('mod_source', None)):
                json_data_obj.update({'mod_source': 'unknown'})

        if utils.is_valid_dict(json_data):
            fix_mod_source(json_data)
        else: # MUST be list
            for json_data_item in json_data:
                fix_mod_source(json_data_item)

        return json_data

    def refresh(self, owner, options, transaction_id=None):
        """
        Refresh method used by callers to invoke a refresh on an object without
        updating impacted objects

        @param owner: the owner to work with, usually nobody
        @type owner: str
        @param options: options for the refresh, for now just a filter data for a bulk refresh
        @type options: dict

        @return: the results of the original get prior to refresh
        @rtype: list or dict
        """
        logger.debug("Calling refresh on objects with owner=%s, options=%s", owner, options)
        transaction_id = self.instrument.push("itoa_object.refresh", transaction_id=transaction_id, owner=owner)

        filter_data = options.get('filter_data', {})
        results = self.get_bulk(
            owner,
            filter_data=filter_data,
            req_source='REST_refresh',
            transaction_id=transaction_id
            )
        if results:
            self.save_batch(
                owner,
                results,
                validate_names=False,
                req_source='REST_refresh',
                ignore_refresh_impacted_objects=True,
                transaction_id=transaction_id
                )
            return results

        self.instrument.pop("itoa_object.refresh", transaction_id)
        return []

    @staticmethod
    def get_filter_data_for_keys(object_ids=None):
        """
        Constructs a mongodb filter string to lookup all objects with the specified ids
        @type object_ids: list of strings
        @param object_ids: ids of objects
        @rtype: dictionary
        @return: json filter constructed for ids, throws exceptions on errors
        """
        if object_ids is None:
            object_ids = []

        if not utils.is_valid_list(object_ids):
            raise AttributeError(_('object_ids is invalid: {0}').format(object_ids))

        filter_data = None
        if len(object_ids) > 0:
            filter_data = {'$or': [{'_key': object_id} for object_id in object_ids]}
        return filter_data

    def get_persisted_objects_by_id(self, owner, object_ids=[], req_source='unknown', transaction_id=None, fields=None):
        """
        Retrieves all object with the specified ids
        @type owner: string
        @param owner: user who is performing this operation
        @type object_ids: list of strings
        @param object_ids: list of ids of objects being retrieved
        @type req_source: string
        @param req_source: string identifying source of this request
        @type transaction_id: string
        @param transaction_id: unique identifier of a user transaction
        @type fields: list
        @param fields: list of field names to fetch, None if all
        @type: list of dictionaries
        @return: objects retrieved for the ids, throws exceptions on errors
        """
        persisted_objects = []
        # bucket_size must be kept as int when used for indexes later on (~line 1330) else it will break
        bucket_size = 1000
        # kvstore cannot handle massive filter strings, so let's paginate this fetch
        if len(object_ids) > bucket_size:
            logger.debug('Trying to get %s must paginate that request', len(object_ids))
            # use a float for bucket_size to provide a variance in return values when calculating num_buckets, which uses math.ceil.
            num_buckets = int(math.ceil(len(object_ids) / float(bucket_size)))
            for i in range(num_buckets):
                start_idx = i * bucket_size
                end_idx = start_idx + bucket_size
                logger.debug('Fetching objects between: ' + str(start_idx) + ' - ' + str(end_idx))
                filter_data = self.get_filter_data_for_keys(object_ids[start_idx:end_idx])
                persisted_objects += self.get_bulk(owner,
                                                   filter_data=filter_data,
                                                   fields=fields,
                                                   req_source=req_source,
                                                   transaction_id=transaction_id)
        else:  # yay! a reasonable amount get it in one shot
            logger.debug('Fetching ' + str(len(object_ids)) + ' objects in a single request')
            filter_data = self.get_filter_data_for_keys(object_ids)
            persisted_objects = self.get_bulk(owner,
                                              filter_data=filter_data,
                                              fields=fields,
                                              req_source=req_source,
                                              transaction_id=transaction_id)
        return persisted_objects
