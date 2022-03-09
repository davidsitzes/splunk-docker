# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Exposes Cherrypy/Splunkweb endpoints that do basic CRUD on objects for maintenance purposes
"""

import sys
import json

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
import ITOA.itoa_common as utils
from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import handle_exceptions
from ITOA.itoa_exceptions import ItoaValidationError
from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ObjectOperation, ITOAError

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))

logger = setup_logging("backup_restore.log", "backup_restore.BackupRestoreRestProvider")
logger.debug("Initialized backup restore log")

class BackupRestoreObjectOperation(ObjectOperation):
    """
    This class provides overridden implementation for delete and bulk delete operations.
    To be used for backup_restore object operations in backup_restore_rest_provider.
    """
    
    def __init__(self, logger, session_key, current_user):
        self.logger = logger
        self.session_key = session_key
        self.current_user = current_user
        super(BackupRestoreObjectOperation, self).__init__(logger, session_key, current_user)

    def create(self, log_prefix, owner, object_type, kwargs, raw=False):
        """
        Generic create. Overwrite the base method for scheduled backup. 
        Raise 500 error if user tries to create more than one scheduled backups.
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; like "service", "entity", "kpi" or "saved_page"
        @param kwargs: The original kwargs passed from cherrypy - here we get the identifier and the data

        @return: json with identifier
        @rval: json string
        """

        results = None
        obj = self.instantiate_object(object_type)
        data = utils.validate_json(log_prefix, kwargs.get('data'))

        # check if the object data is scheduled backup
        if data.get('scheduled') == 1:
            # if one scheduled backup is already created, do not allow user to create another
            status_filter = {'scheduled': 1}
            collection = obj.get_bulk(
                owner,
                filter_data=status_filter,
                )
            if len(collection) == 1:
                message = _('Only one default scheduled backup is allowed.')
                raise ITOAError(status='500', message=message)

        results = obj.create(owner, kwargs.get('data'))
        if raw:
            return results
        else:
            return self.render_json(results)

    def delete(self, log_prefix, owner, object_type, object_id, kwargs):
        """
        Generic delete for an existing object. When the object status is 'In Progress' raise a 400 error.
        @param self: The self reference
        @param log_prefix: The originating log_prefix, passed in here to ease tracking down problems
        @param object_type: The type of the object; "backup_restore" in this case
        @param id_: The identifier for the object to delete
        @param kwargs: The original kwargs passed from cherrypy

        @return: status json and identifier
        @rval: None (a successful delete just returns 200)
        """
        if not utils.is_valid_str(object_id):
            message = _("Missing identifier")
            self.logger.error(log_prefix + message)
            raise ITOAError(status="400", message=message)
        try:
            obj = self.instantiate_object(object_type)
            result = obj.get(owner, object_id, 'REST')

            # if job is in progress, raise exception
            if result.get('status') == 'In Progress':
                raise ItoaValidationError(_('Unable to delete this job since it is currently in progress. '
                                            'Please try again later.'), self.logger)
            # if Force-Delete is not true in header and object is _immutable raise exception
            if kwargs.get('X-Force-Delete') != 'true' and (result.get('_immutable') == 1 or result.get('scheduled') == 1):
                raise ItoaValidationError(self.IMMUTABLE_OBJECT_ERROR_MESSAGE, self.logger)
            obj.delete(owner, object_id, 'REST')
        except ItoaValidationError as exc:
            self.logger.exception(exc)
            raise ITOAError(status="400", message=str(exc))
        except Exception as exc:
            self.logger.exception(exc)
            raise ITOAError(status="500", message=str(exc))

    def delete_bulk(self, log_prefix, owner, object_type, kwargs):
        '''
        Perform a bulk delete operation. Skip over objects that have status='In Progress'.

        @param log_prefix: Logger prefix
        @type log_prefix: string

        @param owner: The method caller
        @type owner: The method owner

        @param object_type: The ITOA object type
        @type object_type: string

        @param kwargs: Optional arguments
        @type kwargs: dict
        '''
        self.logger.debug("DELETE objects=%s owner=%s, kwargs=%s", object_type, owner, kwargs)

        filter_data = kwargs.get('filter')
        self.logger.debug("filter_data=%s", filter_data)
        try:
            if filter_data is not None:
                filter_data = json.loads(filter_data)
                filter_data.update({'status': {'$ne': 'In Progress'}})

                # If X-Force-Delete header is not true, process filter_data to delete only mutable objects
                # kwargs has 'X-Force-Delete' from the headers extracted by endpoint handlers
                if kwargs.get('X-Force-Delete') != 'true':
                    # Append mutability check to filter
                    filter_data.update({'_immutable': {'$ne': 1}})
                    filter_data.update({'scheduled': {'$ne': 1}})

                    # Privatizable objects with RBAC checks need mutability checks in filter_string too
                    if filter_data.get('filter_string') is not None and isinstance(filter_data['filter_string'], dict):
                        filter_data['filter_string'].update({'_immutable': {'$ne': 1}})
                        filter_data['filter_string'].update({'scheduled': {'$ne': 1}})
            else:
                filter_data = {'status': {'$ne': 'In Progress'}}
                # If filter_data is None and X-Force-Delete Header is not true, delete only mutable objects
                if kwargs.get('X-Force-Delete') != 'true':
                    filter_data.update({'_immutable': {'$ne': 1}})
                    filter_data.update({'scheduled': {'$ne': 1}})
        except ValueError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "ValueError not parse filterdata=%s", filter_data)
            filter_data = None
        except TypeError, exc:
            self.logger.exception(exc)
            self.logger.error(log_prefix + "TypeError not parse filterdata=%s", filter_data)
            filter_data = None

        try:
            obj = self.instantiate_object(object_type)
            obj.delete_bulk(owner, filter_data, req_source='REST')
        except Exception as exc:
            self.logger.exception(exc)
            raise ITOAError(status="500", message=str(exc))

class BackupRestoreRestProvider(ItoaInterfaceProviderBase):
    """
    Provides backend interaction via REST for backup restore operations like CRUD for backup restore job
    configuration
    """

    SUPPORTED_OBJECT_TYPES_FOR_CRUD = ['backup_restore']
    SUPPORTED_OBJECT_TYPES = SUPPORTED_OBJECT_TYPES_FOR_CRUD + ['files']

    def _bulk_crud(self, owner, object_type, **kwargs):
        """
        CRUD interface for backup/restore jobs

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: backup/restore object type

        @param: dict
        @param **kwargs: key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        """
        with handle_exceptions():
            LOG_PREFIX = '[CRUD General] '
            if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_CRUD:
                raise ITOAError(
                    status=400,
                    message=_('Invalid object type, supported object types are %s.') % self.SUPPORTED_OBJECT_TYPES_FOR_CRUD
                )

            op = BackupRestoreObjectOperation(logger, self._session_key, self._current_user)
            if self._rest_method in ['POST', 'PUT']:
                result = op.create(LOG_PREFIX, owner, object_type, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'GET':
                result = op.get_bulk(LOG_PREFIX, owner, object_type, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'DELETE':
                op.delete_bulk(LOG_PREFIX, owner, object_type, kwargs)
            else:
                raise ITOAError(
                    status=500,
                    message=_('Invalid method. Valid methods are GET, POST, PUT and DELETE.')
                )

    def _get_object_count(self, owner, object_type, **kwargs):
        """
        Get the object count

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: backup/restore object type

        @param: dict
        @param **kwargs: key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)

        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="500", message=_("Unsupported HTTP method %s.") % self._rest_method)

            if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_CRUD:
                raise ITOAError(
                    status=400,
                    message=_('Invalid object type, supported object types are %s.') % self.SUPPORTED_OBJECT_TYPES_FOR_CRUD
                )

            filter_data = kwargs.get('filter', None)
            logger.debug("filter_data=%s", filter_data)
            try:
                if filter_data is not None:
                    filter_data = json.loads(filter_data)
            except ValueError, e:
                logger.exception("ValueError not parse filterdata=%s", filter_data)
                filter_data = None
            except TypeError, e:
                logger.exception("TypeError not parse filterdata=%s", filter_data)
                filter_data = None
            storage_interface = self._get_storage_interface(object_type)
            count = storage_interface.get_count(self._session_key, owner, object_type, filter_data)
            return self.render_json(count)

    def _crud_by_id(self, owner, object_type, object_id, **kwargs):
        """
        CRUD operations for backup/restore objects by their identifiers

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: backup/restore object type

        @type: string
        @param object_id: existing backup/restore object identifier

        @param: dict
        @param **kwargs: key word arguments extracted from the POST body

        @rtype: dict
        @return: json with object
        """
        with handle_exceptions():
            LOG_PREFIX = '[CRUD by id] '

            op = BackupRestoreObjectOperation(logger, self._session_key, self._current_user)
            if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_CRUD:
                raise ITOAError(
                    status=400,
                    message=_('Invalid object type, supported object types are %s.') % self.SUPPORTED_OBJECT_TYPES_FOR_CRUD
                )
            if self._rest_method in ['POST', 'PUT']:
                result = op.edit(LOG_PREFIX, owner, object_type, object_id, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'GET':
                retval = op.get(LOG_PREFIX, owner, object_type, object_id, kwargs, raw=True)
                if retval is None:
                    raise ITOAError(status=404, message=_("Object not found."))
                try:
                    return self.render_json(retval)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'DELETE':
                op.delete(LOG_PREFIX, owner, object_type, object_id, kwargs)
            else:
                raise ITOAError(
                    status=405,
                    message=_('Invalid method. Valid methods are GET, POST, PUT and DELETE.')
                )
