# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json
from uuid import uuid1
from copy import deepcopy
from contextlib import contextmanager

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.auth import getCurrentUser
from splunk import RESTException

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.objects.itsi_service import ItsiService
from itsi.searches import itsi_filter
from itsi.searches.itsi_searches import ItsiKpiSearches
import ITOA.itoa_common as utils
from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.itoa_config import get_collection_name_for_itoa_object
from ITOA.itoa_exceptions import ItoaError, ItoaAccessDeniedError, ItoaValidationError
from ITOA.setup_logging import setup_logging
from ITOA.storage.statestore import StateStoreError
import SA_ITOA_app_common.splunklib.client as client

from ITOA.controller_utils import (
    ObjectOperation,
    ITOAError,
    check_object_update_allowed
)
from itsi.csv_import import itoa_csv_loader
from itsi.objects.itsi_entity import bulk_entity_update_tags
from itsi.objects.itsi_entity_relationship import get_neighbors
from itsi.service_template.service_template_utils import ServiceTemplateUtils
from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from ITOA.service_tree import generate_subgraphs_json

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess

logger = setup_logging("itsi.log", "itsi.controllers.itoa_rest_interface_provider")
logger.debug("Initialized itoa interface provider log")

@contextmanager
def handle_exceptions():
    """
    Context manager wrapper to handle exception using with for code agility
    """
    try:
        yield
    except ITOAError:
        # Error was already a properly formatted HTTP error (at least for cherrypy)
        raise
    except (TypeError, ValueError, ItoaValidationError) as e:
        logger.exception(e)
        status = e.status_code or 400
        raise ITOAError(status=status, message=e.message)
    except ItoaAccessDeniedError as e:
        logger.exception(e)
        raise ITOAError(status=403, message=e.message)
    except ItoaError as e:
        raise ITOAError(status=500, message=str(e))
    except RESTException as e:
        logger.exception(e)
        raise ITOAError(status=e.statusCode, message=str(e))
    except StateStoreError as e:
        # these exceptions should already be logged, the stacktrace here might be confusing in debugging
        status = e.status_code or 500
        raise ITOAError(status=status, message=str(e))
    except Exception as e:
        logger.exception(e)
        raise ITOAError(status=500, message=str(e))

def get_interactable_object_types():
    """
    method returns object types that are interactable
    i.e. drill down on glass table and so on

    @rtype: list of strings
    @return: names of object types
    """
    return ['home_view',
            'glass_table',
            'deep_dive',
            'notable_event_aggregation_policy',
            'correlation_search']

def get_supported_itoa_object_types():
    """
    Method returns a list of supported ITOA object types in the backend...

    @rtype: list of strings
    @return: names of object types
    """
    return [
        'team',
        'entity',
        'service',
        'base_service_template',
        'kpi',
        'kpi_base_search',
        'saved_page',
        'deep_dive',
        'glass_table',
        'home_view',
        'kpi_template',
        'kpi_threshold_template',
        'temporary_kpi',
        'event_management_state',
        'entity_relationship',
        'entity_relationship_rule'
        ]

def get_privatizeable_object_types():
    """
    method that returns a list of object types that can have a `private`
    ownership vs `public` ownership

    @rtype: list of strings
    @return: names of object types
    """
    return ['home_view', 'glass_table', 'deep_dive']

class ItoaInterfaceProvider(ItoaInterfaceProviderBase):
    """
    Base provider implementing services for REST API for ITOA interface
    It primarily consists of CRUD/bulk actions to configure and use basic ITSI objects like entities, services, etc.
    Specific REST handlers derive from this class to fit functionality to specific REST handling
    """
    SUPPORTED_OBJECT_TYPES = get_supported_itoa_object_types()
    SUPPORTED_OBJECT_TYPES_FOR_BY_ID_OPS = [
        object_type for object_type in SUPPORTED_OBJECT_TYPES if object_type != 'kpi'
        ]
    SUPPORTED_OPERATIONS = utils.get_supported_itoa_operations()
    OBJECT_TYPES_NON_UPDATEABLE_DURING_BACKUP_RESTORE = [
        'team',
        'entity',
        'service',
        'kpi',
        'kpi_template',
        'kpi_base_search'
    ]

    INTERNAL_ONLY_OBJECT_TYPES = ['kpi', 'temporary_kpi', 'saved_page']
    PUBLIC_OBJECT_TYPES = [
        object_type for object_type in SUPPORTED_OBJECT_TYPES if object_type not in INTERNAL_ONLY_OBJECT_TYPES
        ]

    ###############################################################################
    # Basic CRUD routing
    ###############################################################################

    def _perms(self, object_type, **kwargs):
        """
        Invoke this method to update permissions on a bunch of object ids

        @type: object
        @param self: The self reference

        @type: string
        @param object_type: the ITOA object type

        @type kwargs: dictionary
        @params kwargs: object ids and permissions for these objects
            Mandatory keys: objects, acl
                     types: list, dict

        @rtype: json
        @returns json data on success
        @raises ITOAError on failure
        """
        with handle_exceptions():
            if self._rest_method not in ['GET', 'PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method"))
            allowable_types = get_interactable_object_types()

            # first validate...
            if object_type not in allowable_types:
                message = _('Perms can only be set for `%s`. Received: %s.') % (
                    allowable_types, object_type)
                logger.error(message)
                raise ITOAError(status=400, message=message)

            data = utils.get_object(kwargs.get('data'))
            if not data:
                message = _('No data received. `data` is a mandatory key. Received:'
                           ' %s') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)
            if 'acl' not in data or 'objects' not in data:
                message = _('`acl` & `objects` are mandatory keys in data.'
                           ' Received: %s') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)

            acl = utils.get_object(data.get('acl'))
            if 'read' not in acl or 'write' not in acl:
                message = _('`acl` is missing mandatory keys `read`/`write`.'
                           ' Received: %s') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)

            if 'delete' not in acl:
                # no explicit perms for `delete` set. lets use the ones for `write`
                acl['delete'] = deepcopy(acl['write'])

            objects = utils.get_object(data.get('objects'))
            o_store = get_collection_name_for_itoa_object(object_type)
            logger.info(('Received request to update ACL for objects: `{}`'
                         '. ACL:`{}`').format(acl, objects))
            rval = {'updated': False, 'objects': objects, 'acl': acl}

            try:
                success, msg = UserAccess.bulk_update_perms(
                    objects, acl, 'itsi', object_type,
                    o_store, self._session_key, logger,
                    data.get('object_owner', 'nobody'),
                    data.get('object_shared_by_inclusion', True),
                    replace_existing=True)
            except Exception as e:
                message = _('Internal Exception. Input: `{0}` Method: `{1}`.'
                            ' See internal logs.').format(kwargs, self._rest_method)
                logger.exception(e)
                raise ITOAError(status=500, message=message)

            if success:
                rval['message'] = _('Successfully updated permissions.')
                rval['updated'] = True
                logger.debug('Successfully updated permissions')
            else:
                message = _('Failed to update permissions. %s. See internal logs.') % msg
                logger.error(message)
                raise ITOAError(status=500, message=message)
            return self.render_json(rval)

    def _perms_by_id(self, object_type, object_id, **kwargs):
        """
        invoke this endpoint to fetch/update permissions on objects.
        Only users with an `admin` role will be able to do stuff.

        @type: object
        @param self: The self reference

        @type object_type: string
        @param actin: the ITOA object type

        @type: string
        @param self: the object id

        @type kwargs: dict
        @param kwargs: permissions for an object or list of objects

        @rtype: json
        @returns json data on success
        @raises ITOAError on failure
        """
        with handle_exceptions():
            if self._rest_method not in ['GET', 'PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method"))

            data = None
            acl = None

            allowable_types = get_interactable_object_types()

            # first validate...
            if object_type not in allowable_types:
                message = _('permissions can only be set for `%s`. Received: %s') % (
                    allowable_types, object_type)
                logger.error(message)
                raise ITOAError(status=400, message=message)

            c = client.connect(token=self._session_key)
            available_role = [role.name for role in c.roles]

            if self._rest_method == 'POST':
                data = utils.get_object(kwargs.get('data'))
                # do validations specific to this endpoint
                if not data:
                    logger.error('No Data received.')
                    raise ITOAError(status=400, message=_('No data received'))
                if not data.get('acl'):
                    message = _('Missing key in data. `acl` on POST is mandatory'
                                '. Received: `{}`').format(kwargs)
                    logger.error(message)
                    raise ITOAError(status=400, message=message)

                acl = utils.get_object(data['acl'])
                if 'read' not in acl or 'write' not in acl:
                    message = _('`acl` is missing mandatory keys `read`/`write`.'
                                ' Received: %s') % kwargs
                    logger.error(message)
                    raise ITOAError(status=400, message=message)

            rval = {'updated': False, 'id': object_id, 'acl': acl}
            o_store = get_collection_name_for_itoa_object(object_type)

            if self._rest_method == 'POST':
                logger.debug('Request to update perms for %s', object_id)

                # lets normalize acl data to an object
                # we expect itsi to not sent us any `delete` specific data
                # SA-UserAccess expects it..so lets add it
                logger.debug('data[acl]: %s' % data['acl'])
                acl = deepcopy(data['acl'])
                acl = utils.get_object(acl)

                # we need to be careful here, if write is [], it will change
                # permission for other user too. Thats why we need to factor
                # existing permission and substract with roles that user has
                # access to
                existing_role = UserAccess.get_perms(object_id, 'itsi', object_type,
                                                     o_store, self._session_key, logger)

                if not acl['write']:
                    acl['write'] = list(filter(lambda role: role not in available_role, existing_role['write']))

                if not acl['read']:
                    acl['read'] = list(filter(lambda role: role not in available_role, existing_role['read']))

                if 'delete' not in acl:
                    # no explicit perms for `delete` set.
                    # lets use the ones for `write`
                    acl['delete'] = deepcopy(acl['write'])

                try:
                    success, msg = UserAccess.bulk_update_perms(
                        [object_id], acl, 'itsi', object_type,
                        o_store, self._session_key, logger,
                        data.get('object_owner','nobody'),
                        data.get('object_shared_by_inclusion',True),
                        replace_existing=True)
                except Exception as e:
                    message = _('Internal Exception. Input: `{0}` Method: `{1}`.'
                                ' See internal logs.').format(kwargs, self._rest_method)
                    logger.exception(e)
                    raise ITOAError(status=500, message=message)

                if success:
                    rval['message'] = _('Successfully updated permissions.')
                    rval['updated'] = True
                    logger.debug('Successfully updated perms')
                else:
                    message = _('Failed to update permissions. %s. See internal logs.') % msg
                    logger.error(message)
                    raise ITOAError(status=500, message=message)
            else: # GET
                logger.debug('Request to get perms for %s', object_id)
                rval['message'] = _('No permissions were found.')
                try:
                    perms = UserAccess.get_perms(object_id, 'itsi', object_type,
                                                 o_store, self._session_key, logger)
                except Exception as e:
                    message = _('Internal Exception. Input: `{0}` Method: `{1}`.'
                                ' See internal logs.').format(kwargs, self._rest_method)
                    logger.exception(e)
                    raise ITOAError(status=500, message=message)
                if perms:
                    rval['message'] = _('Perms found.')
                    rval['acl'] = perms
            return self.render_json(rval)

    def get_supported_object_types_json(self):
        """
        An app or an SA might want to query the supported object types
        Return a list of supported object types
        No Access Control enforcement on this endpoint...

        @type: object
        @param self: The self reference

        @rtype: list
        @return: an array of supported object types
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="405", message=_("Unsupported HTTP method"))

            return self.render_json(self.PUBLIC_OBJECT_TYPES)

    def _crud_common_checks(self, owner, object_type):
        if object_type not in self.SUPPORTED_OBJECT_TYPES:
            raise ITOAError(status="405", message=_("Unsupported object type %s.") % str(object_type))
        if object_type in ["entity", "service", "kpi", "kpi_template"] and owner != "nobody":
            raise ITOAError(status="400",
                            message=_("Entities, Services, and KPIs can only exist at app level (user='nobody') - %s.") % owner)

        if (object_type in self.OBJECT_TYPES_NON_UPDATEABLE_DURING_BACKUP_RESTORE) and (self._rest_method != 'GET'):
            check_object_update_allowed(self._session_key, logger)

    def _get_bulk(self, owner, object_type, **kwargs):
        """
        Method to get objects

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json with object collection (for GET)
        """
        with handle_exceptions():
            LOG_PREFIX = '[crud_general] '
            self._crud_common_checks(owner, object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            result = op.get_bulk(LOG_PREFIX, owner, object_type, kwargs, raw=True)
            return self.render_json(result)

    def _delete_bulk(self, owner, object_type, **kwargs):
        """
        Method to delete objects

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: None
        @return: None
        """
        with handle_exceptions():
            if self._rest_method != 'DELETE':
                raise ITOAError(status="405", message=_("Unsupported HTTP method"))

            LOG_PREFIX = '[crud_general] '
            self._crud_common_checks(owner, object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            # no need to return anything on DELETE
            op.delete_bulk(LOG_PREFIX, owner, object_type, kwargs)

    def _create_or_update(self, owner, object_type, **kwargs):
        """
        Method to create or update objects

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json with identifier (for POST or PUT)
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[crud_general] '
            self._crud_common_checks(owner, object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            result = op.create(LOG_PREFIX, owner, object_type, kwargs, raw=True)
            return self.render_json(result)

    def _refresh_object(self, owner, object_type, **kwargs):
        """
        CRUD interface for IT context objects to refresh without causing
        related objects to refresh to the change - used by UI primarily

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: None
        @return: None
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[object_refresh] '

            op = ObjectOperation(logger, self._session_key, self._current_user)

            if object_type not in self.SUPPORTED_OBJECT_TYPES:
                raise ITOAError(status="400", message=_("Unsupported object_type type %s.") % str(object_type))
            if object_type in ["entity", "service", "kpi_template"] and owner != "nobody":
                raise ITOAError(status="400",
                                message=_("Entities, Services, and KPI templates can only exist at app level (user='nobody')."))

            options = {}

            if object_type in self.OBJECT_TYPES_NON_UPDATEABLE_DURING_BACKUP_RESTORE:
                check_object_update_allowed(self._session_key, logger)

            if kwargs.get('data') != None:
                options = utils.validate_json(LOG_PREFIX, kwargs.get('data'))
            logger.debug("Calling refresh method")
            result = op.refresh(LOG_PREFIX, owner, object_type, options, raw=True)
            return self.render_json(result)

    def _get_object_count(self, owner, object_type, **kwargs):
        """
        Get the object count

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json with count
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            filter_data = kwargs.get('filter', None)
            logger.debug("filter_data=%s", filter_data)
            try:
                if filter_data != None:
                    filter_data = json.loads(filter_data)
            except ValueError,e:
                logger.exception("ValueError not parse filterdata=%s", filter_data)
                filter_data = None
            except TypeError,e:
                logger.exception("TypeError not parse filterdata=%s", filter_data)
                filter_data = None
            self._crud_common_checks(owner, object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            kwargs['fields'] = ['_key']
            result = op.get_bulk('Get Bulk Count ', owner, object_type, kwargs, raw=True)
            return self.render_json({'count': len(result) if isinstance(result, list) else 0})

    def _crud_by_id_common_checks(self, object_type):
        if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_BY_ID_OPS:
            # CRUD by ID not supported for KPIs for example
            raise ITOAError(status="405", message=_("Unsupported object type %s.") % str(object_type))

        if (object_type in self.OBJECT_TYPES_NON_UPDATEABLE_DURING_BACKUP_RESTORE) and (self._rest_method != 'GET'):
            check_object_update_allowed(self._session_key, logger)

    def _get_by_id(self, owner, object_type, object_id, **kwargs):
        """
        method to get object by id

        Entity specific create - Just defines an endpoint that calls the generic version

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: string
        @param object_id: the id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[crud_general] '
            logger.debug("object=%s, id=%s, kwargs=%s", object_type, object_id, kwargs)
            self._crud_by_id_common_checks(object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)

            logger.debug("Getting object with id_=%s", object_id)
            retval = op.get(LOG_PREFIX, owner, object_type, object_id, kwargs, raw=True)
            if retval == None:
                raise ITOAError(status=404, message=_("Object not found."))
            if object_type in get_interactable_object_types():
                capability = CAPABILITY_MATRIX.get(object_type).get('interact')
                interactable = UserAccess.is_user_capable(
                    self._current_user,
                    capability,
                    self._session_key,
                    logger,
                    owner
                )
                retval['interactable'] = interactable
                logger.debug('Object:%s Interactable:%s', object_type, str(interactable))
            logger.debug("Returning %s", retval)
            return self.render_json(retval)

    def _update_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Update existing object by id

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: string
        @param object_id: the id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[crud_general] '
            logger.debug("object_type=%s, id=%s, kwargs=%s", object_type, object_id, kwargs)
            self._crud_by_id_common_checks(object_type)

            logger.debug("Updating object_type with id=%s", object_id)
            op = ObjectOperation(logger, self._session_key, self._current_user)
            if self._rest_method == 'PUT':
                result = op.edit(LOG_PREFIX, owner, object_type, object_id, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'POST': # create new object_type
                logger.debug("Calling POST")
                # home_view is the only object_type type without a collection, so allow model to be created
                if object_type == 'home_view':
                    result = op.create(LOG_PREFIX, owner, object_type, kwargs, raw=True)
                    try:
                        return self.render_json(result)
                    except (TypeError, ValueError) as e:
                        logger.exception(e)
                        raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
                # Normal handling of POST
                result = op.edit(LOG_PREFIX, owner, object_type, object_id, kwargs, raw=True)
                return self.render_json(result)

    def _delete_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Method to delete object by id

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: string
        @param object_id: the id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        """
        with handle_exceptions():
            if self._rest_method != 'DELETE':
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[crud_general] '
            logger.debug("object_type=%s, id=%s, kwargs=%s", object_type, object_id, kwargs)
            self._crud_by_id_common_checks(object_type)

            logger.debug("Deleting object with id=%s", object_id)
            op = ObjectOperation(logger, self._session_key, self._current_user)
            op.delete(LOG_PREFIX, owner, object_type, object_id, kwargs)

    def _link_template_to_service(self, owner, object_type, id_, **kwargs):
        """
        Get service template id from service /
        Link a single service to a service template

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: string
        @param object_id: the id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the object
        
        """
        with handle_exceptions():
            if object_type != 'service':
                raise ITOAError(status=400, message=_("Unsupported object type %s.") % str(object_type))

            if self._rest_method == 'GET':
                logger.debug("object_type=%s, id=%s, kwargs=%s", object_type, id_, kwargs)
                handler = ServiceTemplateUtils(self._session_key, owner)
                return self.render_json(handler.get_template_id_from_service(owner,id_))

            elif self._rest_method in ['PUT', 'POST']:
                logger.debug("object_type=%s, id=%s, kwargs=%s", object_type, id_, kwargs)
                # validate payload
                data = kwargs.get('data')
                if not utils.is_valid_dict(data):
                    raise ITOAError(status=400, message=_('Invalid or missing service link map. Payload received: {}').format(kwargs))
                service_template_id = data.get('_key', None)
                if not utils.is_valid_str(service_template_id):
                    error = _('Invalid service template key. Payload received: {}').format(kwargs)
                    logger.error(error)
                    raise ITOAError(status=400, message=error)
                # default overwrite_entity_rules to 'append'
                overwrite_entity_rules = data.get('overwrite_entity_rules', 'append')
                if overwrite_entity_rules not in ('append', 'replace', 'ignore'):
                    raise ITOAError(status=400,
                                    message=_('Invalid overwrite_entity_rules. Payload received: {}.').format(overwrite_entity_rules))

                # link a template to a service
                handler = ServiceTemplateUtils(self._session_key, self._current_user)
                return self.render_json(handler.link_template_to_service(owner,
                                                                         id_,
                                                                         service_template_id,
                                                                         overwrite_entity_rules))
            else:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

    def _object_refresh_by_id(self, owner, object_type, object_id, **kwargs):
        """
        CRUD interface for IT context object to refresh its state without refreshing
        related objects, primarily used by UI

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: string
        @param object_id: the id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: None
        @return: None
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[object_refresh_by_id] '
            logger.debug("object_type=%s, id=%s, kwargs=%s", object_type, object_id, kwargs)
            if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_BY_ID_OPS:
                # Refresh not supported on KPIs, use service instead
                raise ITOAError(status="400", message=_("Unsupported object type %s.") % object_type)

            if object_type in self.OBJECT_TYPES_NON_UPDATEABLE_DURING_BACKUP_RESTORE:
                check_object_update_allowed(self._session_key, logger)

            logger.debug("Calling refresh method")
            op = ObjectOperation(logger, self._session_key, self._current_user)
            result = op.refresh(
                LOG_PREFIX,
                owner,
                object_type,
                {'filter_data': {'$or': [{'_key': object_id}]}},
                raw=True
            )
            return self.render_json(result)

    def _update_request_data(self, request, kvpairs):
        """
        Update fields in request data in place

        @type: object
        @param self: the self reference

        @type: dict
        @param request: the request

        @type: dict
        @param kvpairs: kv pairs to update with

        @rtype: None
        @return: None
        """
        if 'data' not in request:
            request.update(kvpairs)
        elif isinstance(request['data'], dict):
            request['data'].update(kvpairs)
        elif isinstance(request['data'], basestring):
            data = json.loads(request['data'])
            data.update(kvpairs)
            try:
                request['data'] = json.dumps(data)
            except (ValueError, TypeError) as e:
                logger.exception(e)
                request['data'] = data
        else:
            logger.error("Error updating request data")
            raise ITOAError(status="500", message=_("Error updating request data."))

    def _get_field(self, request, field):
        """
        Gets a field from request data

        @type: object
        @param self: the self reference

        @type: dict
        @param request: request payload

        @type: string
        @param field: field to get

        @rtype: variable
        @return: value of the found field
        """
        if 'data' in request and isinstance(request['data'], basestring):
            return json.loads(request['data']).get(field, None)
        elif 'data' in request and isinstance(request['data'], dict):
            return request['data'].get(field, None)
        elif isinstance(request, dict):
            return request.get(field, None)
        else:
            logger.error("Error retrieving field %s from request parameters", field)
            raise ITOAError(status="500", message=_("Error retrieving request data."))

    ##############################################################################
    # Bulk Import
    ##############################################################################
    def _bulk_csv_import(self, owner, **kwargs):
        """
        Perform bulk import of objects from CSV data

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the created/updated object keys
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[bulk_csv_import] '

            import_spec = utils.validate_json(LOG_PREFIX, kwargs.get('data'))
            preview_only_mode = kwargs.get('preview_only_mode', False)

            check_object_update_allowed(self._session_key, logger)

            if not import_spec.get('updateType'):
                import_spec['updateType'] = itoa_csv_loader.CSVLoader.default_update_type().upper()

            #FIXME: This whole thing looks problematic, need to talk to discovery scrum
            itoa_csv_loader.CSVLoader.validate_contract(import_spec)
            csv_loader = itoa_csv_loader.CSVLoader(
                owner,
                import_spec,
                self._session_key,
                getCurrentUser()['name'],
                preview_only_mode
            )
            created_keys = csv_loader.load_csv()
            if not created_keys:
                msg = _('No entries created/updated')
                logger.info(msg)
                return self.render_json([msg])
            return self.render_json(created_keys)

    ##############################################################################
    # Bulk Edit of Entity Information Fields
    ##############################################################################
    def _bulk_entities_update(self, owner, object_type, **kwargs):
        """
        POST (UPDATE of subordinate objects) for entity objects INFO FIELDS only

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: Keys updated
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status=405, message=_("Unsupported HTTP method %s.") % self._rest_method)

            if object_type not in ['entity']:
                raise ITOAError(status=400, message=_("Unsupported object type %s.") % str(object_type))

            data = utils.get_object(kwargs.get('data', None))
            if not data:
                logger.error('No data received. `data` is a mandatory key. Received: {}'.format(kwargs))
                raise ITOAError(status=400, message=_("No data received."))

            return self.render_json(bulk_entity_update_tags(self._session_key,
                                                            self._current_user,
                                                            owner,
                                                            data,
                                                            logger))

    def _bulk_update(self, owner, object_type, **kwargs):
        """
        POST for bulk updates to objects

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: the ITOA object type

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: Keys updated
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[crud_general] '
            self._crud_common_checks(owner, object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            result = op.bulk_edit(LOG_PREFIX, owner, object_type, kwargs, raw=True)
            return self.render_json(result)

    #################################################################################
    # These methods are used to get the search snippets used by entities
    #################################################################################
    def _generate_entity_filter(self, owner, **kwargs):
        """
        Generate an entity filter consumable by KPI search strings.

        @type owner: basestring
        @param owner: string indicating owner of this call.

        @type kwargs: dict
        @param kwargs: parameters; query params that are sent as part of request
            Mandatory keys:
                @type service_id: basestring
                @param service_id: identifier of the service that this KPI belongs to
            Other keys:
                @type entity_id_fields: basestring
                @param entity_id_fields: comma separated entity identifier fields as defined in KPI

                @type entity_alias_filtering_fields: basestring
                @param entity_alias_filtering_fields: comma separated entity alias fields for
                    filtering as defined in KPI

        @rtype: basestring
        @return entity filter
        """
        logger.debug('Received input args owner=%s kwargs=%s', owner, json.dumps(kwargs))

        if self._rest_method != 'GET':
            raise ITOAError(status='501', message=_('Unsupported method.'))

        service_id = kwargs.get('service_id')
        if any([not isinstance(service_id, basestring),
                isinstance(service_id, basestring) and not service_id.strip()]):
            raise ITOAError(status=400, message=_('Invalid or missing query param'
                                                  ' "service_id". Expecting non-empty string for service identifier.'))

        transaction_id = uuid1().hex
        self._instrument.push('itsi.searches._generate_entity_filter', transaction_id=transaction_id, owner=owner)

        # Workaround kvstore constraint of not supporting partial fetches of a SINGLE
        # object. We will use query instead. There is no perf impact.
        # In fact data/{collection}/a is changed to query={_key:a}&limit=1 internally by
        # kvstore
        rval = ItsiService(self._session_key, owner).get_bulk(
            owner,
            req_source='search',
            filter_data={'_key':service_id},
            fields=['entity_rules', 'sec_grp'],
            limit=1, # fetch exactly one service
            transaction_id=transaction_id
        )
        logger.debug('Partial service fetched. Value=%s', rval)

        if not rval: # handles empty list or None
            logger.error('No service found for identifier=%s.', service_id)
            raise ITOAError(status=404, message=_('No such service for identifier=%s.') % service_id)

        svc = rval[0]

        entity_rules = svc.get('entity_rules', [])

        datamodel = {}
        if kwargs.get('search_type', 'adhoc') == 'datamodel': # get datamodel parameters if any.
            for k in kwargs.keys():
                if k.startswith('datamodel.'):
                    # incoming datamodel keys look like 'datamodel.object'.
                    # Get "object", discard the rest.
                    datamodel[k.split('.')[1]] = kwargs[k]

        # fetch fields that will help us determine if search clauses are required
        entity_id_fields = kwargs.get('entity_id_fields', '')
        entity_alias_filtering_fields = kwargs.get('entity_alias_filtering_fields', '')

        params = {
            'generate_filter': True,
            'datamodel':datamodel.get('datamodel'),
            'datamodel_object_name':datamodel.get('object'),
            'identifying_fields':entity_id_fields,
            'entity_alias_filtering_fields':entity_alias_filtering_fields,
            'service_entity_rules':entity_rules,
            'sec_grp': svc.get('sec_grp')
        }

        try:
            search_clauses = ItsiKpiSearches.get_search_clause(self._session_key, service_id, **params)
        except Exception:
            logger.exception('Failed to generate search clauses.')
            raise

        logger.debug('Generated search clauses=%s', json.dumps(search_clauses))
        self._instrument.pop('itsi.searches._generate_entity_filter', transaction_id)
        return search_clauses.get('search')

    def _get_kpi_searches(self, owner, **kwargs):
        """
        Gets the search clause/information that that is used in a datamodel search
        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the search string requested and the search terms used to build the string
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status='501', message=_('Unsupported HTTP method "%s".') % self._rest_method)

            log_prefix = '[get_kpi_searches] '

            if 'data' not in kwargs:
                logger.error("Missing 'data' parameter in request, got kwargs: %s", kwargs)
                raise ITOAError(status="400", message=_("Missing 'data' parameter in request for search clause."))

            request_data = utils.validate_json(log_prefix, kwargs.get('data'))
            if 'kpi' not in request_data:
                logger.error("Missing 'kpi' parameter in request, got data: %s", request_data)
                raise ITOAError(status="400", message=_("Must specify KPI for search generation."))

            kpi = request_data.get('kpi')
            gen_alert_search = request_data.get('gen_alert_search')
            sec_grp = request_data.get('sec_grp')
            itsi_searches = ItsiKpiSearches(
                session_key=self._session_key,
                kpi=kpi,
                sec_grp=sec_grp
                )
            if kwargs.get('isBackfill', False):
                results = itsi_searches.gen_backfill_search()
            else:
                results = itsi_searches.gen_kpi_searches(gen_alert_search=gen_alert_search)
            logger.debug('Got search generation result="%s"', results)
            return self.render_json(results)

    def _preview_merge(self, owner, **kwargs):
        """
        This method takes in a list of entities as a json struct and will then return a list of "previewed" entities.
        The order of the entities received will be the order returned in the list
        outputs a json structure that contains a potential merge
        Other attributes passed in will be retained

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the objects from the preview
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            LOG_PREFIX = '[preview_merge] '

            check_object_update_allowed(self._session_key, logger)

            if 'data' in kwargs:
                request_data = utils.validate_json(LOG_PREFIX, kwargs.get('data'))
                logger.debug("After converting data field, got request_data: %s", request_data)
            else:
                message = _("No data field input got keys: {}.").format(str(kwargs.keys()))
                logger.error(message)
                raise ITOAError(status="400",message=message)
            entities = request_data.get("entities",None)
            preview_type = request_data.get("preview_type","APPEND")
            if preview_type.lower() not in ["append","upsert","replace"]:
                message = _("Unrecognized preview type passed in: {}.").format(preview_type)
                logger.error(message)
                raise ITOAError(status="400",message=message)
            if entities == None:
                message = _("Received a preview merge request with no entities.")
                logger.error(message)
                raise ITOAError(status="400", message=message)
            import_spec = {'updateType': preview_type}
            csv_loader = itoa_csv_loader.CSVLoader(owner, import_spec, self._session_key, getCurrentUser()['name'], True)
            results = csv_loader.preview_merge(entities)
            return self.render_json(results)

    def _get_alias_list(self, owner, **kwargs):
        """
        Retrieves the alias list for use with kpis

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the aliases
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            storage_interface = self._get_storage_interface()
            results = storage_interface.get_all_aliases(self._session_key, owner)
            return self.render_json(results)

    def _get_backfill_search(self, owner, **kwargs):
        """
        Method to generate backfill search

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the backfill search string requested and the search terms used to build the string
        """
        with handle_exceptions():
            if self._rest_method not in ['PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            kwargs['isBackfill'] = True
            return self.render_json(self._get_kpi_searches(owner, **kwargs))

    def _get_entity_filter(self, owner, **kwargs):
        """
        Method to generate entity filters

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the generated entity filter
        """
        with handle_exceptions():
            if self._rest_method not in ['GET', 'PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            entity_filter = kwargs.get("entity_filter",None)
            if entity_filter is None:
                message = _("Missing required parameter 'entity_filter'.")
                logger.error(message)
                raise ITOAError(status="400", message=message)
            #Passed our simple validation, send it down the line
            entity_filter = itsi_filter.ItsiFilter(entity_filter)
            results = entity_filter.get_filtered_objects(
                self._session_key,
                owner,
                limit=kwargs.get('count'),
                skip=kwargs.get('offset'),
                current_user_name=self._current_user,
                **kwargs
            )
            return self.render_json(results)

    def _get_entity_filter_count(self, owner, **kwargs):
        """
        Method to generate backfill search

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the count of entity filters
        """
        with handle_exceptions():
            if self._rest_method not in ['GET', 'PUT', 'POST']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            entity_filter = kwargs.get("entity_filter",None)
            if entity_filter is None:
                message = _("Missing required parameter 'entity_filter'.")
                logger.error(message)
                raise ITOAError(status="400", message=message)

            entity_filter = itsi_filter.ItsiFilter(entity_filter)
            results = entity_filter.get_filtered_objects_count(self._session_key, owner,
                                                               current_user_name=self._current_user)
            return self.render_json(results)

    def _templatize_object_by_id(self, owner, object_type, object_id, **kwargs):
        """
        Templatize given object id.
        We will get rid of values that make the given id unique
        and pass back to the UI, the templatized value.

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of the object

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of the backfill search string requested and the search terms used to build the string
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            templatizable_object_types = ('service', 'kpi_base_search')
            if object_type not in templatizable_object_types:
                raise ITOAError(status=400, message=_('Unsupported object type=%s.') % object_type)
            logger.debug('Templatize request received for object type=`%s`', object_type)

            op = ObjectOperation(logger, self._session_key, self._current_user)
            result = op.templatize(owner, object_type, object_id)
            return self.render_json(result)

    def _get_neighbors(self, owner, object_type, **kwargs):
        """
            Get related entity relationships for a given entity

            @type: object
            @param self: the self reference

            @type: string
            @param owner: owner making the request

            @type: string
            @param object_type: type of ITOA object

            @type: dict
            @param **kwargs: key word arguments extracted from request.
            Required: entity_identifier or entity_key
            Optional: level, max_count

            @rtype: json
            @return: json of related entity relationships
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status=405, message=_('Unsupported HTTP method %s.') % self._rest_method)

            if object_type not in ['entity_relationship']:
                raise ITOAError(status=400, message=_('Unsupported object type=%s.') % object_type)

            logger.debug('_get_neighbors request received with args=%s', kwargs)

            # Must provide entity_identifier or entity_key
            entity_identifier = kwargs.get('entity_identifier')
            entity_key = kwargs.get('entity_key')
            if (entity_identifier is None and entity_key is None) or all([
                                entity_identifier is not None and not utils.is_valid_str(entity_identifier),
                                entity_key is not None and not utils.is_valid_str(entity_key)]):
                raise ITOAError(status=400,
                                message=_('Invalid or missing query param "entity_identifier" or "entity_key". '
                                         'Expecting non-empty string for entity_identifier or entity_key.'))

            result = get_neighbors(self._session_key,
                                   self._current_user,
                                   owner,
                                   kwargs,
                                   logger)
            return self.render_json(result)

    def _get_service_trees(self, owner, **kwargs):
        """
        Method to generate service trees

        @type: object
        @param self: the self reference

        @type: string
        @param owner: owner making the request

        @type: dict
        @param **kwargs: key word arguments extracted from request

        @rtype: json
        @return: json of topology tree
        """
        with handle_exceptions():
            if self._rest_method not in ['GET']:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

            # perform a partial fetch of services
            fields = ['title', '_key', 'services_depends_on']
            partial_fetch_kwargs = {'fields':','.join(fields)}

            LOG_PREFIX = '[crud_general] '
            op = ObjectOperation(logger, self._session_key, self._current_user)
            data = op.get_bulk(LOG_PREFIX, owner=owner, object_type='service', kwargs=partial_fetch_kwargs, raw=True)
            service_id_filter = json.loads(kwargs.get('filter', '[]'))
            try:
                result = generate_subgraphs_json(data, service_id_filter=service_id_filter)
            except:
                raise ITOAError(status="500")
            return self.render_json(result)
