# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Exposes Cherrypy/Splunkweb endpoints that do basic CRUD on objects for maintenance purposes
"""

import sys
import json
from splunk.appserver.mrsparkle.lib import i18n
from contextlib import contextmanager
from copy import deepcopy

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk import ResourceNotFound, BadRequest, RESTException

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ITOAError
import ITOA.itoa_common as utils
from ITOA.event_management.event_management_object_manifest import object_manifest
from ITOA.event_management.notable_event_error import NotableEventBadRequest
from ITOA.event_management.notable_event_ticketing import ExternalTicket
from ITOA.event_management.notable_event_actions import NotableEventAction
from ITOA.event_management.notable_event_mad import NotableEventMad

from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity
from itsi.event_management.itsi_notable_event import ItsiNotableEvent
from itsi.event_management.event_management_services import EventManagementService
from ITOA.event_management.notable_event_utils import get_collection_name_for_event_management_objects
from ITOA.itoa_exceptions import ItoaAccessDeniedError

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess

logger = setup_logging("itsi_event_management.log", "event_management_services.EventManagementRestProvider")

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
    except (TypeError, ValueError, NotableEventBadRequest) as e:
        logger.exception(e)
        raise ITOAError(status=400, message=e.message)
    except ItoaAccessDeniedError as e:
        logger.exception(e)
        raise ITOAError(status=403, message=e.message)
    except ResourceNotFound as e:
        logger.exception(e)
        raise ITOAError(status=404, message=e.message)
    except BadRequest as e:
        logger.exception(e)
        raise ITOAError(status=e.statusCode, message=e.extendedMessages)
    except RESTException as e:
        logger.exception(e)
        raise ITOAError(status=e.statusCode, message=e.msg)
    except Exception as e:
        logger.exception(e)
        raise ITOAError(status=500, message=str(e))

def get_interactable_object_types():
    """
    method returns event management object types that are interactable

    @rtype: list of strings
    @return: names of object types
    """
    return ['notable_event_aggregation_policy', 'correlation_search']

class EventManagementRestProvider(ItoaInterfaceProviderBase, EventManagementService):
    """
    Provides backend interaction via REST for event management operations like CRUD for configuration
    """

    SUPPORTED_OBJECT_TYPES = object_manifest.keys()
    NON_DELETABLE_OBJECT_TYPES = ['notable_event']

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
                           ' %s.') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)
            if 'acl' not in data or 'objects' not in data:
                message = _('`acl` & `objects` are mandatory keys in data.'
                           ' Received: %s.') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)

            acl = utils.get_object(data.get('acl'))
            if 'read' not in acl or 'write' not in acl:
                message = _('`acl` is missing mandatory keys `read`/`write`.'
                           ' Received: %s.') % kwargs
                logger.error(message)
                raise ITOAError(status=400, message=message)

            if 'delete' not in acl:
                # no explicit perms for `delete` set. lets use the ones for `write`
                acl['delete'] = deepcopy(acl['write'])

            objects = utils.get_object(data.get('objects'))
            o_store = get_collection_name_for_event_management_objects(object_type)
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
                logger.debug('Successfully updated perms')
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
                message = _('Perms can only be set for `%s`. Received: %s.') % (
                    allowable_types, object_type)
                logger.error(message)
                raise ITOAError(status=400, message=message)

            if self._rest_method == 'POST':
                data = utils.get_object(kwargs.get('data'))
                # do validations specific to this endpoint
                if not data:
                    logger.error('No Data received.')
                    raise ITOAError(status=400, message=_('No data received.'))
                if not data.get('acl'):
                    message = _('Missing key in data. `acl` on POST is mandatory'
                                '. Received: `{}`').format(kwargs)
                    logger.error(message)
                    raise ITOAError(status=400, message=message)

                acl = utils.get_object(data['acl'])
                if 'read' not in acl or 'write' not in acl:
                    message = _('`acl` is missing mandatory keys `read`/`write`.'
                                ' Received: %s.') % kwargs
                    logger.error(message)
                    raise ITOAError(status=400, message=message)

            rval = {'updated': False, 'id': object_id, 'acl': acl}
            o_store = get_collection_name_for_event_management_objects(object_type)

            if self._rest_method == 'POST':
                logger.debug('Request to update perms for %s', object_id)

                # lets normalize acl data to an object
                # we expect itsi to not sent us any `delete` specific data
                # SA-UserAccess expects it..so lets add it
                logger.debug('data[acl]: %s' % data['acl'])
                acl = deepcopy(data['acl'])
                acl = utils.get_object(acl)
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
                    message = _('Failed to update perms. %s. See internal logs.') % msg
                    logger.error(message)
                    raise ITOAError(status=500, message=message)
            else: # GET
                logger.debug('Request to get perms for %s', object_id)
                rval['message'] = _('No perms were found.')
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

    def _bulk_crud(self, owner, object_type, **kwargs):
        """
        CRUD interface for supported object types

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        """
        with handle_exceptions():
            if object_type not in self.SUPPORTED_OBJECT_TYPES:
                raise ITOAError(
                    status="400",
                    message=_('Invalid object type "{}", supported object types are {}.').format(
                        str(object_type),
                        str(self.SUPPORTED_OBJECT_TYPES)
                    )
                )
            if 'data' in kwargs:
                data = kwargs.get('data')
                data = utils.validate_json('[event_management_interface]', data)
                kwargs['data'] = data
            if self._rest_method in ['POST', 'PUT']:
                return self.render_json(self._check_and_call_operation(
                    owner, object_type, kwargs, self.upsert, self.upsert_bulk, self._current_user
                ))
            elif self._rest_method == 'GET':
                return self.render_json(self.get_bulk(owner, object_type, kwargs))
            elif self._rest_method == 'DELETE':
                if object_type in self.NON_DELETABLE_OBJECT_TYPES:
                    raise ITOAError(
                        status='405',
                        message=_('Invalid object type "{}", does not support DELETE.').format(
                            str(object_type)
                        )
                    )
                self.render_json(self.delete_bulk(owner, object_type, kwargs))
            else:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)

    def _get_instance(self, object_type, owner, current_user_name=None):
        """
        Get instance for given object_ type

        @type: string
        @param object_type: type of object to instantiate

        @type: string
        @param owner: owner of the object

        @rtype: ItsiNotableEvent
        @return: object_ instance of given type
        """
        object_class = object_manifest.get(object_type)
        # We want to perform all operation at nobody context
        return object_class(self._session_key, current_user_name=current_user_name)

    def _get_object_count(self, owner, object_type, **kwargs):
        """
        Get the object count

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @type: string
        @param aggregation: aggregation operation request in the REST call

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)

        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="500", message=_("Unsupported HTTP method %s.") % self._rest_method)

            logger.debug('Getting count of %s for user=%s', object_type, owner)
            object_instance = self._get_instance(object_type, owner)
            self._delete_data(kwargs)
            count = len(object_instance.get_bulk([], **kwargs))
            return self.render_json({'count': count})

    def _crud_by_id(self, owner, object_type, object_id, **kwargs):
        """
        CRUD operations for maintenance services objects by their identifiers

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @type: string
        @param object_id: existing maintenance object identifier

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with object
        """
        with handle_exceptions():
            if object_type not in self.SUPPORTED_OBJECT_TYPES:
                raise ITOAError(status="500", message=_("Unsupported object type %s.") % object_type)

            if 'data' in kwargs:
                data = kwargs.get('data')
                data = utils.validate_json('[event_management_interface]', data)
                kwargs['data'] = data

            if self._rest_method in ['POST', 'PUT']:
                current_user = self._current_user
                return self.render_json(self.upsert(owner, object_type, object_id, kwargs, current_user=current_user))
            elif self._rest_method == 'GET':
                return self.render_json(self.get(owner, object_type, object_id, kwargs))
            elif self._rest_method == 'DELETE':
                if object_type in self.NON_DELETABLE_OBJECT_TYPES:
                    raise ITOAError(
                        status='405',
                        message=_('Invalid object type "{}", does not support DELETE.').format(
                            str(object_type)
                        )
                    )
                self.delete(owner, object_type, object_id, kwargs)
            else:
                raise ITOAError(
                    status=405,
                    message=_('Invalid method "{}". Valid methods are GET, POST, PUT and DELETE.').format(self._rest_method)
                )


    def _do_notable_event_action(self, **kwargs):
        """
        Implements notable event action actions

        @type: object
        @param self: the self reference

        @param: dict
        @param **kwargs: key word arguments extracted from the POST body

        Get or execute one or more actions
        @type data - list (when data is list then action is executed in bulk)
        @param data: data
                data - when it is list then more than one event action is being perform
                data - is dict then only one action is being performed
                data structure would looks like this
                    ids : [] -> list of events or group ids
                    name:  -> action name
                    params: key:value pair for action parameters
                    _is_sync - bool to check if action is sync or async
                    _is_group - bool to check if action is being perform on group or not
                    _group_data - list if event ids where action is perform if list is empty then action is being
                        done on all events of the group

        @rtype: json
        @return: list of dict
                    [{
                        sid: search id
                        ids: [] list of events or group id where action is being perform
                        action_name: name of action which is being performed
                    }...]
        """
        with handle_exceptions():
            if self._rest_method not in ['GET', 'POST']:
                raise ITOAError(
                    status=405,
                    message=_('Invalid method "%s". Valid methods are GET and POST.') % self._rest_method
                )

            # Use cherrypy.url() to get app name
            app_name = 'SA-ITOA'
            owner = self._current_user
            action_name = kwargs.get('action_name')
            notable_event_action_object = NotableEventAction(self._session_key, app='SA-ITOA', owner=owner)

            if self._rest_method == 'GET':
                if action_name is None:
                    # get all actions
                    actions = notable_event_action_object.get_actions()
                else:
                    # return only action which need to perform action
                    actions = notable_event_action_object.get_action(action_name)
                logger.debug('Return actions="%s"', actions)
                return self.render_json(actions)
            elif self._rest_method == 'POST':
                data = kwargs.pop('data', {})
                if action_name and isinstance(data, dict):
                    data['name'] = action_name
                ret_data = notable_event_action_object.execute_actions(data)
                logger.debug('Execute action information=%s', ret_data)
                return self.render_json(ret_data)

    def _get_notable_event_configuration(self, **kwargs):
        """
        Get notable event configuration like severity, status owner and email formats.
        It is mainly useful for UI to shows up drop down etc

        @type kwargs: dict
        @param kwargs: Extra arguments

        @rtype: dict
        @return: Return a dictionary which hold information about severities, status and owners
            {
                severities: [
                {
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..],
                statuses: [
                {
                    label: <name>,
                    value: <name>,
                    default: 0|1
                } ...],
                owners: [{
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..],
                email_formats: [{
                    label: <name>,
                    value: <name>,
                    default: 0|1
                }..

            }
        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(
                        status=405,
                        message=_('Invalid method "%s". Valid methods are GET and POST.') % self._rest_method
                    )
            result = self.get_all_notable_event_configuration(self._session_key)
            return self.render_json(result)

    def _cru_ticket_info(self, object_id, **kwargs):
        """
        This method fetches all the ticket information for a particular event id on a GET
        This method upserts a single ticket and associating it with the notable event.

        @type: string
        @param object_id: the key of the notable event to deal with for ticketing

        @type: dict
        @param kwargs: the POST/PUT/GET args to this endpoint, only used for POST and PUT
            for a POST/PUT the kwargs should look like:
                {
                    ticket_system: 'bugziranowmedy',
                    ticket_url: http://bugziranowmedy.com/thisAwesomeSauceTicket
                    ticket_id: thisAwesomeSauceTicket
                    < arbitrary kv pairs to associate with ticket >
                }

        @rtype: json
        @return: json results of the action
        """
        with handle_exceptions():
            external_ticket = ExternalTicket(object_id, self._session_key, logger)
            # Validate objects are supported or not
            if self._rest_method in ['POST', 'PUT']:
                if not isinstance(kwargs.get(ExternalTicket.KEY_TICKET_SYSTEM, None), basestring):
                    raise ValueError(_('Ticket System must be defined to create or update ticket'))
                if not isinstance(kwargs.get(ExternalTicket.KEY_TICKETS_TICKET_ID, None), basestring):
                    raise ValueError(_('Ticket ID must be defined to create or update ticket'))
                if not isinstance(kwargs.get(ExternalTicket.KEY_TICKETS_TICKET_URL, None), basestring):
                    raise ValueError(_('Ticket URL must be defined to create or update ticket'))
                arbitrary_kwargs = kwargs.copy()
                del arbitrary_kwargs[ExternalTicket.KEY_TICKET_SYSTEM]
                del arbitrary_kwargs[ExternalTicket.KEY_TICKETS_TICKET_ID]
                del arbitrary_kwargs[ExternalTicket.KEY_TICKETS_TICKET_URL]
                return self.render_json(external_ticket.upsert(kwargs[ExternalTicket.KEY_TICKET_SYSTEM],
                                                               kwargs[ExternalTicket.KEY_TICKETS_TICKET_ID],
                                                               kwargs[ExternalTicket.KEY_TICKETS_TICKET_URL],
                                                               **arbitrary_kwargs))
            elif self._rest_method == 'GET':
                return self.render_json(external_ticket.get())
            else:
                raise ITOAError(
                    status=405,
                    message=_('Invalid method "%s". Valid methods are GET, POST and PUT.') % self._rest_method
                )

    def _delete_ticket_info(self, object_id, ticket_system, ticket_id, **kwargs):
        """
        This method deletes a single ticket associated with a particular notable event.

        @type: string
        @param object_id: the key of the notable event to deal with for ticketing

        @type: string
        @param ticket_system: the ticket system of the notable event that needs to be deleted

        @type: string
        @param ticket_id: the ticket id of the notable event that needs to be deleted

        @type: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: json
        @return: json results of the delete
        """
        with handle_exceptions():
            external_ticket = ExternalTicket(object_id, self._session_key, logger)
            # Validate objects are supported or not
            if self._rest_method == 'DELETE':
                return self.render_json(external_ticket.delete(ticket_system, ticket_id))
            else:
                raise ITOAError(status=405, message=_('Invalid method "%s". Only DELETE method is valid.') % self._rest_method)

    def _bulk_cru_ticket_info(self, **kwargs):
        with handle_exceptions():
            if self._rest_method not in ('POST', 'PUT'):
                raise ITOAError(status=405, message=_('Invalid method "%s". Valid methods are POST and PUT.') % self._rest_method)

            data = kwargs.get('data')
            if not data or not isinstance(data, dict):
                raise ITOAError(status=400, message=_('Invalid/Missing data'))

            # There is a weakness in how these arguments are passed which implies ids is a reserved key and cannot be
            # used which is not expressly documented anywhere, I have removed it here to avoid it being copied in every
            # ticket information entry, but this endpint should likely be refactored to not use the json parser that
            # mandates content be passed as a string and then redecorates an unnecessary data key around it as it is
            # very confusing.
            ids = data.pop('ids', None)
            if not ids or not isinstance(ids, list):
                raise ITOAError(status=400, message=_('Invalid/Missing event ids.'))

            if any([ExternalTicket.KEY_TICKET_SYSTEM not in data,
                ExternalTicket.KEY_TICKETS_TICKET_ID not in data,
                ExternalTicket.KEY_TICKETS_TICKET_URL not in data
                ]):
                logger.error('Ticket system/ID/URL must be specified to create or update ticket info for %s', ids)
                raise ITOAError(
                    status=400,
                    message=_('Ticket system/ID/URL must be specified to create or update ticket.')
                )

            other_args = data.copy()
            other_args.pop(ExternalTicket.KEY_TICKET_SYSTEM)
            other_args.pop(ExternalTicket.KEY_TICKETS_TICKET_ID)
            other_args.pop(ExternalTicket.KEY_TICKETS_TICKET_URL)

            results = ExternalTicket.bulk_upsert(
                ids,
                data[ExternalTicket.KEY_TICKET_SYSTEM],
                data[ExternalTicket.KEY_TICKETS_TICKET_ID],
                data[ExternalTicket.KEY_TICKETS_TICKET_URL],
                self._session_key,
                logger,
                **other_args
            )
            return self.render_json(results)

    def _do_notable_event_group_action(self, **kwargs):
        """
        Performs group actions on notable events

        @type: object
        @param self: the self reference

        @type: dict
        @param kwargs: kwargs from the handler
            We expect data in format of
            {
                group_id : <group>
                fields_to_update: <key, value> of  field to update
                event_filter: <event to filters from group>
                other kwargs for search arguments like earliest_time and latest_time
            }

        @rtype: json
        @return: json of results of the group action
        """
        with handle_exceptions():
            if self._rest_method not in ['POST', 'PUT']:
                raise ITOAError(status=405, message=_('Invalid method "%s". Valid methods are POST and PUT.') % self._rest_method)

            itsi_notable_event = ItsiNotableEvent(self._session_key)
            input_data = kwargs.get('data') or kwargs
            data = itsi_notable_event.update_group_events(
                input_data.pop('group_id', None),
                input_data.pop('fields_to_update', None),
                input_data.pop('event_filter', None),
                **input_data
            )
            return self.render_json({'event': data}
                                    )

    def _extract_mad_event_payload(self, kwargs):

        if 'event' in kwargs:
            post_data = kwargs.get('event')
        elif 'data' in kwargs:
            post_data = kwargs['data']
            if isinstance(post_data, basestring):
                post_data = json.loads(post_data)
            if isinstance(post_data, dict) and 'event' in post_data:
                post_data = post_data['event']

        return post_data


    def _do_mad_event_action(self, **kwargs):
        """
        Helper API to process MAD event

        @type: object
        @param self: the self reference

        @type: dict
        @param kwargs: key word arguments extracted from the POST body
        The incoming payload will be in the following format if its trending alert
             {
                 "alert": true,
                 "score": 0.5842302014841434,
                 "threshold": 0.46312848166572157,
                 "itsi_kpi_id": "kpi_1",
                 "itsi_service_id": "service-123"
                 "alert_value": 477.97661447203484,
                 "alert_type: "trending",
                 "_time": 1462215600000
            }
            {
                 "alert": true,
                 "score": 0.5842302014841434,
                 "threshold": 0.46312848166572157,
                 "itsi_kpi_id": "kpi_1",
                 "itsi_service_id": "service-123",
                 "entity_id": "pseudo:entity-123",
                 "alert_value": 477.97661447203484,
                 "alert_type: "cohesive",
                 "_time": 1462215600000
            }

        @rtype: json
        @return: json of results of the action
        """
        with handle_exceptions():
            if self._rest_method not in ['POST', 'PUT']:
                raise ITOAError(status=405, message=_('Invalid method "%s". Valid methods are POST and PUT') % self._rest_method)

            post_data = self._extract_mad_event_payload(kwargs)
            if not isinstance(post_data, basestring):
                raise ITOAError(status=400, message=_('Payload is not a valid string'))

            notable_event_mad_object = NotableEventMad(self._session_key)
            alert = json.loads(post_data)
            logger.debug("MAD alert: %s", alert)
            notable_event_mad_object.transform_raw_mad_events(alert)
            return self.render_json({'event': post_data})

    def _get_service_kpi_title(self, service_id, kpi_id):
        """
        Get service title and kpi title for a service id and kpi id, this is a helper method for MAD processing

        @type: object
        @param self: the self reference

        @type: string
        @param kpi_id: identifier for the KPI

        @rtype: tuple
        @return: tuple of service tile and kpi title
        """
        service_object = ItsiService(self._session_key, 'nobody')
        impacted_service = service_object.get('nobody', service_id)
        if not impacted_service:
            logger.warn("No corresponding services were found for %s, the service may have been deleted.", service_id)
            return None, None

        requested_kpis = impacted_service.get('kpis', [])
        service_title = impacted_service.get('title', '')
        kpi_title = None

        for kpi in requested_kpis:
            if kpi_id == kpi.get('_key', ''):
                kpi_title = kpi.get('title', '')
                break

        if not kpi_title:
            logger.warn('The KPI %s in the service %s was not found, the KPI may have been deleted', kpi_id, service_id)
            return None, None

        return service_title, kpi_title

    def _get_entity_title(self, entity_key):
        """
        Get entity title given entity key
        :param entity_key: Identifier of the entity
        :return: Entity title
        """
        entity_object = ItsiEntity(self._session_key, 'nobody')
        impacted_entity = entity_object.get('nobody', entity_key)
        if not impacted_entity:
            logger.warn('No corresponding entity was found for the entity key: %s', entity_key)
            return ""
        return impacted_entity.get("title", "")

    def _get_entity_info(self, entity_id):
        """
        Parse entity_id and get entity_title

        @type: string
        @param entity_id: Specifying type and id of the entity separated by ':'

        @rtype: tuple
        @return: Tuple representing entity_key and entity_title
        """
        entity_id_split = entity_id.split(":")
        if len(entity_id_split) != 2:
            raise ITOAError(status=500, message=_('Invalid entity ID received from MAD: %s') % entity_id)
        try:
            (entity_type, entity_id) = (entity_id_split[0], entity_id_split[1])
            if entity_type == "defined":
                return self._get_entity_title(entity_id)
            elif entity_type == "pseudo":
                return entity_id
        except Exception:
            return ""

        return ""

    def _process_user_message_mad_event(self, **kwargs):
        """
        Helper API to process MAD event

        @type: object
        @param self: the self reference

        @type: dict
        @param kwargs: key word arguments extracted from the POST body

        The incoming payload will be in the following format
             {
                 "event": {
                    "itsi_kpi_id":"kpi_1",
                    "entity_id": "pseudo:entity-123",
                    "service_id": "something",
                    "metric_limit": 30,
                    "instance_id" : instance-123
                 }
            }

        @rtype: json
        @return: json of results of the action
        """
        with handle_exceptions():
            if self._rest_method not in ['POST', 'PUT']:
                raise ITOAError(status=405, message=_('Invalid method "%s". Valid methods are POST and PUT.') % self._rest_method)

            post_data = self._extract_mad_event_payload(kwargs)
            if not isinstance(post_data, basestring):
                raise ITOAError(status=400, message=_('Payload is not a valid string.'))

            alert = json.loads(post_data)
            metric_limit = alert.get('metric_limit', '')
            service_id = alert.get('itsi_service_id', 'UNKNOWN NAME')
            kpi_id = alert.get('itsi_kpi_id', '')
            (service_title, kpi_title) = self._get_service_kpi_title(service_id, kpi_id)
            # Send user message only if the service exists. Else treat MAD entity drop alert has false alarm.
            if isinstance(service_title, basestring):
                entity_title = self._get_entity_info(alert.get('entity_id', ''))
                message = _("Entity {0} in KPI {1} associated with service {2} was dropped from cohesive analysis. " \
                          "Maximum entity limit is {3}.").format(entity_title, kpi_title, service_title, metric_limit)
                ITOAInterfaceUtils.create_message(self._session_key, message)

            return self.render_json({'event': post_data})
