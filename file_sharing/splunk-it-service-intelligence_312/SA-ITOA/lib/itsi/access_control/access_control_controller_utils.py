# -*- coding: utf-8 -*-
# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This module can be used for enforcing RBAC at the ITOA Web Controller level.
It is usuable only when an active CherryPy session is available to be consumed.
It is unsuable by Splunkd REST endpoints, Modular Inputs or anything else
outside the `appserver/controllers` framework.

Your CherryPy REST endpoint (SplunkWeb endpoint) simply needs to be decorated as
follows:
    @route(...)
    @EnforceRBAC(logger)
    def mysplunkweb_endpoint():
        pass

The decorator EnforceRBAC handles both bulk operations and operations on
an individual object.

~~~~~~~~~~~~~~~~~
Operation Summary
~~~~~~~~~~~~~~~~~

Aurora:
RBAC in ITSI is enforceable only for Dashboard like objects.
Dashboard like objects include `service analyzer`, `glass table` & `deep dive`.
All other objects are exempt.

Operation Types
----------------
Note: For all operations, RBAC is not enforceable on private objects...

1. For Operation Create:
    a. create the object(s) in statestore..we will set the `_key`
    b. stash away acl if provided or default acl(s) by calling SA-UserAccess API
    using the `_key`

2. For Operation Read:
    a. fetch requested data and iterate through it. filter out shared objects
    that are not accessible by user and set a new Query.
    b. at the end of it:
        ` respond with 200, if no object id(s) are available to be returned,
    c. if object is an `interactable type` ex. `glass table` or `deep dive`, add
        additional information to return message indicating `interactability` for
        this user as follows:
    e. `interact` ability is an ITSI specific Splunk capability. All we need to
        do is fetch the user's capabilities and see if he/she has the capability
        or not.

3. For Operation Update:
    a. fetch requested data and iterate through it.
    b. query SA-UserAccess API and see if object id is accessible by current
        user.
    c. at the end of it:
        ` respond with a 403, if any object id is inaccessible
        ` respond with a 200, if all object ids are accessible

4. For Operation Delete:
    a. fetch requested data and iterate over it. filter out objects that are
    inaccessible by querying SA-UserAccess.
    b. at the end of it:
        ` respond with a 403, if any object id is inaccessible
"""

#### Core Python imports
####
import sys
from copy import deepcopy
from uuid import uuid1
import json
import cherrypy

#### Splunk imports
####
from splunk.appserver.mrsparkle.lib import i18n
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.auth import getCurrentUser
from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess
from ITOA.controller_utils import ITOAError, ObjectOperation, Request
from ITOA.itoa_common import get_object, extract
from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import get_interactable_object_types
from ITOA.itoa_config import get_collection_name_for_itoa_object
from itsi.event_management.event_management_services import EventManagementService
from ITOA.event_management.notable_event_utils import get_collection_name_for_event_management_objects


class EnforceRBAC(controllers.BaseController):
    """
    Class based decorator for enforcing RBAC at the ITOA controller level.
    RBAC stands for `Role Based Access Control`
    """

    EVENT_MANAGEMENT_SERVICE_OBJECTS = ['notable_event_aggregation_policy',
                                        'correlation_search']

    def __init__(
        self,
        logger,
        session_key=None,
        app='itsi',
        user=None,
        method=None,
        kwargs=None
    ):
        """
        @param logger: caller's logger
        @param session_key: splunkd session key
        @param user: current user
        @param method: incoming `method` ex: `GET`, `POST` etc...
        @param object_type: glass_table, deep_dive or what?
        @param kwargs: incoming params
        """
        self.logger = logger
        self.session_key = session_key
        self.user = user
        self.method = method
        self.app = app
        self.op = None
        self.request = None
        self.operation = None
        self.key = '_key'

    def fetch_requested_data(
        self,
        more_keys=None,
        filter_data=None,
        new_params=None,
        ignore_params=None
    ):
        """From statestore, fetch the data being requested for RBAC enforcement
        by default only fetch keys in keys_to_fetch

        @type more_keys: list
        @param more_keys: key/values to fetch.
            For ex: for deep dives, you might want `is_named` values
                    for glass table, you might want `svg_content`

        @type filter_data: dict
        @param filter_data: fetch data that matches this criteria
            For ex: for deep dives, you might want records where `is_named` is
                    True
                    for glass tables, you might want records where `svg_content`
                    is non-empty

        @type new_params: dict
        @param new_params: params to use when making a request..could be
            something like count, offset and so on.

        @type ignore_params: list
        @param ignore_params: params to ignore when making a request..could be
            something like count, offset and so on...

        @rtype: blob
        @return: requested data.
        """
        keys_to_fetch = [self.key, '_owner', 'title']

        if isinstance(more_keys, list):
            keys_to_fetch.extend(more_keys)
            keys_to_fetch = list(set(keys_to_fetch))
        self.logger.debug('Keys to fetch: %s', keys_to_fetch)

        params = deepcopy(self.kwargs)
        params['fields'] = keys_to_fetch
        if filter_data:
            self.logger.debug('Not using request filter data. Filter data provided as param: %s', filter_data)
            # use filter_data given by caller..else use the one in request
            params['filter'] = filter_data

        # this request should be made w/o these params
        if ignore_params:
            self.logger.debug('Ignoring params: %s', ignore_params)
            for i in ignore_params:
                params.pop(i, None)

        # this request should be made with new query params
        if new_params:
            self.logger.debug('Adding params: %s', new_params)
            for param in new_params:
                params[param] = new_params[param]

        self.logger.debug('Fetch params: %s', params)
        o_owner = self.request.get_object_owner()
        o_type = self.request.get_object_type()
        if self.request.is_bulk():
            self.logger.info('Fetching for bulk.')
            if self._is_event_management_object(o_type):
                r_data = self.op.get_bulk(o_owner, o_type, params)
            else:
                r_data = self.op.get_bulk(None, o_owner, o_type, params, raw=True)
            self.logger.debug('Req data: %s len: %s', r_data, len(r_data))
        else:
            self.logger.info('Fetching for nonbulk.')
            ids_ = self.request.get_object_ids()
            self.logger.info('ids_: %s', ids_)
            try:
                if self._is_event_management_object(o_type):
                    r_data = self.op.get(o_owner, o_type, ids_[0], params)
                else:
                    r_data = self.op.get(None, o_owner, o_type, ids_[0], params, raw=True)
            except ResourceNotFound:
                # In certain test cases it is desired to not have anything return and return that as empty dict
                r_data = None
        self.logger.info('Read data: %s', r_data)
        if not r_data:
            r_data = {}
        else:
            r_data = self._get_obj(r_data)
        return r_data

    def _is_enforceable(self):
        """
        should we be enforcing RBAC for this object type?
        Enforce only if object is of an interactable type
            AND
        Object owner is `nobody` i.e. object is shared

        @return True if object is a dashboard like object
            False if otherwise
        """
        o_type = self.request.get_object_type()
        if o_type in get_interactable_object_types():
            return True
        return False

    def _is_event_management_object(self, o_type):
        """
        is o_type an event management service object?
        @type o_type: str
        @param o_type: type of object with acl
        @rtype: bool
        @return: True if event management object, False otherwise
        """
        for object_type in self.EVENT_MANAGEMENT_SERVICE_OBJECTS:
            if o_type == object_type:
                return True
        return False

    def validate_input(self, kwargs, logger):
        """ensure that some mandatory keys are present in object
        @param kwargs: incoming dictionary
        @param logger: caller's logger
        @raise ITOAError: Bad Request if any missing params
        @return nothing
        """
        expected = ['object']
        message = _('Bad Request: Missing one/all of the keys=`%s`. Received=%s.') % (expected, kwargs)
        for i in expected:
            if i not in kwargs:
                logger.error(message)
                raise ITOAError(status=400, message=message)

    def _get_obj(self, obj):
        """
        given an obj, try and get a dict type of it
        @param obj: an object to dict`ify
        @return a dict type object or list
        @raise ITOAError
        """
        obj = get_object(obj)
        if obj is None:
            m = 'Unable to json`ify `%s`. Internal error.' % obj
            self.logger.error(m)
            raise ITOAError(status=500, message=m)
        return obj

    def fetch_outliers(self, r_data):
        """given requested data, extract and return outliers
        These include private objects and unnamed deep dives
        @type r_data: list/dict
        @param r_data: requested data

        @rtype: list
        @return: list of outlier ids
        """
        outliers = []
        r_data = [r_data] if isinstance(r_data, dict) else r_data
        if not isinstance(r_data, list):
            raise TypeError(_('Invalid r_data: {} type: {}').format(
                r_data, type(r_data).__name__))
        for req in r_data:
            if any([
                req.get('_owner') and req['_owner'] == self.user,
                self.request.get_object_type() == 'deep_dive' and 'is_named' in req and req['is_named'] is False
            ]):
                outliers.append(req[self.key])
        return outliers

    def issue_verdict(self, accessible):
        """Issue a verdict if one is available...
        and construct a new query
        @type accessible: list
        @param accessible: list of accessible ids.
        @return Nothing.
        """
        if not isinstance(accessible, list):
            raise TypeError(
                'List expected. Invalid type: %s received for accessible: %s' % (type(accessible).__name__, accessible)
            )

        if not self.request.is_bulk():
            if not accessible:
                msg = _('%s is not accessible') % self.request.get_object_ids()
                self.logger.error(msg)
                raise ITOAError(status=403, message=msg)
            self.logger.info('Updating Request with accessible ids: `%s`', accessible)
            self.request.update_object_id(accessible[0])
        else:
            if not accessible:
                # I cant think of any other way to construct a filter
                # that returns nothing
                fake_key = str(uuid1())

                self.logger.info('Given user has no accessible ids. setting fake key=%s', fake_key)
                self.request.update_keys_in_query([fake_key])
                return

            self.logger.info('Updating Request with accessible ids: `%s`', accessible)
            self.request.update_keys_in_query(accessible)
            # in read, we always deal with ids...query params: count & offset should
            # never be allowed going forward. Purge them.
            self.kwargs.pop('offset', None)
            self.kwargs.pop('count', None)
            self.kwargs.pop('skip', None)

        self.logger.info('New request: %s', self.request)
        return

    def handle_regular_read(self):
        """
        Handles RBAC enforcement for the case of a READ operation
        on a single object or other reads that dont involve pagination requests
        """
        self.logger.debug('Regular read Request. Single object read or non-pagination bulk reads')

        # fetch all objects being requested
        r_data = self.fetch_requested_data()
        requested = extract(objects=r_data, key=self.key)

        if not requested:
            self.logger.debug('Nothing requested. No-op')
            return

        o_type = self.request.get_object_type()
        o_store = (get_collection_name_for_itoa_object(o_type)
                   or get_collection_name_for_event_management_objects(o_type))

        msg = _('Checking for accessible object ids.\n'
               'Requested ids: {0}\n'
               'operation: {1}\n'
               'app: {2}\n'
               'object type: {3}\n'
               'object store: {4}').format(requested, 'read', self.app, o_type,
                                           o_store)
        self.logger.debug(msg)

        accessible = UserAccess.get_accessible_object_ids(
            user=self.user,
            operation='read',
            session_key=self.session_key,
            logger=self.logger,
            object_ids=requested,
            object_app=self.app,
            object_type=o_type,
            object_store=o_store
            )
        outliers = self.fetch_outliers(r_data)

        self.logger.debug(
            'accessibles: %s\n outliers: %s', accessible, outliers)
        accessible.extend(outliers)

        # clear existing query & construct a new one containing accessible ids
        self.logger.debug('Clearing existing Query.')
        self.request.reset_query()
        return self.issue_verdict(accessible)

    def is_pagination_requested(self):
        """Pagination requests involve `offset` and `count` being passed in with
        the request. The value of count must be > 0 and that of offset can be
        whatever(0 or greater)...But merely an offset value w/o a count value does not imply
        a pagination request.

        @rtype: boolean
        @return True if pagination is requested; False otherwise.
        """
        count = self.request.get_query_param().get_count()
        offset = self.request.get_query_param().get_offset()

        # request doesnt have count and offset..this is not a pagination
        # request.
        if count is None and offset is None:
            return False

        try:
            offset = int(offset)
        except TypeError:
            offset = -1  # seems like an invalid type; not a pagination req.
        except ValueError:
            offset = -1  # seems like an invalid value; not a pagination req.

        try:
            count = int(count)
        except TypeError:
            count = 0  # seems like an invalid type; not a pagination req.
        except ValueError:
            count = 0  # seems like an invalid value; not a pagination req.

        # pagination is when
        if count > 0 and offset >= 0:
            return True
        return False

    def handle_bulk_read_pagination(self):
        """Handles RBAC enforcement for the case of a READ operation;
        involves pagination
        """
        self.logger.debug('Bulk read pagination request')

        requested = []  # requested ids
        accessible = []  # accessible ids
        outliers = []  # outliers; always accessible ids

        o_type = self.request.get_object_type()
        o_store = (get_collection_name_for_itoa_object(o_type)
                   or get_collection_name_for_event_management_objects(o_type))

        # requested offset and requested count; these should always be present.
        req_offset = int(self.request._qp.get_offset())
        req_count = int(self.request._qp.get_count())

        self.logger.debug('Requested offset: %s Requested count: %s', req_offset, req_count)

        # we'll start fetching data with these values...
        new_offset = req_offset
        new_count = req_count - len(accessible)

        # Fetch data till we reach requested count
        # or we run out of data to fetch...
        fetch_run = 1
        while ((len(accessible) + len(outliers)) < req_count):
            self.logger.debug('New offset:%s, new count:%s fetch run: %s', new_offset, new_count, fetch_run)

            # fetch data with new values of count and offset.
            r_data = self.fetch_requested_data(
                ignore_params=['count', 'offset'],
                new_params={'count': new_count, 'offset': new_offset}
            )

            requested = extract(objects=r_data, key=self.key)

            # this means there are no more objects to be read.
            if not requested:
                self.logger.debug('No more data available. Break')
                break

            # fetch accessibles and outliers
            accessible += UserAccess.get_accessible_object_ids(
                user=self.user,
                operation='read',
                session_key=self.session_key,
                logger=self.logger,
                object_ids=requested,
                object_app=self.app,
                object_type=o_type,
                object_store=o_store
            )

            outliers += self.fetch_outliers(r_data)
            self.logger.debug('Fetch run: %s accessibles: %s outliers: %s', fetch_run, accessible, outliers)

            # we need to paginate here. Under normal situations, if no data is
            # found for given count/offset, KV Store reads more data to
            # satisfy the `count` constraint. For RBAC,
            # even if there were `count` # of read objects,
            # we could have possibly ACL'ed some or all of them out.
            # Since there is potentially more accessible data to satisfy the
            # `count` constraint, we will continue
            # reading; but with new offset and count values.
            new_count = req_count - len(accessible)
            new_offset += req_count
            fetch_run += 1
        # end of while...

        self.logger.debug('Accessibles=%s outliers=%s', accessible, outliers)
        accessible.extend(outliers)

        # clear existing query & construct a new one containing accessible ids
        self.logger.debug('Clearing existing Query')
        self.request.reset_query()
        return self.issue_verdict(accessible)

    def handle_read(self):
        """Handles RBAC enforcement for the case of a READ operation
        * Fetch requested objects, and weed out inaccessible ids
        * always allows private objects to be read.
        * construct a new query param and return
        @param params: dict; input params containing query
        @return nothing
        @raise: ITOAError
        """
        self.logger.info('Received request to read')
        if self.request.is_bulk() and self.is_pagination_requested():
            return self.handle_bulk_read_pagination()
        return self.handle_regular_read()

    def handle_create(self):
        """Handle RBAC enforcement for the case of CREATE.
        *. no-op for private data
        *. Set a Key in data
        *. Stash away ACL and then return
        @return nothing
        """
        self.logger.info('Received request to create.')

        # normalize incoming data....
        data = self.request.get_data_as_list()
        self.logger.info('Data: %s', data)

        # dont stash acl for private objects
        req_is_private = True
        for i in data:
            if i.get('_owner', None) == 'nobody':
                req_is_private = False
                break
        if req_is_private:
            self.logger.info('Wont store ACL for private objects. %s. Returning.', self.kwargs)
            return

        # set the `_key` for the given data
        keys_ = []
        for i in data:
            if i.get(self.key):
                # home_view type objects set their own key.
                # ie. they want their own _key. So be it.
                key = i[self.key]
            else:
                key = str(uuid1())
                i[self.key] = key
            keys_.append(key)
        self.logger.info('Keys added. Data: %s', data)

        acl = self.kwargs.get('acl')
        if not acl:
            # TODO: call ACL.get_default_acl_blob() here instead..hasnt been
            # checked in yet
            acl = {'read': ['*'], 'write': ['*'], 'delete': ['*']}
        o_type = self.request.get_object_type()
        o_store = (get_collection_name_for_itoa_object(o_type)
                   or get_collection_name_for_event_management_objects(o_type))
        success, rval = UserAccess.bulk_update_perms(
            object_ids=keys_,
            acl=acl,
            object_app='itsi',
            object_type=o_type,
            object_storename=o_store,
            session_key=self.session_key,
            logger=self.logger
        )
        if not success:
            self.logger.error('Unable to save acl for input %s. Response: `%s`', self.kwargs, rval)
        else:
            self.logger.info('Successfully saved acl for input %s. Response:`%s`', self.kwargs, rval)
        self.kwargs.pop('acl', None)

        # convert data to basestring as it was...
        if len(data) == 1:
            # we have put in an array originally, move it out
            data = data[0]
        self.kwargs['data'] = deepcopy(json.dumps(data))
        return

    def handle_update(self):
        """Handle RBAC for an Update
        Given an id to update, see if id is accessible,
        if not, raise error. Else continue.
        Even if a subset is inaccessible, raise error
        @raises ITOAError
        """
        self.logger.info('Received request to Update.')
        o_type = self.request.get_object_type()
        r_data = self.fetch_requested_data()

        # manually convert glass_table/correlation_search dict into list
        if self.request.get_object_type() in ['glass_table', 'correlation_search']:
            if isinstance(r_data, dict):
                r_data = [r_data]

        # correlation searches have no _owner key
        if o_type != 'correlation_search':
            # fetch object being requested
            requested = extract(objects=r_data, key='_owner')

            self.logger.debug('Current User: %s', self.user)
            if not requested:
                # we dont have any objects to filter on, return
                return
            elif self.user in set(requested):
                self.logger.debug('Request to update private data. RBAC not applicable.')
                return

        o_store = (get_collection_name_for_itoa_object(o_type)
                   or get_collection_name_for_event_management_objects(o_type))
        ids_ = extract(objects=r_data, key=self.key)
        accessible = UserAccess.get_accessible_object_ids(
            self.user,
            self.operation,
            self.session_key,
            self.logger,
            object_ids=ids_,
            object_app='itsi',
            object_type=o_type,
            object_store=o_store
        )

        # some requests are for unnamed deepdives. these are saved directly from
        # the deep dive services endpoint and will have no ACL info...and I
        # think it doesnt make sense to save ACL info for them. Make an
        # exception for such objects...
        if (
            self.request.get_object_type() == 'deep_dive' and
            r_data.get('is_named') is not None and
            r_data['is_named'] is False
        ):
            accessible.append(self.request.get_object_ids()[0])

        if any([
                len(accessible) != len(ids_),
                set(accessible) != set(ids_)
                ]):
            not_accessible = [i.get('title', i.get(self.key)) for i in r_data if i.get(self.key) not in accessible]
            msg = _('You do not have permission to update the following object(s): {}').format(','.join(not_accessible))
            self.logger.error(msg)
            raise ITOAError(status=403, message=msg)
        self.logger.debug('Requested ids: %s are accessible.', ids_)
        return

    def handle_delete(self):
        """Handle RBAC for Delete.
        *. we will first GET the desired objects
        *. Query SA-UserAccess for accessibility of them
        *. If any of the desired are not accesssible, raise 403
        Allow otherwise...
        """
        self.logger.info('Received Request to Delete.')

        o_type = self.request.get_object_type()
        o_store = (get_collection_name_for_itoa_object(o_type)
                   or get_collection_name_for_event_management_objects(o_type))

        # only fetched named deep dives
        qp_filter = self.request.get_query_param().get_filter(stringify=False)
        filter_data = {} if not qp_filter else qp_filter
        if o_type == 'deep_dive':
            filter_data['is_named'] = True

        # correlation searches have no _owner key
        if o_type != 'correlation_search':
            r_data = self.fetch_requested_data(filter_data=filter_data)
            owners = extract(objects=r_data, key='_owner')
            req_is_private = True
            if 'nobody' in set(owners):
                req_is_private = False
            if req_is_private is True:
                self.logger.debug('Not applicable to private objects. %s. Returning', self.kwargs)
                return
        else:
            object_ids = self.request.get_object_ids()
            if object_ids:
                filter_data = {'OR': [{'name': i} for i in object_ids]}
                r_data = self.fetch_requested_data(filter_data=filter_data)
            else:
                r_data = []

        requested = extract(objects=r_data, key=self.key)
        accessible = UserAccess.get_accessible_object_ids(
            user=self.user,
            operation='delete',
            session_key=self.session_key,
            logger=self.logger,
            object_ids=requested,
            object_app=self.app,
            object_type=o_type,
            object_store=o_store
        )

        # manually convert glass_table/correlation_search dict into list
        if self.request.get_object_type() in ['glass_table', 'correlation_search']:
            if isinstance(r_data, dict):
                r_data = [r_data]

        # some requests are for unnamed deepdives. these are saved directly from
        # the deep dive services endpoint and will have no ACL info...and I
        # think it doesnt make sense to save ACL info for them. Make an
        # exception for such objects...
        if self.request.get_object_type() == 'deep_dive':
            if isinstance(r_data, dict):
                r_data = [r_data]
            for i in r_data:
                if i.get('is_named') is not None and i['is_named'] is False:
                    accessible.append(i[self.key])

        if any([
                len(accessible) != len(requested),
                set(accessible) != set(requested)
                ]):
            # some objects which are `deemed` to be inaccessible...
            # could be private objects... for such a case, lets iterate
            # through requested and append the requested pvt ids to accessible
            if o_type != 'correlation_search':
                for i in r_data:
                    if (i.get('_owner') and i['_owner']
                            == self.request.current_user):
                        accessible.append(i[self.key])
            if any([
                    len(accessible) != len(requested),
                    set(accessible) != set(requested)
                    ]):
                not_accessible = [i.get('title', i.get(self.key)) for i in r_data if i.get(self.key) not in accessible]
                msg = _('You do not have permission to delete the following object(s): {}').format(','.join(not_accessible))
                self.logger.error(msg)
                raise ITOAError(status=403, message=msg)
        msg = _('Requested ids: {} are accessible').format(requested)

        # delete the perms we had saved for this object...
        for i in requested:
            msg = _('Deleting perms for object_id=`%s` object_app=`%s object_type=`%s` object_store=`%s`').format(
                i,
                self.app,
                o_type,
                o_store
            )
            self.logger.debug(msg)
            UserAccess.delete_perms(
                object_id=i,
                object_app=self.app,
                object_type=o_type,
                object_storename=o_store,
                session_key=self.session_key,
                logger=self.logger
            )
        return

    def update_request(self, decorated, decorated_self, args):
        """
        Method that implements controller specific update of request info
        The default controller is assumed to be chrrypy
        Other controllers will override this method for specific implementation

        @type: reference
        @param decorated: the decorated function reference

        @type: reference
        @param decorated_self: the decorated function's self

        @type: tuple
        @param args: the decorated function's args

        @rtype: None
        @return: None
        """
        self.user = getCurrentUser()['name']
        # always use cherrypy session key if its available.
        self.session_key = cherrypy.session["sessionKey"]
        self.method = cherrypy.request.method
        self.request = Request(
            self.kwargs,
            self.method,
            self.logger,
            self.session_key,
            self.user
        )
        self.operation = self.request.get_operation(self.method)

    def initialize(self, decorated, decorated_self, args, kwargs):
        """
        Do some initialization
        @type decorated: function/method
        @param decorated: method being decorated

        @type decorated: reference
        @param decorated: reference to method being decorated

        @type decorated_self: reference
        @param decorated: self reference of the decorated method's class context

        @type args: list
        @param args: function args

        @type kwargs: dict
        @param kwargs: function kwargs
        @return nothing
        """
        self.args = args
        self.kwargs = kwargs
        self.update_request(decorated, decorated_self, args)
        self.op = ObjectOperation(self.logger, self.session_key, self.user)

    def __call__(self, decorated):
        def wrapper(decorated_self, *args, **kwargs):
            """
            Wrapper implementation for the decorator

            @type: reference
            @param decorated_self: the decorated function's self

            @type: tuple
            @param args: the decorated function's args

            @type: dict
            @param kwargs: the decorated function's kwargs

            @rtype: variable
            @return: results from executing the decorated function
            """
            # Note that self here is the decorator's self
            self.validate_input(kwargs, self.logger)

            if not isinstance(kwargs, dict):
                kwargs = self._get_obj(kwargs)

            self.initialize(decorated, decorated_self, args, kwargs)

            object_type = self.request.get_object_type()
            if self._is_event_management_object(object_type):
                self.op = EventManagementService(self.session_key)
            if object_type == 'correlation_search':
                self.key = 'name'
            else:
                self.key = '_key'
            if not self._is_enforceable():
                self.logger.debug('RBAC not applicable for `%s`', object_type)
                return decorated(decorated_self, *self.args, **self.kwargs)

            self.logger.info('RBAC is applicable for `%s`.', object_type)
            self.logger.info('Received Request for\nUser: `%s` Operation: `%s` Input Params: `%s`', (
                self.user,
                self.operation,
                self.kwargs
            ))

            local_kwargs = deepcopy(self.kwargs)

            if self.operation == 'read':
                self.handle_read()
            elif self.operation == 'write':
                if self.request.is_create():
                    self.handle_create()
                else:
                    self.handle_update()
            elif self.operation == 'delete':
                self.handle_delete()

            # data was popped out in get() function in event_management_rest_provider.py
            # so we try to keep a local copy here
            if not self.kwargs.get('data') and local_kwargs.get('data'):
                self.kwargs = local_kwargs

            # update filter if applicable:
            filter_ = self.request.get_query()
            if filter_:
                self.kwargs['filter'] = filter_

            self.logger.info('New params kwargs: %s', self.kwargs)
            return decorated(decorated_self, *self.args, **self.kwargs)
        return wrapper
