# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time

from splunk.appserver.mrsparkle.lib import i18n
from splunk.search import dispatch, waitForJob
from splunk.auth import getCurrentUser
from splunk.util import normalizeBoolean

from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_current_utc_epoch
from notable_event_utils import Audit, MethodType
from base_event_management import BaseEventManagement

class NotableEventComment(BaseEventManagement):
    """
    Class to create, update, get and delete comments
    Use to store notable event comments
    {
        _key: Random key
        event_id: <event id>
        owner: <which was create comments at first time>,
        user: <user id>,
        create_time: epoch time,
        mod_time: epoch time,
        comment: <comment string>
        object_type: notable_event_comment
    }

    Note: this code chunk would be similar to tag code but I kept is different because logic may change along
        the line of new feature requirement so I kept it different then share that code.
    """

    def __init__(self, session_key, current_user_name=None, collection='itsi_notable_event_comment',
                 object_type='notable_event_comment', user='nobody',
                 audit_token_name='Auto Generated ITSI Notable Index Audit Token', **kwargs):
        """
        Initialize
        @param session_key: session key
        @param collection: collection name
        @param object_type: object type
        @param user: user context to save
        @param audit_token_name: audit token to used to send to audit logging
        @param kwargs: extra args
        @return:
        """
        # Initialized base event object
        super(NotableEventComment, self).__init__(
            session_key, collection, object_type, user, current_user_name
        )
        self.audit = Audit(self.session_key, audit_token_name=audit_token_name,
                           audit_host=kwargs.get('audit_host'),
                           audit_source=kwargs.get('audit_source', 'Notable Event Audit'),
                           audit_sourcetype=kwargs.get('audit_sourcetype', 'stash'))

        self.filter_key = 'filter_search'
        self.event_id_key = 'event_id'
        self.comment_key = 'comment'
        self.mod_time_key = 'mod_time'
        self.create_time_key = 'create_time'
        self.user_key = 'user'
        self.owner_key = 'owner'
        self.logger = setup_logging('itsi_event_management.log', 'itsi.notable_comment.tag')

    def pre_processing(self, data_list, method):
        """
        Perform check and also add user and time information in the stanza

        @type data_list: list
        @param data_list: list of data to validate and add time, user info etc

        @type method: basestring
        @param method: method type

        @rtype: list
        @return: It updates list in place and also return it back as well
        """
        if not isinstance(data_list, list):
            raise TypeError(_('Data is not a valid list, data_list type is %s'), type(data_list))
        for data in data_list:
            # Make sure data is valid dict
            if not isinstance(data, dict):
                raise TypeError(_('Data is not a valid dictionary.'))
            session_user = getCurrentUser().get('name')
            user = session_user if session_user else self.owner
            time_value = get_current_utc_epoch()
            if method == MethodType.CREATE:
                if not (self.event_id_key in data and self.comment_key in data):
                    message = _('data does not contain either %s or %s') % (self.event_id_key, self.comment_key)
                    self.logger.error(message)
                    raise TypeError(message)
                # Add mod time, create time
                data[self.create_time_key] = time_value
                data[self.owner_key] = user
            if method != MethodType.DELETE:
                # Need to set it for create and update
                data[self.mod_time_key] = time_value
                data[self.user_key] = user
        return data_list


    def clean_comment(self, comment):
        #Per ITOA-5624 - Rewrite what gets passed in to be just event_id and comment
        #This just means to extract the event id and comment keys and nothing else
        return {self.event_id_key: comment.get(self.event_id_key, ''),
                self.comment_key: comment.get(self.comment_key, '')}

    def create(self, data, **kwargs):
        """
        Create new comment

        @type data: dict
        @param data: data which hold comment and event id in format of
            {
             'event_id'     : <event id>,
             'comment'      : <comment string>
             }

        @type kwargs: dict
        @param kwargs: kv args which holds extra settings

        @rtype: dict {'_key': <key>}
        @return: id of generated comment document
        """
        result = super(NotableEventComment, self).create(data, **kwargs)

        self.audit.send_activity_to_audit(self.clean_comment(data),
            'New comment="%s" is created'%data.get(self.comment_key), 'Comment created')
        return result

    def create_for_group(self, data, **kwargs):
        """
        Method for creating comments for a notable event group.
        It triggers a splunk search and then goes on to do stuff. Hence the
        special handling.

        @type data: dict
        @param data: data which hold comment and group id in format of
            {
             'event_id'     : <group id>,
             'is_group'     : <boolean>,
             'filter_search': <string>,
             'earliest_time': <earliest time, string>,
             'latest_time'  : <latest time, string>,
             'comment'      : <comment string>
             }
             we trigger a splunk search and fetch event_ids
                 corresponding to this group. There is also a `filter_str` which
                 is appeneded when triggering the search.
                 Then, for each event in the search output, we create a comment.

        @type kwargs: dict
        @param kwargs: kv args which holds extra settings

        @rtype: list [{'_key': <key>},...]
        @return: ids of generated comment documents
        """

        # handle event_id as group_id
        comment_str = data.get(self.comment_key)
        filter_search = data.get(self.filter_key, '') # assume a prepended `AND`
        group_id = data.get(self.event_id_key)


        # trigger a splunk search and fetch all corresponding event_ids
        search = 'search index=itsi_tracked_alerts [search index=itsi_grouped_alerts itsi_group_id="{0}" |' \
                 ' table event_id] | lookup itsi_notable_event_state_lookup _key AS event_id OUTPUT severity' \
                 ' AS lookup_severity, owner AS lookup_owner, status AS lookup_status |' \
                 ' eval severity=if(isnull(lookup_severity), severity, lookup_severity),' \
                 ' status=if(isnull(lookup_status), status, lookup_status), owner=if(isnull(lookup_owner),' \
                 ' owner, lookup_owner) | fields - lookup_* | search {1} | table event_id'.format(group_id,
                                                                                                  filter_search)
        job = dispatch(search,
                sessionKey=self.session_key,
                owner='nobody',
                earliestTime=data.get('earliest_time'), # None is OK.
                latestTime=data.get('latest_time') # None is OK.
                )
        waitForJob(job)

        comments = []
        bulk_data = []
        activities = []
        for result in job.results:
            data = {
                'event_id': str(result.get('event_id')), #str typecast; `get` returns ResultSetField
                'comment': comment_str
                }
            bulk_data.append(data)
            comments.append(data)
            activities.append('New comment=`%s` created.' % comment_str)

        if not bulk_data:
            self.logger.info('No search results found for=`%s`. Bailing out.', search)
            return []

        result = super(NotableEventComment, self).create_bulk(bulk_data, **kwargs)

        #Per ITOA-5624 - Rewrite what gets passed in to be just event_id and comment
        bulk_data = [self.clean_comment(x) for x in bulk_data]
        self.audit.send_activity_to_audit_bulk(bulk_data, activities, 'Comment created for Group.')
        return result

    def get(self, object_id, **kwargs):
        """
        Get operation can be supported for both _key and event_id. User either get only one comment by passing object_id
        as _key of KV store or object_id can be passed as event_id to get all comments of given event_id - only caveat is
        that user needs to 'is_event_id' flag to true. Default this flag is false

        @param object_id:
        @param kwargs:
        @return:
        """
        if not isinstance(object_id, basestring):
            raise TypeError(_('object_id=%s is not valid string.') % object_id)
        is_event_id = normalizeBoolean(kwargs.get('is_event_id', False))
        if is_event_id:
            filter_data = {'$or': [{self.event_id_key: object_id}]}
            return super(NotableEventComment, self).get_bulk(None, filter_data=filter_data)
        else:
            return super(NotableEventComment, self).get(object_id)

    def update(self, object_id, data, is_partial_update=False, **kwargs):
        """
        Update any existing comments

        Note: object_id is _key of kv store which stores comment itself

        @type object_id: basestring
        @param object_id: object id

        @type data: dict
        @param data: data

        @type is_partial_update: bool
        @param is_partial_update: flag to do partial update

        @type kwargs: dict
        @param kwargs: Extra parameters

        @rtype: dict
        @return: return dict which holds updated keys
        """
        self.logger.info('Updating %s comment', object_id)
        result = super(NotableEventComment, self).update(object_id, data, is_partial_update=is_partial_update, **kwargs)
        self.audit.send_activity_to_audit(self.clean_comment(data),
            'comment="%s" updated.' % data.get(self.comment_key), 'Comment updated.')
        return result

    def delete(self, object_id, **kwargs):
        """
        Delete is support for both (_key and event_id).
        User either delete only one comment by passing object_id as _key of KV store
        or object_id is passed as event_id to delete all comments of given event_id only caveat is that user needs
        to 'is_event_id' flag to true. Default value is False

        @type object_id: basestring
        @param object_id: object id

        @type kwargs: dict
        @param kwargs: extra params

        @return: None
        """
        if not isinstance(object_id, basestring):
            raise TypeError(_('object_id=%s is not valid string.') % object_id)

        is_event_id = normalizeBoolean(kwargs.get('is_event_id', False))
        if not is_event_id:
            self.logger.debug('Deleting comments with key=%s', object_id)
            comment = self.get(object_id, **kwargs)
            super(NotableEventComment, self).delete(object_id, **kwargs)

            self.audit.send_activity_to_audit(self.clean_comment(comment),
                'Deleted comment=`%s`.' % comment.get(self.comment_key), 'Comment deleted.')
        else:
            self.logger.debug('Deleting comments with for event=%s', object_id)
            filter_data = {'$or': [{self.event_id_key: object_id}]}
            comments = self.get(object_id, filter_data=filter_data, **kwargs)
            super(NotableEventComment, self).delete_bulk(object_id, filter_data=filter_data, **kwargs)
            for comment in comments:
                self.audit.send_activity_to_audit(self.clean_comment(comment),
                    'Deleted comment=`%s`' % comment.get(self.comment_key), 'Comment deleted.')

    def create_bulk(self, data_list, **kwargs):
        """
        To bulk create comments
        @type data_list: list
        @param data: data which hold array of comment and event id in format of
        [{
             'event_id' : <event id>,
             'comment' : <comment string>
        }]
        @type kwargs: dict
        @param kwargs: kv args which holds extra settings

        @rtype: list [<keys>]
        @return: ids of generated comment documents
        """
        if not isinstance(data_list, list):
            raise TypeError(_('Array of comments expected'))
        result = super(NotableEventComment, self).create_bulk(data_list, **kwargs)
        # audit does not have bulk send activity hence the iteration
        activities = []
        for data in data_list:
            activities.append('New comment=`%s` is created.'%data.get(self.comment_key))
        self.audit.send_activity_to_audit_bulk(data_list, activities,  'Comment created')
        return result

    def get_bulk(self, object_ids, **kwargs):
        raise NotImplementedError(_('%s operation is not supported for this %s object type') % ('get_bulk',
                                                                                           self.object_type))

    def update_bulk(self, object_ids, data_list, is_partial_update=False, **kwargs):
        raise NotImplementedError(_('%s operation is not supported for this %s object type') % ('update_bulk',
                                                                                           self.object_type))

    def delete_bulk(self, object_ids, **kwargs):
        raise NotImplementedError(_('%s operation is not supported for this %s object type') % ('delete_bulk',
                                                                                           self.object_type))
