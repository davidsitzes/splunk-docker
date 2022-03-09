# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time
import json
import sys

from splunk import ResourceNotFound
from splunk.rest import simpleRequest
from splunk.util import normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.itoa_common import extract
from ITOA.storage.itoa_storage import ITOAStorage
from ITOA.event_management.notable_event_utils import Audit
from ITOA.event_management.notable_event_comment import NotableEventComment
from ITOA.event_management.notable_event_actions import NotableEventAction
from itsi_notable_event import ItsiNotableEvent
from ITOA.event_management.notable_event_group import NotableEventGroup


class ITSINotableEventActionsQueueConsumer(object):
    """
    An instance of this class implements a Consumer of a Queue.
    The Producer is primarily, the Rules Engine so far, but can be
    anyone.
    We leverage a KV Store Collection to "store" this Queue data.

    Usage:
        >>> consumer = ITSINotableEventActionsQueueConsumer(session_key, logger)
        >>> consumer.consume_forever()
        OR
        >>> consumer.consume_once()
    """

    def __init__(
        self,
        session_key,
        logger,
        exec_delay_value,
        instance_id,
        timeout,
        batch_count,
        collection='itsi_notable_event_actions_queue',
        audit_token_name='Auto Generated ITSI Notable Index Audit Token',
        audit_source='Notable Event Audit',
        audit_sourcetype='stash'
    ):
        """
        @type session_key: basestring
        @param session_key: splunkd issued authorization session key

        @type logger: logger
        @param logger: caller's logger object

        @type exec_delay_value: float
        @param exec_delay_value: Value(in seconds) to delay execution

        @type instance_id: basestring
        @param instance_id: instance who is running this instance. It is need to claim the job

        @type collection: basestring
        @param collection: kvstore collection which stores queue data

        @type audit_token_name: basestring
        @param audit_token_name: token name used for auditing. required for HEC,
            which is what we use to index audit data.
        """
        if not isinstance(session_key, basestring):
            raise TypeError(_('Invalid type for session_key. Received type="{}".').format(type(session_key).__name__))
        elif not session_key.strip():
            raise ValueError(_('Received empty session_key.'))

        if not logger:
            raise TypeError(_('Expecting valid logger'))

        if not isinstance(exec_delay_value, float):
            raise TypeError(_('exec_delay must be an float, not "{}"').format(type(exec_delay_value).__name__))

        type_msg = _('Invalid type for "{}". Expecting string type. Received value="{}" type="{}"')
        if not isinstance(collection, basestring):
            raise TypeError(type_msg.format('collection', collection, type(collection).__name__))
        elif not collection.strip():
            raise ValueError(_('Received empty value for collection name.'))

        if not isinstance(audit_token_name, basestring):
            raise TypeError(type_msg.format('audit_token_name', audit_token_name, type(audit_token_name).__name__))
        elif not audit_token_name.strip():
            raise ValueError(_('Received empty value for audit_token_name.'))

        if not isinstance(audit_source, basestring):
            raise TypeError(type_msg.format('audit_source', audit_source, type(audit_source).__name__))
        elif not audit_source.strip():
            raise ValueError(_('Received empty value for audit_source.'))

        if not isinstance(audit_sourcetype, basestring):
            raise TypeError(type_msg.format('audit_sourcetype', audit_sourcetype, type(audit_sourcetype).__name__))
        elif not audit_sourcetype.strip():
            raise ValueError(_('Received empty value for audit_sourcetype.'))

        if not isinstance(instance_id, basestring):
            raise TypeError(type_msg.format('instance_id', instance_id, type(instance_id).__name__))
        elif not audit_sourcetype.strip():
            raise ValueError(_('Received empty value for instance_id.'))

        self.session_key = session_key
        self.logger = logger
        self.storage = ITOAStorage(collection=collection)
        self.claimed_storage = ITOAStorage(collection="itsi_temp_batch_claimed_action_queue")
        self.claimed_batch_object_type = 'claimed_batch'
        self.owner = 'nobody'
        self.objecttype = 'action_queue_job'
        self.exec_delay_value = exec_delay_value
        self.auditor = Audit(self.session_key, audit_token_name=audit_token_name, audit_source=audit_source,
           audit_sourcetype=audit_sourcetype)
        # Wait for kvstore to be up
        if not self.storage.wait_for_storage_init(self.session_key):
            raise Exception(_('KVStore is not initialized'))

        self.instance_id = instance_id
        self.timeout = float(timeout) if timeout else 1800 #default 30 mins
        self.batch_count = int(batch_count) if batch_count else 5
        # Object initialization which is going to be used later
        self.itsi_notable_event_comment = NotableEventComment(self.session_key)
        self.notable_event_action = NotableEventAction(self.session_key, app='SA-ITOA', owner='nobody')
        self.itsi_notable_event = ItsiNotableEvent(self.session_key)
        self.itsi_notable_event_group = NotableEventGroup(self.session_key)
        # create initial registration of modular input, if end point already created then touch too
        self.check_and_save_module_id_kv_store(self.instance_id, is_touch=True)

    def _assign_jobs_to_this_instance(self, filter_data, batch_size=5):
        """
        Removing old claimed job based upon filter

        @type filter_data: basestring
        @param filter_data: filter_data which is used to get expired or stale claimed job

        @return: None
        """
        jobs = self.storage.get_all(
            self.session_key,
            self.owner,
            self.objecttype,
            filter_data=filter_data,
            limit=batch_size
        )

        if not jobs:
            return

        self.logger.debug('Removing claimed %s jobs', jobs)
        for job in jobs:
            job['id'] = self.instance_id
            job['timeout'] = time.time() + self.timeout

        return self.storage.batch_save(self.session_key, self.owner, jobs)

    def _claim_expired_job(self, batch_size=5):
        """
        Clean stale claimed job

        @return: None
        """
        if not batch_size:
            return
        # Get timeout jobs
        # Removed the claim
        filter_data = {'timeout': {'$lte': time.time()}}
        jobs = self._assign_jobs_to_this_instance(filter_data=filter_data, batch_size=batch_size)
        self.logger.info('Successfully re-claimed expired %s jobs with filter_data=%s by id=%s',
                         len(jobs) if jobs else 0, filter_data, self.instance_id)

    def _create_assignment_entry(self, batch_id):
        """
        Create batch id so consumer can claim its id
        @param batch_id: batch id
        @return: _key if entry is created properly
        """
        # Claimed batch id
        return self.claimed_storage.create(self.session_key, self.owner, self.claimed_batch_object_type,
                                           {'id': self.instance_id,
                                            'timeout': time.time() + self.timeout, '_key': batch_id},
                                           current_user_name="action_queue_consumer")

    def _claim_batch_id(self):
        """
        This functional first claimed batch id so same batch job are assigned to one consumer
        In this function first we get already assigned batch ids, if None then assign on

        @return: list of claimed batch ids or empty list/None
        """
        claimed_batch_ids = self.claimed_storage.get_all(
            self.session_key,
            self.owner,
            self.claimed_batch_object_type,
            fields=['_key'],
            filter_data={'id': self.instance_id})

        if claimed_batch_ids:
            return [batch_id.get('_key') for batch_id in claimed_batch_ids]

        skip = 0
        while True:
            # Assign at-least one batch id
            batch_ids = self.storage.get_all(
                self.session_key,
                self.owner,
                self.objecttype,
                sort_key="create_time",
                sort_dir="asc",
                limit=self.batch_count,
                skip=skip,
                filter_data={'$and': [{'create_time': {'$lte': time.time() - self.exec_delay_value}},
                            {'id': 'unclaimed'}]},
                fields=['_key', 'batch_id'])
            if not batch_ids:
                break
            # Unique ids
            batch_ids = set([batch_id.get('batch_id') for batch_id in batch_ids])
            for bid in batch_ids:
                try:
                    ret = self._create_assignment_entry(bid)
                    if ret:
                        return [ret.get('_key')] if isinstance(ret, dict) else ret
                except Exception as e:
                    self.logger.debug('Could not assigned batch id=%s, trying to claim another one', bid)
            skip += self.batch_count

        self.logger.info('Could not claimed any batch id to this modular input=%s', self.instance_id)
        return []

    def unclaimed_all_batch_ids(self):
        """
        Unclaimed all claimed batch id
        @return: None
        """
        # Unclaimed batch ids assigned to this instance
        filter_data = {'id': self.instance_id}
        self.claimed_storage.delete_all(self.session_key, self.owner, self.claimed_batch_object_type, filter_data)
        self.logger.info('Successfully unclaimed batch_ids, for instance=%s', self.instance_id)

    def claim_job_based_up_batch_ids(self, batch_size):
        """
        First claim a batch id and then assign jobs based up that batch id
        @param batch_size: batch size
        @return: Empty/valid list of claimed jobs
        """
        if not batch_size:
            self.logger.debug('Batch size is zero, hence instance=%s are not claiming the job', self.instance_id)
            return []

        batch_ids = self._claim_batch_id()
        if not batch_ids:
            return []
        # Assign unclaimed_job
        filter_data = {'$or': [{'batch_id': bid} for bid in batch_ids]}
        jobs = self._assign_jobs_to_this_instance(filter_data, batch_size)
        if not jobs:
            self.unclaimed_all_batch_ids()
            self.logger.info('Successfully unclaimed batch_ids=%s jobs', batch_ids)
            return []
        jobs = self._get_assigned_jobs(filter_data, batch_size)
        self.logger.info('Successfully assigned unclaimed_jobs=%s with filter=%s', len(jobs) if jobs else 0,
                         filter_data)
        return jobs

    def _get_assigned_jobs(self, filter_data, batch_size):
        """
        Return assigned job
        @param filter_data: filter
        @param batch_size: batch size
        @return: list of return jobs
        """
        # We should account for execute delay time while fetching job from the queue
        return self.storage.get_all(
            self.session_key,
            self.owner,
            self.objecttype,
            sort_key="create_time",
            sort_dir="asc",
            limit=batch_size,
            filter_data=filter_data)

    def claim_jobs(self, is_delete=False):
        """
        Perform the operation of Dequeue.

        @type is_delete: false
        @param is_delete - clear data from queue when this flag is set

        @rtype: list
        """

        filter_data = {'$and': [{'create_time': {'$lte': time.time() - self.exec_delay_value}},
                                {'id': self.instance_id}]}
        # We should account for execute delay time while fetching job from the queue
        jobs = self._get_assigned_jobs(filter_data, self.batch_count)

        # There is specific reason for handing cleaning expired job here so
        # it can assigned to itself now and execute already claimed job, so  we can minimize
        # race condition could caused by other modular input
        # claimed only when load is low
        remaining_batch_size = self.batch_count - (len(jobs) if jobs else 0)
        if remaining_batch_size != 0:
            # First claim only unassigned jobs
            unassigned_jobs = self.claim_job_based_up_batch_ids(remaining_batch_size)
            jobs.extend(unassigned_jobs) if unassigned_jobs else None
            # Claim only remaining batch size
            # Note - we are going to claimed only expired jobs only and execute it in next run
            # so we can normalized race condition which can be caused by multiple consumer
            self._claim_expired_job(remaining_batch_size - (len(unassigned_jobs) if unassigned_jobs else 0))

        # Lets do not clear here because if splunk restarted/stopped then we lose in-memory data, so we will delete it
        # from queue after execution
        if is_delete:
            self._clear_queue(extract(jobs, '_key'))

        self.unclaimed_all_batch_ids()
        self.logger.info('Claimed jobs=%s, by instance_id=%s', len(jobs) if jobs else 0, self.instance_id)
        return jobs

    def _clear_queue(self, ids, field_key='_key'):
        """
        Clear queue of given ids.

        @type ids: list
        @param ids: ids to clear from queue.

        @type field_key: basestring
        @param field_key: key which is used in the filter

        @return: Nothing
        """
        self.logger.debug('%s to delete length=%s, ids=%s', field_key, len(ids) if ids else 0, ids)
        if not ids:
            self.logger.info('No jobs=%s to delete', ids)
            return

        # we will delete all of these ids. We will need to construct a kv store filter
        # for the same
        filter_ = {'$or': [{field_key: id_} for id_ in ids]}
        self.logger.debug('Created delete_all filter=%s by instance_id=%s', filter_, self.instance_id)
        self.storage.delete_all(
            self.session_key,
            self.owner,
            self.objecttype,
            filter_
        )

    def _invoke_uris(self, objs):
        """
        Supporting function for _consume_batch, refer that function for more information

        @type objs: list
        @param objs: object to consume

        @rtype tuple (boolean, string)
        @return: True on success, False on failure. Message indicating more verbose.
        """
        if not isinstance(objs, list):
            self.logger.error('Invalid objects to consume')
            return False, 'Invalid objects list to consume'
        for obj in objs:
            path = obj.get('uri')
            method = obj.get('method')
            if not isinstance(path, basestring) or not isinstance(method, basestring):
                self.logger.warn('Invalid path=%s or method=%s', path, method)
                return False, 'Invalid path or method'

            # Post and getArgs
            jsonargs = None
            getargs = None
            is_success = False
            content = json.loads(obj.get('content', {}))

            if method and method.upper() == 'GET':
                getargs = content
            if method and method.upper() == 'POST':
                jsonargs = content

            response, content = simpleRequest(path, self.session_key, getargs=getargs, jsonargs=json.dumps(jsonargs))
            if response.status in [200, 201]:
                is_success = True
                self.logger.info('Successfully executed action=%s', path)
            else:
                self.logger.info('Failed to run action=%s, return code=%s, content=%s',path, response, content)
            return is_success, _("Successfully executed actions={}.").format([obj.get('uri') for obj in objs])

    def _handle_notable_event_group_state(self, data_list):
        """
        Supporting function for consume_batch
        @type data_list: list
        @param data_list: data to process

        @rtype: tuple
        @return: tuple of status and message
        """
        # Get which is create or update based upon group_id key existence
        create_list = []
        update_list = []
        for data in data_list:
            if 'group_id' in data:
                create_list.append(data)
            else:
                update_list.append(data)
        final_ret = []
        if update_list:
            ret = self.itsi_notable_event_group.update_bulk([data.get(self.itsi_notable_event_group.id_key)
                                                            for data in update_list], update_list)
            final_ret.append(ret)
        if create_list:
            ret = self.itsi_notable_event_group.create_bulk(create_list)
            final_ret.append(ret)
        return len(final_ret) > 0 if final_ret else False, _('Successfully executed action=notable_event_group_state_change,' \
                                   ' updated/create group state={}.').format(final_ret)

    def check_and_save_module_id_kv_store(self, module_id, is_touch=False):
        """
        Check and register module id

        @type module_id: basestring
        @param module_id: module id

        @type is_touch: bool
        @param is_touch: update mod_time of register to tell producer that it's alive

        @return: tuple of response and content
        """
        path = '/servicesNS/nobody/SA-ITOA/storage/collections/data/itsi_notable_event_actions_queue/'
        uri = path + '/' + module_id
        try:
            response, content = simpleRequest(uri, self.session_key)
            if response.status != 200:
                raise Exception(_('Failed to fetch consumer_registration object %s') % self.instance_id)
        except ResourceNotFound:
            # Create one in same manner like touching endpoint
            is_touch = True
            uri = path

        if is_touch:
            json_args = {'_key': module_id, 'object_type': 'consumer_registration', 'mod_time': time.time()}
            response, content = simpleRequest(uri, self.session_key, jsonargs=json.dumps(json_args), method='POST')
            if response.status not in [200, 201]:
                raise Exception(_('Failed to save modular input id to kvstore'))
            return response, content

    def _handle_notable_event_actions(self, objects):
        """
        Supporting function for consume_batch
        @type objects: list
        @param objects: job objects to process

        @rtype: tuple
        @return: tuple of status and message

        """
        actions = []
        for obj in objects:
            uri = obj.get('uri', '')
            action_name = uri.rsplit('/')[-1] if not uri.endswith('/') else uri.rsplit('/')[-2]
            content = json.loads(obj.get('content', {}))
            if action_name and isinstance(content, dict):
                content['name'] = action_name
            actions.append(content)
        ret_data = self.notable_event_action.execute_actions(actions)
        return len(ret_data) > 0 if ret_data else False, _('Successfully action=executed notable_event_action, ret_data={}.').format(ret_data)

    def _handle_notable_event_change_of_group(self, objects, audit_data, activities):
        """
        Supporting function for consume_batch
        @type objects: list
        @param objects: job objects to process

        @type: list
        @param audit_data: audit data to add

        @type: list
        @param activities: activity information to add
        """
        # Bulk operation endpoint is not available
        for obj in objects:
            input_data = json.loads(obj.get('content', {}))
            ret = self.itsi_notable_event.update_group_events(
                    input_data.pop('group_id', None),
                    input_data.pop('fields_to_update', None),
                    input_data.pop('event_filter', None),
                    **input_data
            )
            is_success = True if ret else False
            if is_success:
                msg = _('Successfully executed action=notable_event_change, ret={}.').format(ret)
            else:
                msg = _('Failed to get associated events of group (notable_event_change action), ret={}.').format(ret)
            self._get_audit_data([obj], is_success, msg, audit_data, activities)
            self.logger.debug('Successfully updated %s events of group_information=%s', len(ret) if ret else 0,
                              input_data)

    def _consume_batch(self, objects):
        """
        Finally, consume objects.

        @type objects: list
        @param objects: objects to consume

        @rtype None
        @return: None
        """
        if not isinstance(objects, list):
            self.logger.error('Invalid objects to consume')
            return False, 'Invalid objects list to consume'

        audit_data = []
        activities = []
        activity_type = 'Action executed via ITSI Notable Events Action Queue Consumer id={}'.format(self.instance_id)

        # Create group based upon sub_object_type
        group = {}
        for item in objects:
            if item.get('sub_object_type') in group:
                group[item.get('sub_object_type')].append(item)
            else:
                group[item.get('sub_object_type')] = [item]
        try:
            for obj_type, type_objects in group.iteritems():
                data_list = [json.loads(obj.get('content', {})) for obj in type_objects]
                if obj_type == 'notable_event_action':
                    is_success, msg = self._handle_notable_event_actions(type_objects)
                    self._get_audit_data(type_objects, is_success, msg, audit_data, activities)
                elif obj_type == 'notable_event_change':
                    ret = self.itsi_notable_event.update_bulk([data.get(self.itsi_notable_event.id_key)
                                                               for data in data_list], data_list)
                    msg = _('Successfully executed action={0}, ret_data={1}.').format(obj_type, ret)
                    self._get_audit_data(type_objects, True, msg, audit_data, activities)
                elif obj_type == 'notable_event_change_in_group':
                    self._handle_notable_event_change_of_group(type_objects, audit_data, activities)
                elif obj_type == 'notable_event_comment':
                    is_success = True
                    data_list_without_group = []
                    for data in data_list:
                        if normalizeBoolean(data.get('_is_group')):
                            # Run it inline because there is no bulk action available
                            ret = self.itsi_notable_event_comment.create_for_group(data)
                            is_success = is_success and True if len(ret) > 0 else False
                        else:
                            data_list_without_group.append(data)
                    ret = self.itsi_notable_event_comment.create_bulk(data_list_without_group)
                    is_success = is_success and True if len(ret) > 0 else False
                    msg = _('Successfully executed action={0}.').format(obj_type)
                    self._get_audit_data(type_objects, is_success, msg, audit_data, activities)
                elif obj_type == 'notable_event_group_state_change':
                    is_success, msg = self._handle_notable_event_group_state(data_list)
                    self._get_audit_data(type_objects, is_success, msg, audit_data, activities)
                else:
                    self.logger.info('Invalid object_type=%s, hence invoking uri directly', obj_type)
                    is_success, msg = self._invoke_uris(type_objects)
                    self._get_audit_data(type_objects, is_success, msg, audit_data, activities)
        except Exception as e:
            self.logger.exception(e)
            msg = _('Failed to run action on instance_id={0}, exception={1}.').format(self.instance_id, str(e))
            self._get_audit_data(type_objects, False, msg, audit_data, activities)
        finally:
            # Lets delete with same transaction id (implies duplicate request)
            self._clear_queue([obj.get('transaction_id') for obj in objects], 'transaction_id')
            self.logger.info('Successfully deleted objects=%s of instance_id=%s', len(objects) if objects else 0,
                             self.instance_id)
            # Audit
            self.auditor.send_activity_to_audit_bulk(audit_data, activities, activity_type)

    @staticmethod
    def _get_audit_data(objects, success_flag, message, audit_data, activities):
        """
        Get audit data
        @type objects: list
        @param objects: list of objects to add audit log about with message and success-flag

        @type success_flag: boolean
        @param success_flag: success flag

        @type message: basestring
        @param message: message

        @type audit_data: list
        @param message: list which hold audit logging

        @type activities: list
        @param activities: list which hold activity information
        """
        for obj in objects:
            audit_data.append({
                'uri': obj.get('uri', ''),
                'content': obj.get('content', ''),
                'method': obj.get('method', ''),
                'query': obj.get('query', ''),
                'transaction_id': obj.get('transaction_id', ''),
                'object_creator': obj.get('object_type','rules_engine'),
                'object_create_time': obj.get('create_time'),
                'audit_creator': 'itsi_notable_event_actions_queue_consumer',
                'exec_status': normalizeBoolean(success_flag),
                'exec_message': message
            })
            activities.append('Issued REST request="{}". Method="{}" Query="{}" Body="{}"'.format(
                obj.get('uri', ''), obj.get('method', ''), obj.get('query', ''), obj.get('content', '')
                )
            )

    def consume_once(self):
        """
        Consume all available objects from queue. Consumption entails:
            1. claim job from queue for available objects
            2. Consume each object.
            3. Audit information about consumed objects in audit index.
            Audit will contain both successfully and unsuccessfully consumed objects.
        @rtype: int
        @return: count of objects that were consumed.
        """
        objects = self.claim_jobs()

        if not objects:
            self.logger.debug('No job to process of instance_id=%s', self.instance_id)
            return 0
        self._consume_batch(objects)
        return len(objects) if objects else 0

    def consume_forever(self):
        """
        Consume available objects forever.
        """
        # Let stop if there is no job to process for 5 min
        timeout = 900
        # Do not want to refresh too frequently when there is no job to process
        refresh_rate = 120 # 2 minutes
        refresh_time = time.time()
        try:
            while timeout > 0:
                self.logger.debug('Started fetching job for instance_id=%s', self.instance_id)
                count = self.consume_once()
                self.logger.debug('Successfully completed number of jobs=%s of instance_id=%s', count, self.instance_id)
                # sleep for a few seconds if no data was consumed.
                if not count:
                    time.sleep(1)
                    timeout -= 1
                if time.time() - refresh_time >= refresh_rate:
                    # Touch end point now before executing new batch
                    self.check_and_save_module_id_kv_store(self.instance_id, True)
                    # reset start time
                    refresh_time = time.time()

            else:
                self.logger.info('No job for process, hence shuting down now, will restart automatically after given'
                                 'interval ')
        except Exception, e:
            self.logger.exception('Exception when consuming. "%s"', e)
            raise# modular input should catch this and log
#
