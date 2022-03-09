# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
The KVStore queue worker (can be renamed at any time if a better label is found).  It's a way
for us to implement a worker that can work across any search head (or wherever), pulling jobs
from a centralized kvstore queue.  This is only a consumer, other tasks will grab from the
specified queue

Designed so that it can work on any splunk instance, not just those with an SHC leader - the
cost of this is that the entire system may end up doing extra work

The only big problem remainint - how to deal with multiple
"""
from time import time, sleep

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.storage.statestore import StateStore

DUPLICATE_LOOK_BACK_LIMIT = 100


class KVStoreQueueConsumer(object):
    """
    Main consumption class.  The KVStoreQueueConsumer treats the kvstore as a queue and allows anything
    to be consumed by it.  It supports one or two methods.  The first is just to process a single request.
    The second is to separate things out into a process and commit method.  The commit will ONLY be run
    if the ownership is verified, making it more valuable for actions that can be performed once
    """

    def __init__(self, session_key, logger, uid, queue_collection, metadata_collection, sort_field,
                 sort_order, object_type, job_process_object, job_process_method, job_preprocess_method,
                 job_commit_method):
        """
        @param session_key: The splunkd session key
        @type session_key: string

        @param logger: Where we want to log stuff to
        @type logger: A logging object

        @param uid: The UID that identifies us as the consumer
        @type uid: string

        @param queue_collection: The kvstore collection that is turned into a queue, expected to
                                 have the sort field so that it can pull different data
        @type queue_collection: string

        @param metadata_collection: The kvstore collection that handles queue metadata
        @type metadata_collection: string

        @param sort_field: The field to sort on for the queue, determines priority order
        @type sort_field: string

        @param sort_order: 'ascending' or 'decending' on the sort field
        @type sort_order: string

        @param job_process_object: Python Object that does the transforms and stores final state
        @type job_process_object: Instance of python class


        @type job_process_method: Callable of job_process_object
        @param job_process_method: A callable that takes the entire structure received from the
                                  kvstore
        @type job_process_method: string

        @param job_commit_method: Callable that commits any changes from the object
        @type job_commit_method: string
        """
        self.session_key = session_key
        self.logger = logger
        self.uid = uid
        self.queue_collection = queue_collection
        self.metadata_collection = metadata_collection
        self.sort_field = sort_field
        self.sort_order = sort_order
        self.job_process_object = job_process_object
        self.job_process_method = job_process_method
        self.job_preprocess_method = job_preprocess_method
        self.job_commit_method = job_commit_method
        self.object_type = object_type

        # Create the statestore interface
        self.jobs = StateStore(collection=self.queue_collection)
        self.metadata = StateStore(collection=self.metadata_collection)
        self.key = None

    def block_until_ready(self, waitTime=None, interval=None):
        """
        Poll and sleep until the kvstore has shown itself to be ready.
        @param waitTime: An approximate time to wait.
        @return: Boolean indicating success, will not return if waitTime is none
        @rtype: True, False
        """
        self.logger.debug("Blocking until ready uid=%s", self.uid)
        if interval is None:
            interval = 5
        start_time = time()
        status = True
        # first time check to avoid the wait, a little sloppy, I know
        if self.jobs.is_available(self.session_key):
            self.logger.debug("Ready uid=%s", self.uid)
            return True
        while status:
            sleep(interval)
            end_time = time()
            if self.jobs.is_available(self.session_key):
                break
            if waitTime is not None and end_time - start_time > waitTime:
                status = False
        self.logger.debug("Ready status=%s uid=%s", status, self.uid)
        return status

    def take_job(self):
        """
        Grabs the job that comes up first in the sort
        """
        self.logger.debug("Querying job uid=%s", self.uid)
        # We can't always get just our select fields, because we may pass this to a different handler if we reclaim it"
        jobs = self.jobs.get_all(
            self.session_key,
            'nobody',
            self.object_type,
            sort_key=self.sort_field,
            sort_dir=self.sort_order,
            limit=100,
            skip=0
        )

        my_job = None
        for job in jobs:
            processor = job.get('processor', None)
            if processor is not None and processor != self.uid:
                # Somebody else is processing this
                continue
            if processor is None:
                key = job['_key']
                # We're reassigning the variable here, filling it in with the real values
                job = self.jobs.get(self.session_key, 'nobody', self.object_type, key)
                if job is None:
                    # The job may have been deleted out from under us, and no longer exists
                    # If it was processed dramatically faster than this worker can handle.
                    # A possibility in highly latent environments
                    # This is fine, just claim a new job
                    continue
                if job.get('processor') is None:
                    # Make a legitimate claim on the job
                    job['processor'] = self.uid
                    my_job = job
                    # Make sure that others know this is yours
                    self.jobs.edit(self.session_key, 'nobody', self.object_type, key, job)
                    self.logger.debug("Claiming job key=%s uid=%s", key, self.uid)
                    # In theory it is now ours
                    break
            else:
                # We're likely to hit this inside of a restart or shutdown, where we were
                # In the middle of processing a job and then bonked.  Reclaim it
                self.logger.debug("Relaiming job key=%s uid=%s", job['_key'], self.uid)
                my_job = job
                break

        # If no jobs were found, return None
        if my_job is None:
            self.logger.debug("No jobs found uid=%s", self.uid)
            self.key = None
            return None

        self.key = my_job['_key']
        self.logger.debug("Taking job key=%s uid=%s", self.key, self.uid)
        return my_job

    def check_ownership(self):
        """
        Check and see if we can submit the PR.  If the value that we have for the job is still
        set, then we have taken the job object and can
        """
        # Before we commit anything, verify that we so indeed own the job in question
        job = self.jobs.get(self.session_key, 'nobody', self.object_type, self.key)
        if job is None or job.get('processor') != self.uid:
            # This can either not exist or belong to somebody else
            # Both are problems
            self.logger.debug("Job is not owned by us key=%s uid=%s", self.key, self.uid)
            return False
        self.logger.debug("Ownership verified for key=%s uid=%s", self.key, self.uid)
        return True

    def process_job(self):
        """
        Take the job out of the queue, process it, check if we can still have ownership or if there
        was a race condition.  If so, commit the job and take another one
        """
        job_data = self.take_job()
        if job_data is None:
            self.logger.debug("No pending jobs found uid=%s", self.uid)
            sleep(1)
            return True
        processor = getattr(self.job_process_object, self.job_process_method, None)
        if not processor:
            raise Exception(_("Could not find processing method method=%s uid=%s.") % (self.job_process_method, self.uid))
        if not callable(processor):
            raise Exception(_("The processing object is not callable method=%s uid=%s.") %
                            (self.job_process_method, self.uid))
        if not self.check_ownership():
            self.logger.warning("Detected duplicate claim method=%s key=%s uid=%s", self.job_process_method, self.key,
                                self.uid)
            return False
        try:
            preprocessor = getattr(self.job_process_object, self.job_preprocess_method, None)
            if preprocessor and callable(preprocessor):
                # We don't want to get the whole collection because we don't necessarily want to delete ALL duplicates.
                # That can lead to a long time period in which the objects are out of sync
                duplicate_jobs = preprocessor(job_data, self._get_all_unhandled_jobs(DUPLICATE_LOOK_BACK_LIMIT))
                num_duplicates = len(duplicate_jobs)
                if num_duplicates > 0:
                    # Keep the last one in the queue so the job will be eventually taken care of
                    job_to_keep = duplicate_jobs[-1]
                    keys_to_delete = [job.get('_key') for job in duplicate_jobs[:num_duplicates - 1]]
                    keys_to_delete.append(self.key)
                    self.logger.debug("Deleting duplicate jobs, duplicate_job_keys={} Keeping latest job,"
                                     "kept_job_key={}".format(keys_to_delete, job_to_keep.get('_key')))

                    # Delete duplicate jobs including the one currently processing
                    self._delete_jobs(keys_to_delete)
                    return True
            processor(job_data)
        except Exception:
            # TODO: Log something here, don't know
            self.logger.exception("Exception while processing job uid=%s", self.uid)
            self.logger.error("Removing failed job key=%s uid=%s", self.key, self.uid)
            self.jobs.delete(self.session_key, 'nobody', self.object_type, self.key)
            return False
        # Now, the job has been processed, the data is in the object
        if not self.check_ownership():
            # TODO: Log the wasted effort, we will want to minimize this if possible
            self.logger.debug("Detected unsanctioned owner method=%s key=%s uid=%s", self.job_process_method, self.key,
                              self.uid)
            return False

        if self.job_commit_method is not None:
            commit = getattr(self.job_process_object, self.job_commit_method, None)
            if not commit:
                raise Exception(_("Could not find commit method %s.") % self.job_commit_method)
            commit()

        if self.key is None:
            self.logger.warning("Successfully processed key=%s uid=%s", self.key, self.uid)
            return False
        self.jobs.delete(self.session_key, 'nobody', self.object_type, self.key)
        self.logger.debug("Successfully processed key=%s uid=%s", self.key, self.uid)
        return True

    def _get_all_unhandled_jobs(self, limit):
        """
        Get all jobs in the queue that is not being processed, i.e. doesn't have processor
        @return: List of refresh job objects
        @rtype: List
        """

        return self.jobs.get_all(
            self.session_key,
            'nobody',
            self.object_type,
            sort_key=self.sort_field,
            sort_dir=self.sort_order,
            filter_data={'processor': None},
            limit=limit,
            skip=0
        )

    def _delete_jobs(self, job_keys):
        """
        Deletes jobs with specific ids. This is not a bulk delete with a filter
        @param job_keys: list of keys of the jobs that we want to delete
        @return: None
        """
        for key in job_keys:
            try:
                self.jobs.delete(self.session_key, 'nobody', self.object_type, key)
            except Exception as e:
                self.logger.error("Exception while deleting jobs: {}".format(e.message))
