# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
This module implements a refresh queue utility to enable object consistency management.
Interfaces exposed act as utility methods to abstract processing of refresh queue.
"""

# Python Imports
import time

from splunk.appserver.mrsparkle.lib import i18n
# pylint: disable = import-error
from ITOA.storage import statestore
from .itoa_config import get_registered_change_handlers
# pylint: enable = import-error

from ITOA.setup_logging import InstrumentCall

class RefreshQueueAdapter(object):
    '''
    Provides an interface to set get and delete refresh queue entries
    '''

    def __init__(self, session_key):
        self.statestore = statestore.StateStore(collection="itsi_refresh_queue")
        self.statestore.lazy_init(session_key)
        self.session_key = session_key
        self.owner = "nobody"
        self.objecttype = "refresh_job"
        self.logger = None

    def create_refresh_job(
            self,
            change_type,
            changed_object_key,
            changed_object_type,
            change_detail=None,
            transaction_id=None,
            synchronous=False
    ):
        '''
        Creates a record in the refresh queue for the given change type, with the key and
        the type of changed object as well as the other required fields.
        Final refresh job object looks like:
            {
                _key: <generated by statestore>,
                change_type: <identifier of the change used to pick change handler>,
                changed_object_key: <Array of changed objects' keys>,
                changed_object_type: <string of the type of object>,
                create_time: <epoch timestamp>,
                change_detail: dict of whatever user sends
                object_type: "refresh_job"
            }

        @param change_type: a string of the change descriptor/type/identifier
        @type change_type: str
        @param changed_object_key: The key or list of keys for the changed objects
        @type changed_object_key: str|list
        @param changed_object_type: the type of ITSI object(s) changed
        @type changed_object_type: str
        @param change_detail: any extra information the change handler could use
        @type change_detail: dict (by convention, not enforced)

        @param transaction_id: The transaction id used to trace a user request all the way through the system
        @type transaction_id: String

        @param synchronous: A parameter to ignore the refresh queue entirely and process synchronously
        @type synchronous: Boolean

        @return: True if successful, False otherwise.  For synchronous jobs, successful jobs mean everything is done
        @rtype: bool
        '''
        if change_detail is None:
            change_detail = {}

        if change_type is None or changed_object_key is None or changed_object_type is None:
            raise TypeError(_("Problem with input to create_refresh_job"))

        if not isinstance(changed_object_key, list):
            changed_object_key = [changed_object_key]

        data = {
            "create_time": time.time(),
            "change_type": change_type,
            "changed_object_key": changed_object_key,
            "changed_object_type": changed_object_type,
            "change_detail": change_detail,
            "transaction_id": transaction_id
            }

        if synchronous:
            handler_manifest = get_registered_change_handlers()
            handler_class = handler_manifest.get(data.get("change_type"))
            handler_class(self.logger, self.session_key)
            handler.assert_valid_change_object(data)
            return handler.deferred(data, transaction_id=transaction_id)
        else:
            try:
                self.statestore.create(self.session_key, self.owner, self.objecttype, data)
                return True
            except statestore.StateStoreError:
                return False

    def get_all_refresh_jobs(self):
        '''
        Get all refresh jobs sorted by their create time and return them as a list.
        Returns an empty list in certain error scenarios

        @returns: list of refresh jobs
        @rtype: list
        '''
        return self.statestore.get_all(
            self.session_key,
            self.owner,
            self.objecttype,
            sort_key="create_time",
            sort_dir="asc",
            limit=1000
        )

    def delete_refresh_job(self, refresh_job_key):
        '''
        Deletes a refresh job record from the kv store collection

        @param refresh_job_key: the key of the object to be deleted
        @type refresh_job_key: str

        @returns: True if successful, False otherwise
        @rtype: bool
        '''
        try:
            self.statestore.delete(self.session_key, self.owner, self.objecttype, refresh_job_key)
            return True
        except statestore.StateStoreError:
            return False

    def flush_refresh_job_queue(self):
        '''
        Mainly for testing, this will delete everything in the collection
        '''
        self.statestore.delete_all(
            self.session_key,
            self.owner,
            self.objecttype,
            {"object_type": self.objecttype}
        )

class ITSIRefresherCore(object):
    """
    Abstracted functionality of the modular input for testing purposes
    """

    def __init__(self, session_key, logger=None):
        self.session_key = session_key
        self.logger = logger
        self.instrument = InstrumentCall(logger)

        # adapter should be init-ed by calling module when ready via self.setup_adapter
        self.adapter = None
        self.handler_manifest = get_registered_change_handlers()

    def get_handler_for_job(self, job):
        """
        Looks at the change type and other information from the job if necessary to determine
        what handler class to delegate the execution to. Instantiates the handler and returns it.

        @param job: itsi refresh job formetted dictionary
        @type job: dict

        @returns: the handler
        @rtype: ItoaChangeHandler
        """
        handler_class = self.handler_manifest.get(job.get("change_type"))
        if handler_class == None:
            message = _('No valid handler found for job: {0}.').format(job)
            self.logger.error(message)
            raise Exception(message)
        return handler_class(self.logger, self.session_key)

    def setup_adapter(self):
        """
        Setup the adapter to the refresh job queue
        """
        self.adapter = RefreshQueueAdapter(self.session_key)

    def main_refresh_loop(self):
        '''
        Runs the main logic of the ITSI Refresher. Abstracted out of the run method
        for testing purposes

        @return: count of total processed jobs (for testing)
        @rtype: int
        '''
        processed_job_count = 0
        keep_running = True
        while keep_running:
            jobs = self.adapter.get_all_refresh_jobs()
            if len(jobs) == 0:
                self.logger.debug(
                    'could not find job to do, exiting now, splunk will restart refresh ' \
                        'based on mod input interval'
                )
                keep_running = False
            else:
                self.logger.info("Beginning refresh loop. job_length=%s", len(jobs))
                for job in jobs:
                    start_time = time.time()
                    #The following fields are used for job reporting and tracking
                    create_time = float(job.get("create_time"))
                    job_change_type = job.get("change_type")
                    job_change_key = job.get("changed_object_key", "Unknown Key")
                    transaction_id = job.get("transaction_id", None)
                    job_changed_object_type = job.get("changed_object_type", "Unknown Change Object Type")

                    is_job_complete = False
                    retry_count = 0
                    while (retry_count < 3) and (not is_job_complete):
                        try:
                            self.logger.debug(
                                'refresh job detail for debugging refresh_job_object="%s" ' \
                                    'refresh_job_key="%s"',
                                job,
                                job.get("_key", "NO-KEY")
                            )
                            self.logger.info(
                                'starting refresh_job_key="%s"',
                                job.get("_key", "NO-KEY")
                            )
                            handler = None
                            impacted_objects = {}
                            handler = self.get_handler_for_job(job)
                            handler.assert_valid_change_object(job)
                            self.logger.debug(
                                'deferred refresh_job_key="%s" tid=%s operation=%s',
                                job.get("_key", "NO-KEY"),
                                transaction_id,
                                handler.__class__.__name__
                            )
                            method_name = handler.__class__.__name__ + ".deferred"
                            transaction_id = self.instrument.push(method_name, transaction_id)
                            is_job_complete = handler.deferred(job, transaction_id=transaction_id)
                            self.instrument.pop(method_name, transaction_id)
                        # pylint: disable = broad-except
                        except Exception as error:
                        # pylint: enable = broad-except
                            self.logger.exception(error)
                            self.logger.error(
                                'problem running handler="%s" for refresh_job_key="%s", ' \
                                    'stacktrace in next message, continuing run',
                                handler,
                                job.get("_key", "NO-KEY")
                            )
                        finally:
                            retry_count += 1

                    #Here we're just giving the impacted_objects keys because the impacted objects
                    #themselves can be
                    if is_job_complete:
                        self.logger.info(
                            'refresh_job_key="%s" status=successful retry_count=%d keys="%s"',
                            job.get("_key", "NO-KEY"),
                            retry_count,
                            impacted_objects.keys()
                        )
                    else:
                        self.logger.error(
                            'refresh_job_key="%s" status=failed retry_count=%d keys="%s"',
                            job.get("_key", "NO-KEY"),
                            retry_count,
                            impacted_objects.keys()
                        )
                        #Additional information to debug if we failed
                        self.logger.debug(
                            'refresh_job_key="%s" status=failed retry_count=%d object="%s"',
                            job.get("_key", "NO-KEY"),
                            retry_count,
                            impacted_objects
                        )

                    # Remove job from queue when it finishes or fails on repeated retries
                    # It is safe to remove the refresh job at this point since if the job
                    # had failed earlier owing to KV store having shut down during SIGTERM,
                    # the deletion of the job from the queue would also fail below - which
                    # would result in the job refresh being re-tried at next startup.
                    self.adapter.delete_refresh_job(job["_key"])
                    processed_job_count += 1
                    end_time = time.time()
                    job_time = end_time - start_time
                    queue_time = start_time - create_time
                    overall_time = end_time - create_time
                    completion = "Successful"
                    if not is_job_complete:
                        completion = "Failed"
                    self.logger.info("Transaction: Job %s: tid=%s job_change_type=%s job_change_key=%s, job_changed_object_type=%s " \
                                "start_time=%s end_time=%s job_time=%s queue_time=%s overall_time=%s",
                            completion, transaction_id, job_change_type, job_change_key, job_changed_object_type,
                            start_time, end_time, job_time, queue_time, overall_time)

        return processed_job_count