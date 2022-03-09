# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
This is a re-implementation of the refresh queue that we had before, with the major change that this one is designed to be run
concurrently.  Itself, it will behave appropriately.  However, it is paramount that any new/existing refresh queues be audited for
the amount of risk that they can have.  Currently we have no transaction support from our supporting datastore, so
theres definately a risk of race conditions.
"""
import sys
from time import time
import json

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n
from splunk.rest import simpleRequest
from splunk import LicenseRestriction

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.setup_logging import setup_logging, InstrumentCall
from ITOA.storage.statestore import StateStore
from itsi.objects.changehandlers.handler_manifest import handler_manifest
from kvstore_queue.kvstore_queue_consumer import KVStoreQueueConsumer

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

# TODO: Debating whether or not I should use this
# from SA_ITOA_app_common.solnlib.server_info import ServerInfo

logger = setup_logging("itsi_consumer.log", "itsi.object.consumer")
instrumenter = InstrumentCall(logger)


class JobDemultiplexer(object):
    """
    De-Multiplexer for ITSI objects.  A user passes in a field that
    will select what action to run - the demultiplexier field (demux_field)
    Essentially the job type, but can be used for other things
    """

    def __init__(self, session_key, demux_field):
        """
        Initialize the process object
        @param session_key: The splunkd session key
        @param demux_field: The field in the job data to demultiplex on
        """
        self.demux_field = demux_field
        self.session_key = session_key
        self.handler_manifest = handler_manifest

    def preprocess_job(self, job_data, other_jobs):
        """
        If the handler is configured to, check for duplicate jobs
        @param job_data: job object the handler is currently working on
        @param other_jobs: list of job objects in the queue
        @return: list of duplicate job objects
        @rtype List
        """
        job_changed_object_type = job_data.get("changed_object_type")
        job_change_key = job_data.get("changed_object_key")
        if job_changed_object_type and job_change_key:
            selector = job_data.get(self.demux_field, None)
            handler_object = self._get_handler(job_data, selector)(logger, self.session_key)
            should_remove_duplicates = getattr(handler_object, 'should_remove_duplicates', None)
            if should_remove_duplicates and callable(should_remove_duplicates) and should_remove_duplicates(job_data):
                duplicates = [job for job in other_jobs if
                              job.get("changed_object_type") == job_changed_object_type and
                              job.get("changed_object_key") == job_change_key]
                return duplicates
        return []

    def process_job(self, job_data):
        """
        Using the demultipler field, process the job_data
        @param job_data: JSON data coming in to be processed.  In this case, it will be a refresh
        queue job
        """
        start_time = time()
        create_time = float(job_data.get("create_time"))
        job_change_type = job_data.get("change_type")
        job_change_key = job_data.get("changed_object_key", "Unknown Key")
        transaction_id = job_data.get("transaction_id", None)
        job_changed_object_type = job_data.get("changed_object_type", "Unknown Change Object Type")
        try:
            selector = job_data.get(self.demux_field, None)
            handler_object = self._get_handler(job_data, selector)(logger, self.session_key)
            method_name = selector + ".deferred"
            transaction_id = instrumenter.push(method_name, transaction_id)
            handler_object.deferred(job_data, job_data.get('transaction_id'))
            successful = True
            instrumenter.pop(method_name, transaction_id)
        except Exception:
            successful = False
            logger.exception("Error processing job=%s change_type=%s tid=%s",
                             job_data.get("_key"),
                             job_data.get("change_type"),
                             job_data.get("transaction_id"))
            raise
        finally:
            # Log the entire experience
            end_time = time()
            job_time = end_time - start_time
            queue_time = start_time - create_time
            overall_time = end_time - create_time
            completion = "Successful"
            if not successful:
                completion = "Failed"
            logger.info("Transaction: Job %s: tid=%s job_change_type=%s job_changed_object_type=%s "
                        "start_time=%s end_time=%s job_time=%s queue_time=%s transaction_time=%s job_change_key=%s",
                        completion, transaction_id, job_change_type, job_changed_object_type,
                        start_time, end_time, job_time, queue_time, overall_time, job_change_key)

    def _get_handler(self, job_data, selector):
        """
        Get the handler class for job
        @param job_data: the refresh queue job object
        @param selector: the demux field
        @return: Handler class
        """
        key = job_data.get("_key")
        transaction_id = job_data.get('transaction_id')
        if selector is None:
            raise Exception(_("No selector found in data field=%s, key=%s, tid=%s") %
                            (self.demux_field, key, transaction_id))
        handler_class = self.handler_manifest.get(selector)
        if handler_class is None:
            raise Exception(_("No handler manifest could be found selector=%s, key=%s, tid=%s") %
                            (selector, key, transaction_id))
        return handler_class

    def commit(self):
        """
        Just hold off on this one for now, it will come up later though
        """
        pass


class ItsiConsumerModularInput(ModularInput):
    """
    Modular input that processes job objects from the specified queue and collection
    """
    # Required options for Modular Input
    title = _("ITSI Multiple Job Queue Processor")
    description = _("Runs deferred operations to ensure consistency for ITSI knowledge objects")
    app = "SA-ITOA"
    name = "itsi_consumer"
    use_single_instance = False
    use_kvstore_checkpointer = False
    use_hec_event_writer = False

    # Consumer specific arguments
    # At some point we may want to move these into conf files
    # If people branch out into multiple collections
    queue_collection = 'itsi_refresh_queue'
    metadata_collection = 'itsi_refresh_metadata'
    sort_field = 'create_time'
    sort_order = 'asc'
    object_type = 'refresh_job'
    owner = 'nobody'

    def extra_arguments(self):
        """
        Additional argument definitions required for the modular input class
        """
        return [{'name': "log_level",
                 'title': _('Logging Level'),
                 'description': _('Logging level to use for logging errors (ERROR, WARNING, INFO, DEBUG)')
                 }
                ]

    # It may seem a little strange to have these wrapped, but the good reason is
    # So that we can do good unit testing around this feature
    def request_shc_members(self):
        """
        The reason that we split this up into a separate method is so that we can
        abstract everything else out and test it by overwriting this method
        """
        return simpleRequest('/services/shcluster/member/members',
                             sessionKey=self.session_key,
                             getargs={"output_mode": "json"},
                             raiseAllErrors=False)

    # It may seem a little strange to have these wrapped, but the good reason is
    # So that we can do good unit testing around this feature
    def request_input_conf_entries(self):
        """
        The reason that we split this up into a separate method is so that we can
        abstract everything else out and test it by overwriting this method
        """
        return simpleRequest('/services/properties/inputs',
                             sessionKey=self.session_key,
                             getargs={"output_mode": "json"},
                             raiseAllErrors=False)

    def unclaim_incomplete_jobs(self, localhost):
        """
        So, with multiple processing queues, what happens if one dies unexpectedly?  We need to
        find a way to
        1) Determine that the process has died
        2) Adjust all of its jobs to unclaimed
        3) Do this all within splunk.  The worst part.

        For 1, what we need to do is first compare what hosts are up and which ones are not.  Now,
        this is only possible as far as the different search heads share the same kvstore - which
        is only possible if they are clustered. That means that we can look through all of the
        hosts that we're informed of in our shc (or single instance) and see if there are any hosts
        in the list of jobs that are not in the list provided by splunk

        If there are any jobs assigned to hosts that don't exist, we put those back on the open
        market.

        Next, we look for jobs that are assigned to job processors that don't exist.
        Unfortunately, we can't check other hosts that well, but we can check our own host
        pretty easily.  So lets do that.  Once we have dead hosts and dead input stanzas covered,
        we've covered a large portion of the jobs.  The only thing that isn't covered are hosts up
        that have 0 jobs assigned to them (usually through user intervention).

        We'll need a special way of dealing with that case

        For 2, thats easy.  Just rewrite the job itself to take out the processing piece

        For 3, we'll be limited to conf files, the kvstore, etc.  Not great, but whatever
        """
        # Step 0: Are we a part of a shc?
        valid_hosts = []
        try:
            response, content = self.request_shc_members()
            if response.status != 200:
                # Assume that we are not a part of the search head cluster, just grab localhost
                is_shc = False
                valid_hosts.append(localhost)
            else:
                is_shc = True
                parsed_content = json.loads(content)
                for entry in parsed_content.get("entry", []):
                    entry_content = entry.get('content', {})
                    label = entry_content.get("label")
                    status = entry_content.get("status")
                    if label is not None and status == "Up":
                        valid_hosts.append(label)
        except LicenseRestriction:
            logger.exception("Please update your license. Continuing with localhost awareness only")
            valid_hosts.append(localhost)
        # Step 1: Check for any hosts that are not a part of the shc.
        # Find jobs that are assigned to the dead hosts
        valid_local_workers = []
        response, content = self.request_input_conf_entries()
        if response.status == 200:
            # If we don't get status = 200, then we should skip any of the local workers
            parsed_content = json.loads(content)
            for entry in parsed_content.get("entry", []):
                entry_content = entry.get('name')
                if "itsi_consumer://" in entry_content:
                    valid_local_workers.append(entry_content + ":" + localhost)
        # Step 2: Check for any jobs that are assigned to workers not present on this host.
        if not hasattr(self, "jobs"):
            # This is used for testing.  If we have already assigned self.jobs, then use that
            self.jobs = StateStore(collection=self.queue_collection)

        queue_jobs = self.jobs.get_all(self.session_key,
                                       'nobody',
                                       self.object_type)

        redo_jobs = []
        for job in queue_jobs:
            processor = job.get("processor")
            if processor is None or len(processor) == 0:
                continue
            worker_host = processor[processor.rfind(":") + 1:]
            if worker_host not in valid_hosts:
                redo_jobs.append(job)
            elif processor not in valid_local_workers and worker_host == localhost:
                redo_jobs.append(job)

        # Individually save all of the jobs
        for job in redo_jobs:
            old_job = self.jobs.get(self.session_key, 'nobody', self.object_type, job['_key'])
            if old_job.get('processor') == job.get('processor'):
                # Step 3: For any jobs in 1 or 2,
                # nullify their workers (if they are not claimed by other workers)
                del old_job['processor']
                self.jobs.edit(self.session_key, 'nobody', self.object_type, job['_key'], old_job)

    def do_run(self, stanzas):
        """
        Run the modular input
        """
        if len(stanzas) == 0:
            # The feature is disabled, no stanzas are present.
            return
        # We only want the first instance of the stanza, it has the name that we want
        stanza_name = stanzas.iterkeys().next()
        stanza_config = stanzas.itervalues().next()
        # A mostly unique identifier that will persist across different iterations
        # Here we're assuming that the stanza name itself is unique across stanza types
        # It could be a uuid though
        # Anything as long as it persists across reboots
        self.uuid = stanza_name + ":" + stanza_config.get('host')
        logger.debug("Running with uid=%s", self.uuid)
        level = stanza_config.get("log_level")
        if level is not None:
            level = level.upper()
            if level not in ["ERROR", "WARN", "WARNING", "INFO", "DEBUG"]:
                level = "INFO"
            logger.setLevel(level)

        demux = JobDemultiplexer(self.session_key, 'change_type')
        self.consumer = KVStoreQueueConsumer(self.session_key, logger, self.uuid, self.queue_collection,
                                             self.metadata_collection, self.sort_field, self.sort_order,
                                             self.object_type, demux, 'process_job', 'preprocess_job', 'commit')
        # Next, wait for the kvstore to get up and running
        self.consumer.block_until_ready()
        keep_running = True
        start_time = time()
        while keep_running:
            try:
                self.consumer.process_job()
            except Exception:
                logger.exception("Exception processing handler on uid=%s", self.uuid)
                # Once it is logged, we want to crash out and let splunk bring us back up
                raise
            end_time = time()
            if end_time - start_time > 60:
                logger.debug("Checking for cleanup on incomplete jobs uid=%s", self.uuid)
                # Check to see if we need to clean anything up
                self.unclaim_incomplete_jobs(stanza_config.get("host"))
                # Reset our start time
                start_time = time()

        logger.info("Exit modular input uid=%s", self.uuid)
        return


if __name__ == "__main__":
    worker = ItsiConsumerModularInput()
    worker.execute()
    sys.exit(0)
