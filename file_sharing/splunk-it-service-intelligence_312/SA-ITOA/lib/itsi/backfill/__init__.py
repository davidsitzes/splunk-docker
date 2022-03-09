# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This file contains the implementation of the backfill job queue.
The data structures of note here are:
1. the backfill requests represented by `BackfillRequestModel`s with fields:
   - status: one of ['new', 'pending', 'running', 'done', 'failed', 'cancelled']
   - cancellation_flag: optional, if present, must have the value 'cancellation_requested'
   - search
   - earliest
   - latest
   - kpi_id
   - kpi_title
   - job_progress: array of <nchunk> job_metadata objects. This field created when job is added to the queue.
                   job_metadata objects are dicts with keys: ('et', 'lt', 'num', 'tot', 'sid', 'status', 'retries_left')
   - t_start [not present in new/pending state]
   - t_finish [not present before completion]
2. the job chunk records represened by dict with fields:
   - et: job chunk earliest time
   - lt: jub chunk latest time
   - status: one of ['new', 'running', 'done', 'failed']
   - num: job chunk number [1, tot]. Job chunk 1 will execute first and corresponds to the most recent (et, lt) time interval.
   - tot: total number of job chunks
   - request: reference to the backfill request this job chunk is a part of
   - searchjob: reference to the searchjob object dispatched for this job chunk [not present until search dispatches]
   - retry_flag: [field is present and set to true if this job is being retried after a failure]

Request status evolution is given by the following state diagram:

                                      +-----------------+  yes   +-----------+  yes
new+----> pending+----->running+------>search succeeded?+-------->last chunk?+---------->done
                           ^          +-------+---------+        +-----------+             ^
                           |                  |no                      |no                 |
                           |                  v                        |                   |
                           |         +--------------------+            |                   |
                           |---------+failure recoverable?|            |                   |
                           |    yes  +--------+-----------+            |                   |
                           |                  |no                      |                   |
                           |                  v                        |                   |
                           |                fail                       v                   |
                           |                                  +----------------------+     |
                           +----------------------------------+should keep executing?+-----+
                                                      yes     +----------------------+   no
"""

import sys
import time
import datetime
import math
import copy
from collections import deque

from itsi_backfill_requests import BackfillRequestCollection, BackfillRequestModel

import splunk.search as splunk_search
import splunk.rest as splunk_rest
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'bin']))
from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import get_current_utc_epoch

CHECK_EXE_SLEEP_SECONDS = 10
LOOP_SLEEP_SECONDS = 3
IN_PROGRESS_SLEEP_SECONDS = 3
CHUNK_SECONDS = 3600 * 24  # 1 day
JOB_HISTORY_TTL = 3600 * 24 * 14
COLLECT_INDEX = "itsi_summary"
COLLECT_COMMAND = " | collect index={indexname}".format(indexname=COLLECT_INDEX)
COLLECT_REQUEST_TIMEOUT = 60
DEFAULT_RETRIES = 5  # number of retry attempts for recoverable errors

LOGGER = setup_logging("itsi_backfill_services.log", "itsi.backfill.modinput")


class BackfillStatus(object):
    """
    Enum-like class for status codes
    """
    STATUS_NEW = 'new'
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_DONE = 'done'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'
    STATUS_CANCELLATION_REQUESTED = CANCELLATION_REQUESTED = 'cancellation_requested'


class BackfillJobQueue(object):
    '''
    Job queue is a set of k queues, one for each request.
    Each request queue contains some number of request chunks (in reverse
    chronological order). Each chunk except for the first and/or last has
    the same duration.

    Chunks can be retrieved either by picking the latest one from all
    request queues, or by picking the latest from a particular request queue.
    '''
    def __init__(self, logger=None):
        self._queues = {}
        self.logger = logger or LOGGER

    def __len__(self):
        '''
        Returns total length of all the enqueued chunks
        '''
        return sum(len(x) for x in self._queues.itervalues())

    @staticmethod
    def _get_chunks(request):
        'Returns job chunks in reverse chronological order, numbered 1..nchunks'
        et, lt = request.earliest, request.latest
        dt = lt - et
        if dt <= 0:
            return []
        intervals = []
        nchunks = int(math.ceil(dt / float(CHUNK_SECONDS)))
        for i in xrange(nchunks):
            et_i = et + i * CHUNK_SECONDS
            lt_i = min(et_i + CHUNK_SECONDS - 1, lt)
            intervals.append({
                'et': et_i,
                'lt': lt_i,
                'num': nchunks - i,
                'tot': nchunks,
                'status': BackfillStatus.STATUS_NEW,
                'retries_left': DEFAULT_RETRIES,
                'request': request
            })
        intervals.reverse()
        return intervals

    @staticmethod
    def _serialize_job_chunks(chunks):
        job_progress = []
        for c in chunks:
            cc = copy.copy(c)
            del cc['request']  # request reference is for local use and isn't JSON serializable
            job_progress.append(cc)
        return job_progress

    def add(self, request):
        '''
        Add request to the queue; this method generates job chunks from the request, changes the
        request status to 'pending' and adds 'job_progress' array to the request.

        @param request
        @type: BackfillRequestModel
        '''
        if request.id_ in self._queues:
            raise Exception(_("Attempting to add a job already in the queue"))
        chunks = BackfillJobQueue._get_chunks(request)
        request.update({'status': BackfillStatus.STATUS_PENDING,
                        'job_progress': BackfillJobQueue._serialize_job_chunks(chunks)})
        self.logger.debug("Queue add: splitting request %s into %s chunks", request.id_, len(chunks))
        self._queues[request.id_] = deque(chunks)
        # Might be nice to put in some extra error checking to make sure we never include
        # overlapping chunks for the same KPI id

    def add_job_chunk(self, request, chunk, to_front=False):
        '''
        Add job chunk to the queue. Resets its status to 'new'. Always adds 'request' attribute to
        ensure the queue data structure is valid.

        @param request
        @type: BackfillRequestModel

        @param chunk: job chunk record
        @type dict
        '''
        chunk['request'] = request
        queue = self._queues.setdefault(request.id_, deque())
        if to_front:
            queue.appendleft(chunk)
        else:
            queue.append(chunk)

    def flush_request(self, request):
        '''
        Removes all chunks for this request from the job queue.

        @param request
        @type: BackfillRequestModel
        '''
        self._queues.pop(request.id_, None)

    def has_request(self, request):
        '''
        Check if the request is in the job queue.

        @param request
        @type: BackfillRequestModel

        @returns True if this request is in the queue else False
        @rtype bool
        '''
        return request.id_ in self._queues

    def _get_latest(self):
        # get a set of ('earliest time of leftmost element', 'queue reference') tuples
        frontier = [(x[0]['et'], x) for x in self._queues.itervalues() if len(x) > 0]
        if len(frontier) > 0:
            return max(frontier)[1].popleft()
        else:
            return None

    def _get_latest_from(self, request):
        queue = self._queues.get(request.id_, None)
        if queue is None:
            self.logger.error("Queue not found for request id %s", request.id_)
            return
        if len(queue) > 0:
            return queue.popleft()

    def get(self, request=None):
        '''
        Pop a job chunk from the queue. Assuming chronological ordering of job chunks
        (those with most recent 'latest' times at the front of the queue), this will
        extract the most recent job chunk (as judged by the 'latest' time). If an optional
        `request` parameter is provided, this will extract the most recent chunk for this
        request.

        @param request [optional]
        @type: BackfillRequestModel

        @returns job chunk dict by grabbing latest from the queue (returns None if there's no job chunk to return)
        @rtype dict
        '''
        if request is None:
            return self._get_latest()
        else:
            return self._get_latest_from(request)


class JobProcessor(object):
    '''
    JobProcessor is responsible for getting job chunks from the job queue and dispatching searches
    to run the backfill for that job chunk.
    '''
    STATE_IDLE = 'idle'
    STATE_RUNNING = 'running'

    def __init__(self,
                 job_queue,
                 success_callback=(lambda x, **kw: None),
                 fail_callback=(lambda x, **kw: None),
                 logger=None,
                 session_key=None,
                 owner="nobody"):
        '''
        @param job_queue
        @type: BackfillJobQueue

        @param success_callback [optional]: a function taking the job dict and kwargs
        @type: function

        @param fail_callback [optional]: a function taking the job dict and kwargs
        @type: function

               (Note: success and failure callbacks are optional and are intended for things
               like displaying messages in the UI).

        @param logger [optional]
        @type: logging.logger

        @param session_key
        @type: string

        @param owner
        @type string
        '''
        self.logger = logger or LOGGER
        self._job_queue = job_queue
        self._success_callback = success_callback
        self._fail_callback = fail_callback
        self._session_key = session_key
        self._owner = owner
        self._state = self.STATE_IDLE
        self._job_chunk = None

    def _check_job_state(self):
        searchjob = self._job_chunk.get('searchjob', None)
        if searchjob is None:
            return
        searchjob.refresh()
        if searchjob.isFailed or searchjob.isZombie or searchjob.isFinalized:
            self._on_job_fail(self._job_chunk, retry=(searchjob.isZombie or searchjob.isFinalized))
            self._setup_job(self._job_queue.get())
        elif searchjob.isDone:
            self._on_job_success(self._job_chunk)
            self._setup_job(self._job_queue.get())

    def _collect_into_summary(self, job_chunk):
        'Runs the | collect <summaryindex> command as a post-process'
        sid = job_chunk['searchjob'].id
        uri = '/servicesNS/nobody/SA-ITOA/search/jobs/{sid}/results'.format(sid=sid)
        args = {'search': COLLECT_COMMAND}
        splunk_rest.simpleRequest(uri,
                                  getargs=args,
                                  sessionKey=self._session_key,
                                  raiseAllErrors=True,
                                  timeout=COLLECT_REQUEST_TIMEOUT)

    def _on_job_success(self, job_chunk):
        self.logger.debug("Job [sid=%s] finished successfully", job_chunk['searchjob'].id)
        t_finish = int(get_current_utc_epoch())
        request = job_chunk['request']
        request.fetch()
        request.update_job_progress(job_chunk['num'], {'status': BackfillStatus.STATUS_DONE, 't_finish': t_finish})
        try:
            self._collect_into_summary(job_chunk)
        except Exception as e:
            self.logger.exception("Summarization post-process command failed: %s", e)
            self._on_job_fail(job_chunk)
        if all(x['status'] == BackfillStatus.STATUS_DONE for x in request.job_progress):
            update = {'status': BackfillStatus.STATUS_DONE, 't_finish': t_finish}
        else:
            update = {}
        if request['status'] != BackfillStatus.STATUS_FAILED and len(update) > 0:
            request.update(update)
        self._success_callback(job_chunk)

    def _on_job_fail(self, job_chunk, retry=False):
        messages = {}
        if 'searchjob' in job_chunk:
            messages = job_chunk['searchjob'].messages
        sid = getattr(job_chunk.get('searchjob', ''), 'id', '')
        self.logger.error("Job [sid=%s] failed with messages: %s; retry=%s", sid, messages, retry)
        if 'request' in job_chunk:
            t_finish = int(get_current_utc_epoch())
            request = job_chunk['request']
            request.fetch()
            request.update_job_progress(job_chunk['num'], {
                'status': BackfillStatus.STATUS_FAILED,
                't_finish': t_finish
            })
            if retry and job_chunk['retries_left'] > 0:
                job_chunk['retry_flag'] = True
                self.logger.debug("Retrying failed job chunk %s for request %s; adding it to the queue",
                                  job_chunk['num'], request.id_)
                self._job_queue.add_job_chunk(request, job_chunk, to_front=True)
        if not retry:
            self._job_queue.flush_request(request)
            job_chunk['request'].update({'status': BackfillStatus.STATUS_FAILED,
                                         't_finish': t_finish,
                                         'messages': messages})
        self._fail_callback(job_chunk, retry=retry)

    def _dispatch_search(self, search):
        search = search.lstrip()
        if not search.startswith('|'):
            search = 'search ' + search
        kwargs = {
            'sessionKey': self._session_key,
            'owner': self._owner,
            'earliestTime': self._job_chunk['et'],
            'latestTime': self._job_chunk['lt']
        }
        self._job_chunk['searchjob'] = splunk_search.dispatch(search, **kwargs)

    def _setup_job(self, job_chunk):
        self._job_chunk = job_chunk
        if job_chunk is None:
            self._state = self.STATE_IDLE
        else:
            self._state = self.STATE_RUNNING
            request = job_chunk['request']
            try:
                self._dispatch_search(request['search'])
            except Exception as e:
                self.logger.exception("Failed to dispatch search job: %s", e)
                self._state = self.STATE_IDLE
                self._job_chunk = None
                self._on_job_fail(job_chunk)
                return
            sid = job_chunk['searchjob'].id
            t_start = int(get_current_utc_epoch())
            if request['status'] != BackfillStatus.STATUS_RUNNING:
                request.update({'status': BackfillStatus.STATUS_RUNNING, 't_start': t_start})
            retries_left = job_chunk['retries_left'] - (1 if job_chunk.get('retry_flag', False) else 0)
            request.update_job_progress(job_chunk['num'], {
                'status': BackfillStatus.STATUS_RUNNING,
                'sid': sid,
                'retries_left': retries_left,
                't_start': t_start
            })
            self.logger.debug("Kicked off search job with sid %s for chunk %s of request %s",
                              sid, job_chunk['num'], request.id_)

    @property
    def state(self):
        return self._state

    @property
    def job(self):
        return self._job_chunk

    def adopt(self, request, chunk):
        '''
        'Adopts' in-progress job chunks that may not have been spawned by this job processor.
        Note that a single request can have multiple in-progress job chunks, as indicated by
        the list of sids.  By 'adopt', we mean discover a running search job (if any) and
        start monitoring its completion in the job processor, calling the fail/success hooks, etc.

        @param request: request record
        @type: BackfillRequestModel

        @param chunk: chunk number to be looked up in job_progress array
        @type: int
        '''
        job_chunk = {'request': request}
        if request['status'] != BackfillStatus.STATUS_RUNNING:
            raise Exception(_("RequestProcessor: Attempted to adopt a non-running request %s") % request)
        try:
            job_chunk.update(request.get_job_chunk(chunk))
            sid = job_chunk['sid']
            job_chunk['searchjob'] = splunk_search.getJob(sid, sessionKey=self._session_key)
        except Exception as e:
            self.logger.exception("Error trying to get already-running job (request_id=%s, chunk=%s): %s",
                              request.id_, chunk, e)
            self._on_job_fail(job_chunk, retry=True)
            self._state = self.STATE_IDLE
            return
        self.logger.debug("Picking up a running job for request %s with SID %s", request.id_, sid)
        self._job_chunk = job_chunk
        self._state = self.STATE_RUNNING

    def update_state(self):
        '''
        Check the current state and pull the next job chunk from the queue if idle.

        @returns (state, job_record) tuple
        @type: tuple
        '''
        if self._state == self.STATE_IDLE:
            self._setup_job(self._job_queue.get())
        else:
            self._check_job_state()
        return (self._state, self._job_chunk)


class ItsiBackfillCore(object):
    '''
    This class is used by the ITSI backfill modinput to perform the following:
    1. startup actions:
        - clear completed requests
        - check in-progress jobs:
          - wait for in-progress searches to complete
          - rebuild job queues for partially completed jobs
        - instantiate JobProcessor classes
    2. backfill loop:
        - retrieve new backfill requests from kv store
        - for every new request, add it to the BackfillJobQueue (which automatically creates job chunks)
        - check if JobProcessors are idle and if so, feed them from the queue

    It inherits from thread in order to receive termination messages
    '''
    def __init__(self, session_key, target_checker, messenger=None, concurrent_jobs=2, max_iterations=None, logger=None):
        '''
        @param session_key: splunkd session key used to communicate w/ kv store
        @type: string

        @parm target_checker: callable that is used to determine whether the modinput
        that owns this class is still the designated backfill handler. This will return
        `False` if e.g. a new machine in SHC configuration takes on the designated backfill
        handler role.
        @type: callable

        @param messenger: callable used to display messages in the UI
        @type callable

        @param concurrent_jobs [optional]: number of concurrent backfill search jobs (default: 2)
        @type: int

        @param max_iterations [optional]:  maximum number of iterations for the main loop (default: unlimited)
        @type: int

        @param logger
        @type: logging.logger
        '''
        self._max_iterations = max_iterations
        self.session_key = session_key
        self.job_history_ttl = JOB_HISTORY_TTL  # expose for testing
        self.interface = BackfillRequestModel.initialize_interface(self.session_key)
        self.logger = logger or LOGGER
        self._n_concurrent = concurrent_jobs
        self._modinput_is_target = target_checker
        self._message_fn = messenger or (lambda x: None)
        self._job_queue = BackfillJobQueue()
        self._requests = BackfillRequestCollection(interface=self.interface)
        self._initialize_job_processors()
        self._last_exe_check_time = 0

    def _should_execute(self):
        now = int(get_current_utc_epoch())
        if now - self._last_exe_check_time > CHECK_EXE_SLEEP_SECONDS:
            self._last_exe_check_val = self._modinput_is_target(self.session_key, logger=self.logger)
            self._last_exe_check_time = int(get_current_utc_epoch())
        return self._last_exe_check_val

    def _initialize_job_processors(self, n=None):
        if n is None:
            n = self._n_concurrent
        self._job_processors = [JobProcessor(
            self._job_queue,
            self._on_job_success,
            self._on_job_fail,
            self.logger,
            self.session_key
        ) for _ in range(n)]

    @staticmethod
    def _make_success_message(request):
        dt_min = int(round((request['t_finish'] - request['t_start']) / 60))
        et = datetime.datetime.fromtimestamp(request.earliest).strftime("%Y-%m-%d %H:%M:%S")
        lt = datetime.datetime.fromtimestamp(request.latest).strftime("%Y-%m-%d %H:%M:%S")
        return "Backfill for KPI {0} from {1} to {2} completed in {3} m".format(
            request.get('kpi_title', ''), et, lt, dt_min)

    @staticmethod
    def _make_fail_message(request):
        et = datetime.datetime.fromtimestamp(request.earliest).strftime("%Y-%m-%d %H:%M:%S")
        lt = datetime.datetime.fromtimestamp(request.latest).strftime("%Y-%m-%d %H:%M:%S")
        return "Backfill for KPI {0} from {1} to {2} failed".format(request.get('kpi_title', ''), et, lt)

    # success and fail callbacks here are run in addition to default success/fail handling in the job processor
    def _on_job_success(self, job, **kwargs):
        request = job['request']
        if request['status'] == BackfillStatus.STATUS_DONE:
            self._message_fn(ItsiBackfillCore._make_success_message(request))

    def _on_job_fail(self, job, **kwargs):
        if 'request' in job and not kwargs.get('retry', False):
            self._message_fn(ItsiBackfillCore._make_fail_message(job['request']))

    def _clear_completed(self):
        count = 0
        now = int(get_current_utc_epoch())
        for req in self._requests:
            if req['status'] in (BackfillStatus.STATUS_DONE, BackfillStatus.STATUS_FAILED) and (now - req.get('t_finish', 0)) > self.job_history_ttl:
                req.delete()
                count += 1
        if count > 0:
            self.logger.debug("Deleted %s completed requests", count)

    def _renew_pending(self):
        for req in self._requests:
            if req['status'] == BackfillStatus.STATUS_PENDING:
                req.update({'status': BackfillStatus.STATUS_NEW})
                self.logger.debug("Updating status of request %s from pending to new", req.get("_key", None))

    def _process_incomplete_requests(self):
        '''
        Examine requests that are showing as 'running'. Assumes we've handled all in-progress
        search jobs, and we must now determine what to do about the incomplete request.

        The strategy is as follows: if we have any job chunks that are in the 'failed' state with
        'retries_left' == 0, fail this job.  For any job chunk that are in 'failed' with non-zero
        'retries_left', or any chunk in the 'new' state, add it to the job queue
        '''
        def handle_fatal_errors(req):
            for job in req.job_progress:
                if job['status'] == BackfillStatus.STATUS_FAILED:
                    if job['retries_left'] == 0:
                        self.logger.debug("Found a failed job chunk with no provision for recovery, failing backfill job")
                        req.update({'status': BackfillStatus.STATUS_FAILED, 't_finish': job['t_finish']})

        def rebuild_queue(req):
            count = 0
            for job in req.job_progress:
                if job['status'] == BackfillStatus.STATUS_NEW or (job['status'] == BackfillStatus.STATUS_FAILED and job['retries_left'] > 0):
                    self._job_queue.add_job_chunk(req, job)
                    count += 1
            if count > 0:
                self.logger.debug("Put %s chunks back in the queue for request %s", count, req.id_)

        def process_incomplete_request(req):
            if req['status'] == BackfillStatus.STATUS_RUNNING:
                handle_fatal_errors(req)
                if req['status'] != BackfillStatus.STATUS_FAILED:
                    rebuild_queue(req)

        for req in self._requests:
            process_incomplete_request(req)

    def _finish_running(self):
        '''
        Examine SIDs of job chunks that are showing as 'running'.  This may
        have resulted due to the modular input having restarted.  To finish those
        jobs, we assign them to the job processors and run the usual loop, checking
        their state and waiting until all processors are idle.
        '''
        running_requests = [r for r in self._requests if r['status'] == BackfillStatus.STATUS_RUNNING]
        active_sids = {}  # active sid to (request, request_chunk) mapping
        for req in running_requests:
            for job in req.job_progress:
                if job['status'] == BackfillStatus.STATUS_RUNNING:
                    active_sids[job['sid']] = (req, job['num'])
        if len(active_sids) > self._n_concurrent:
            self.logger.warning("More running jobs than job processors (%s > %s);"
                                "re-initializing job processors to match", len(active_sids), self._n_concurrent)
            self._initialize_job_processors(n=len(active_sids))
        for job_processor, sid in zip(self._job_processors, active_sids.keys()):
            job_processor.adopt(*active_sids[sid])
        while not all(j.state == JobProcessor.STATE_IDLE for j in self._job_processors):
            for processor in self._job_processors:
                processor.update_state()
            self.logger.debug("Waiting for all Job Processors to become idle")
            time.sleep(IN_PROGRESS_SLEEP_SECONDS)

    def _process_new_requests(self):
        self._requests.fetch({
            'status': {
                '$ne': BackfillStatus.STATUS_DONE
            }
        })
        for req in self._requests:
            if req['status'] == BackfillStatus.STATUS_NEW:
                if req.is_backfillable():
                    self.logger.debug("Updating status of request %s from new to pending", req.get("_key", None))
                    self._job_queue.add(req)
                else:
                    self.logger.debug("Deleting request %s since it should not be backfilled", req.get("_key"))
                    req.delete()
            elif req['status'] == BackfillStatus.STATUS_PENDING:
                if not self._job_queue.has_request(req):
                    self.logger.warning("Request with status `pending` was not found in the job queue; changing to `new`")
                    req.update({'status': BackfillStatus.STATUS_NEW})
            if req.get('cancellation_flag') == BackfillStatus.STATUS_CANCELLATION_REQUESTED:
                self._job_queue.flush_request(req)
                req.update({'cancellation_flag': BackfillStatus.STATUS_CANCELLED, 'status': BackfillStatus.STATUS_CANCELLED})

    def _poll_job_processors(self):
        for processor in self._job_processors:
            processor.update_state()

    def _run_main_loop(self):
        if len(self._job_processors) != self._n_concurrent:
            self._initialize_job_processors(n=self._n_concurrent)
        self._count_iterations = 0
        while (self._should_execute()
               and (self._max_iterations is None or self._count_iterations < self._max_iterations)):
            self._process_new_requests()
            self._poll_job_processors()
            self._count_iterations += 1
            time.sleep(LOOP_SLEEP_SECONDS)

    def job_processor_info(self):
        '''
        @returns a list of (job_state, job_reference) tuples, one from each job processor
        @rtype tuple
        '''
        return [(jp.state, jp.job) for jp in self._job_processors]

    def job_queue_info(self):
        '''
        @returns a dict of job queue metadata
        @rtype dict
        '''
        return {'length': len(self._job_queue)}

    def start(self):
        '''
        The following operations are performed on startup:
        1. Clear old completed request records from KV store
        2. If any are found in 'pending' state, change them to 'new'
        3. Examine requests with 'running' status. Look at the SID(s) in the job record(s), and
           allow all in-progress searches to complete.
        4. Examine requests with 'partially_complete' status. Change their 'latest' time to
           match the 'earliest' time or the last-completed job chunk, as indicated in the job record,
           and change the status to 'new'.
        5. Run the main loop (check for new jobs, check progress of running jobs, manage job queue);
           stop when this class is no longer the designated processor or the max # of loop iterations is exceeded.
        '''
        self.logger.debug("Starting the backfill job queue")
        self._requests.fetch()
        self.logger.debug("Found %s requests on startup", len(self._requests))
        self._clear_completed()
        self._renew_pending()
        self._finish_running()
        self._process_incomplete_requests()
        self._run_main_loop()
