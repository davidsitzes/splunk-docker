# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
ITOA-8115: remove dependencies of SA-ITOA from SA-ITSI-Licensechecker.
Manually copied from apps/SA-ITOA/package/lib/ITOA/setup_logging.py
If you change this file, please also update the original.
"""
import logging
from splunk import setupSplunkLogger
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import os


# On Windows System, suppress all logging exceptions
if os.name == 'nt':
    logging.raiseExceptions = False

"""
    Please add new logger name and its log file information here, so we can have information at one place

    Logger Standards
        1. Each logger name must be prefixed with app name like itoa. For example: itoa.storage
        2. Each log file must be prefixed with <app name>_ like itoa_storage.log

    The following logger had been defined in the SA-ITOA
    1. itoa ---> Itoa app Root logger
    2. itoa.storage --> Root logger for storage (itoa_storage.log)
        - itoa.storage.statestore ---> Logger for module which write information in KV store (itoa_statestore.log)
        - itoa.storage.lookup --> Logger for lookup file module (itoa_lookup.log)
    3. itoa.common ---> Logger for common module (itoa_common.log)
    4. itoa.object ---> Logger for itoa object base (itoa_object.log)
"""


def setup_logging(log_name, logger_name, logger=None, level=logging.INFO, is_console_header=False,
                  log_format='%(asctime)s %(levelname)s [%(name)s] [%(module)s] [%(funcName)s] [%(process)d]'
                             ' %(message)s', is_propagate=False):
    '''
    Setup logging

    @param log_name: log file name
    @param logger_name: logger name (if logger specified then we ignore this argument)
    @param logger: logger object
    @param level: logging level
    @param is_console_header: set to true if console logging is required
    @param log_format: log message format
    @param is_propagate: set to true if you want to propagate log to higher level
    @return: logger
    '''
    if log_name is None or logger_name is None:
        raise ValueError(_("log_name or logger_name is not specified."))

    if logger is None:
        # Logger is singleton so if logger is already defined it will return old handler
        logger = logging.getLogger(logger_name)

    logger.propagate = is_propagate  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)

    # If handlers is already defined then do not create new handler, this way we can avoid file opening again
    # which is issue on windows see ITOA-2439 for more information
    # TODO: we do not check for type of handler, we can add this check later
    if len(logger.handlers) == 0:
        try:
            lockdir = make_splunkhome_path(['var', 'itsi', 'lock'])
            if not os.path.exists(os.path.dirname(lockdir)):
                os.mkdir(make_splunkhome_path(['var', 'itsi']))
                os.mkdir(make_splunkhome_path(['var', 'itsi', 'lock']))
            elif not os.path.exists(lockdir):
                os.mkdir(lockdir)
        except OSError, ose:
            #Swallow all "File exists" errors - another thread/process beat us to the punch
            if ose.errno != 17:
                raise

        #Note that there are still some issues with windows here, going to make it so that we dont
        file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', log_name]),
                                                            maxBytes=2500000, backupCount=5)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console stream handler
        if is_console_header:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            logger.addHandler(console_handler)

    # Read logging level information from log.cfg so it will overwrite log
    # Note if logger level is specified on that file then it will overwrite log level
    LOGGING_DEFAULT_CONFIG_FILE = make_splunkhome_path(['etc', 'log.cfg'])
    LOGGING_LOCAL_CONFIG_FILE = make_splunkhome_path(['etc', 'log-local.cfg'])
    LOGGING_STANZA_NAME = 'python'
    setupSplunkLogger(
        logger,
        LOGGING_DEFAULT_CONFIG_FILE,
        LOGGING_LOCAL_CONFIG_FILE,
        LOGGING_STANZA_NAME,
        verbose=False
    )

    return logger


from time import time
from uuid import uuid1
class InstrumentCall(object):
    '''
    Instrument a call - i.e. see how long this thing takes and potentially trace through it in
                        order to gain understanding of how long it takes for either 1) This
                        particular method to run or 2) What other things
    is this method doing on the inside.
    If you just want to put transaction tracing on a method - use @InstrumentCall(logger)
    to decorate your method
    If you want to do more detailed tracing, use the push and the pop methods to instrument
    what you want to trace through.  Use the transaction_id returned (recommended) by the first
    push or define your own (doable, but be careful of duplicate values in multi-threaded
    environments
    '''
    start_times = {}
    owners = {}
    def __init__(self, logger, loginfo=True):
        '''
        Create the instrument call object (half decorator, half not)
        @param loginfo: A flag indicating that we want to log at info (vs debug)
        @param logger: The logger to log to
        '''
        self.logger = logger
        self.loginfo = loginfo


    def __call__(self, f):
        def wrapper(decorated_self, *args, **kwargs):
            start_time = time()
            if hasattr(f, '__name__'):
                method_name = f.__name__
            else:
                method_name = str(f)
            temporary_transaction_id = self.push(method_name)
            retval = f(decorated_self, *args, **kwargs)
            self.pop(method_name, temporary_transaction_id)

            return retval
        return wrapper

    def push(self, method, transaction_id=None, owner=None):
        '''
        Push based on the passed in transaction id
        '''
        start_time = time()
        if transaction_id is None:
            transaction_id = uuid1().hex

        if self.loginfo:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        if owner is None:
            owner = "None"
        log_method("Invoked tid=%s method=%s start_time=%s owner='%s'",
                       transaction_id,
                       method,
                       start_time,
                       owner)

        InstrumentCall.owners[transaction_id] = owner
        if transaction_id not in InstrumentCall.start_times:
            InstrumentCall.start_times[transaction_id] = [start_time]
        else:
            InstrumentCall.start_times[transaction_id].append(start_time)
        return transaction_id


    def pop(self, method, transaction_id):
        '''
        Pop based on the transaction id
        '''
        if transaction_id not in InstrumentCall.start_times:
            self.logger.error("Timing information could not be determined ttid=%s", transaction_id)
            return

        start_time = InstrumentCall.start_times[transaction_id].pop()
        end_time = time()
        transaction_time = end_time - start_time

        owner = InstrumentCall.owners.get(transaction_id, "Missing")

        if self.loginfo:
            log_method = self.logger.info
        else:
            log_method = self.logger.debug
        log_method("Finished tid=%s method=%s start_time=%s end_time=%s transaction_time=%s owner='%s'",
                    transaction_id,
                    method,
                    start_time,
                    end_time,
                    transaction_time,
                    owner)
        if len(InstrumentCall.start_times[transaction_id]) == 0:
            #In longer runs, we would run into a memory problem, although unlikely, its easier
            #To deal with now
            del InstrumentCall.start_times[transaction_id]

