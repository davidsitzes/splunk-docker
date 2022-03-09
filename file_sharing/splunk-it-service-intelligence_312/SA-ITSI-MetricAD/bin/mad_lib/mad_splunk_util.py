import logging
from splunk import entity
from splunk import setupSplunkLogger
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest
import json


def setup_logging(log_name, logger_name, logger=None, level=logging.INFO, is_console_header=False,
                  log_format='%(asctime)s %(levelname)s [%(name)s] [%(module)s] [%(funcName)s] %(message)s', is_propagate=False):
    '''Setup logging

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
        raise ValueError("log_name or logger_name is not specified")

    if logger is None:
        # Logger is singleton so if logger is already defined it will return old handler
        logger = logging.getLogger(logger_name)

    logger.propagate = is_propagate  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)

    if len(logger.handlers) == 0:
        file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', log_name]),
                                                            maxBytes=2500000, backupCount=5)
        formatter = logging.Formatter(log_format)
        file_handler.setFormatter(formatter)
        logger.handlers = []
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


def get_user_capabilities(user=None):
    """
    Obtains a list of capabilities in an list for the given user.

    Arguments:
    user -- The user to get capabilities for (as a string)
    """

    roles = []
    capabilities = []

    # Get user info
    if user is not None:
        userEntities = entity.getEntities('authentication/users/%s' % user, count=-1)

        for stanza, settings in userEntities.items():
            if stanza == user:
                for key, val in settings.items():
                    if key == 'roles':
                        roles = val

    # Get capabilities
    for role in roles:
        roleEntities = entity.getEntities('authorization/roles/%s' % role, count=-1)

        for stanza, settings in roleEntities.items():
            if stanza == role:
                for key, val in settings.items():
                    if key == 'capabilities' or key == 'imported_capabilities':
                        capabilities.extend(val)

    return capabilities


def get_conf_stanza(session_key, conf_name, stanza_name, app='SA-ITSI-MetricAD'):
    getargs = {'output_mode': 'json'}
    uri = '/servicesNS/nobody/' + app + '/properties/' + conf_name + '/' + stanza_name

    response, content = rest.simpleRequest(
        uri,
        method='GET',
        getargs=getargs,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    return response, json.loads(content)
