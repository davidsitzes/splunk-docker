# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import re
import sys

from splunk import auth
from splunk import AuthenticationFailed
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging
logger = setup_logging('itsi_module_interface.log', 'itsi.clis.itsi_module_interface')


class print_colors:
    """
    Enumeration of colors to use for printing
    """

    INFO = '\033[94m'
    OK = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_session_key(username, password, host_path):
    """
    Get session key. It is used to make the Splunk REST requests.

    @type username: string
    @param username: splunk username

    @type password: string
    @param password: splunk password

    @type host_path: string
    @param: splunkd management host path

    @rtype: string
    @param: splunkd session key
    """
    try:
        return auth.getSessionKey(username, password, host_path)
    except AuthenticationFailed as e:
        print 'Unable to login to Splunk using the given credentials. Error: ' + str(e)
        print 'Please run the command again with the correct credentials or request permissions from the Splunk admin.'
        sys.exit(1)
    except Exception as e:
        print 'Unable to login to Splunk using the given credentials. Error: ' + str(e)
        print 'Please make sure the correct host, schema and port have been provided.'
        sys.exit(1)


def is_itsi_module_name_valid(value):
    """
    Check if given ITSI module name is valid. Will error out if it has any space

    @type value: string
    @param value: ITSI module name

    @rtype: string
    @return: ITSI module name
    """
    if re.search(r'\s', value):
        print 'Error: ITSI module name cannot contain spaces!'
        sys.exit(1)

    return value


def is_port_number_negative(value):
    """
    Check if given port number is a postive integer

    @type value: string
    @param value: port number

    @rtype: int
    @return: port number as an integer
    """
    int_value = int(value)
    if int_value < 0:
        print 'Error: Port number cannot be negative. Please use a positive integer'
        sys.exit(1)
    return int_value


def print_with_color(print_color_enum, text, append_log_list=None):
    """
    Print the given text using the given color enumeration

    @type print_color_enum: print_colors
    @param print_color_enum: the color enumeration

    @type text: string
    @param text: the message to print

    @type append_log_list: list
    @param append_log_list: the list that text will be appended to
    """
    print print_color_enum + text + print_colors.ENDC

    if append_log_list is not None:
        append_log_list.append(text)


def add_common_arguments(parser):
    """
    Add common arguments to the parser

    @type parser: ArgParse
    @param parser: the parser object

    @rtype: ArgParse
    @return: parser with the added common arguments
    """
    parser.add_argument(
        '--server',
        dest='server',
        required=True,
        default='localhost',
        help='Splunk server name. Defaults to \'localhost\'.')
    parser.add_argument(
        '--user',
        dest='user',
        required=True,
        help='Splunk username, required.')
    parser.add_argument(
        '--password',
        dest='password',
        required=True,
        help='Splunk password, required.')
    parser.add_argument(
        '--scheme',
        dest='scheme',
        default='https',
        choices=['http', 'https'],
        help='Scheme to Splunkd management port. Defaults to \'https\'.')
    parser.add_argument(
        '--port',
        dest='port',
        default='8089',
        type=is_port_number_negative,
        help='Splunkd management port. Defaults to \'8089\'.')
    parser.add_argument(
        '--module-name',
        dest='itsi_module',
        required=True,
        type=is_itsi_module_name_valid,
        help='Name of ITSI module, no space or special characters, required.')

    return parser


def print_log_message(msg, logging_level='DEBUG'):
    """
    Print and log message

    @type msg: string
    @param msg: message

    @type logging_level: string
    @param logging_level: logging level. Defaults to 'DEBUG'
    """
    log_message(msg, logging_level)

    print msg

def log_message(msg, logging_level='DEBUG'):
    """
    Log message

    @type msg: string
    @param msg: message

    @type logging_level: string
    @param logging_level: logging level.
    """
    if not isinstance(msg, basestring):
        try:
            msg = str(msg)
        except Exception as e:
            logger.exception(e)
            return

    level = logging_level.strip().upper()
    if level not in ['INFO', 'WARN', 'DEBUG', 'ERROR']:
        return

    if level == 'INFO':
        logger.info(msg)
    elif level == 'WARN':
        logger.warning(msg)
    elif level == 'ERROR':
        logger.error(msg)
    else:
        logger.debug(msg)
