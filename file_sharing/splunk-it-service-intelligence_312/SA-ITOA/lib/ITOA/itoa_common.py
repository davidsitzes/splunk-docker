# -*- coding: utf-8 -*-

# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Basic utility module for itoa.  Contains miscellaneous and ubiquitous base classes
and various generic constants and utilities

ITOA-8115: remove dependencies of SA-ITOA from SA-ITSI-Licensechecker.
Manually copied to apps/SA-ITSI-Licensechecker/lib/ITOA/itoa_common.py
If you change this file, please also update the copy.

Only differences in this file are the imports:
- SA_ITOA_app_common
instead of
- SA_ITSI_Licensechecker_app_common
"""

import re
import sys
import time
import json
import glob
import shutil
import urllib
import os
import errno
import zipfile
from uuid import uuid1
import datetime
import copy
import uuid

import splunk.rest as rest
from splunk.util import utc
from splunk import ResourceNotFound
from splunk.util import localTZ

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from setup_logging import setup_logging
from itoa_exceptions import ItoaError, ItoaValidationError

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from SA_ITOA_app_common.solnlib.splunk_rest_client import SplunkRestClient
from SA_ITOA_app_common.solnlib.server_info import ServerInfo
from SA_ITOA_app_common.splunklib.binding import HTTPError


def get_local_tz_offset_to_utc_sec():
    """
    Identifies the seconds offset to apply to an epoch to convert it from local server timezone to UTC

    @rtype: float
    @return: the offset in seconds of the local server's timezone from UTC
    """
    local_tz_offset = localTZ.utcoffset(localTZ)
    return float((local_tz_offset.days * 24 * 3600) + local_tz_offset.seconds)


def get_current_timestamp_utc():
    """
    Utility to get ISO formatted UTC value for current time
    """
    return datetime.datetime.now(utc).isoformat()


def get_current_utc_epoch():
    """
    Utility to get float UTC value for current time
    """
    return time.time()


def calculate_default_schedule_time(logger, frequency='daily', scheduled_day=0, scheduled_hour=1):
    """
    Calculate default scheduled time based on frequency, day and hour setting

    @type logger: logger object
    @param logger: logger object

    @type frequency: str
    @param frequency: 'daily' or 'weekly'

    @type scheduled_day: int
    @param scheduled_day: scheduled day (0 for Monday - 6 for Sunday)

    @type scheduled_hour: int
    @param scheduled_hour: scheduled hour in from 0 - 23

    @rtype: float
    @return: Next scheduled time in UTC epoch
    """
    def _next_weekday(d, weekday):
        days_ahead = weekday - d.weekday()
        if days_ahead < 0: # Target day already happened this week
            days_ahead += 7
        return d + datetime.timedelta(days_ahead)

    current_time = datetime.datetime.now()
    if not is_valid_num(scheduled_hour) or scheduled_hour > 23 or scheduled_hour < 0:
        scheduled_hour = 0

    if frequency == 'daily':
        next_run_time = current_time.replace(hour=scheduled_hour, minute=0, second=0)
        if (current_time - next_run_time).total_seconds() >= 0:
            next_run_time += datetime.timedelta(days=1)

    elif frequency == 'weekly':
        next_day = _next_weekday(current_time, scheduled_day)
        next_run_time = next_day.replace(hour=scheduled_hour, minute=0, second=0)
        if (current_time - next_run_time).total_seconds() >= 0:
            next_run_time += datetime.timedelta(days=7)

    next_run_time_utc = (next_run_time - datetime.datetime(1970,1,1)).total_seconds() - get_local_tz_offset_to_utc_sec()

    localtime = time.localtime()
    if localtime.tm_isdst == 1:
        next_run_time_utc -= 60 * 60
        logger.debug('Perform a shift due to daylight saving.')

    return next_run_time_utc


class JsonPathElementNotArrayException(Exception):
    pass


class JsonPathElement(object):
    """
    A JSON Path from conf looks like `entry.{0}.content`
    It indicates the path to traverse to a pertinent blob.
    i.e.
    1. First read the value key'ed by `entry`.
    2. This value is an array indicated by `{0}` and in it, the value
        we care about is the 1st indicated by 0.
    3. Next, fetch the value key'ed by `content`.

    Usage::
    >>> path = 'entry.{0}.content'
    >>> elems = path.split('.')
    >>> for e in elems:
    >>>     json_elem = JsonPathElement(e)
    >>>         if json_elem.is_array():
    >>>            # retrieve index'ed blob
    >>>            pass
    >>>         else:
    >>>             # elem is dict, retrieve it, do stuff
    >>>             pass
    """

    def __init__(self, elem):
        if any([not isinstance(elem, basestring), isinstance(elem, basestring) and not elem.strip()]):
            raise TypeError(_('Invalid path element. %s') % elem)

        self.elem = elem

        # lets try and make "match groups" if element is an array
        # {1} or {0} are examples. There will be only one capture group.
        # everything preceeding the numeral and trailing the numeral is not captured
        array_pattern = re.compile('^(?:[a-zA-Z]*{)([0-9]*)(?:})$')
        self.array_match = re.match(array_pattern, self.elem)

    def __str__(self):
        return self.elem

    def is_array(self):
        return True if self.array_match else False

    def get_array_index(self):
        """
        returns the index in the path which corresponds to an array
        Ex: if elem = `{1}`, return `1`
        @rtype: int
        @returns: an integer corresponding to the array index

        @raises JsonPathElementNotArrayException if element is not an index
        """
        if not self.is_array():
            raise JsonPathElementNotArrayException(_('Element `%s` is not an array') % self.elem)
        # if elem is indeed an array, we are guaranteed 1 element in the group, OK to
        # access the group using index.
        return int(self.array_match.group(1))

    def is_dict(self):
        return not self.is_array()


def get_session_user(session_key):
    """
    Get current username for given session key
    @param session_key: splunkd session key
    @param type: basestring

    @return username: current user logged into the system
    @return type: str

    @raise TypeError: if invalid session_key
    @raise AttributeError: if user is not logged into system
    """
    if not isinstance(session_key, basestring):
        raise TypeError(_('Invalid session key'))

    resp, content = rest.simpleRequest(
        '/authentication/current-context',
        getargs={'output_mode':'json'},
        sessionKey=session_key,
        raiseAllErrors=False)
    content = json.loads(content)
    return content['entry'][0]['content']['username']


def modular_input_should_run(session_key, logger=None):
    """
    Determine if a modular input should run or not.
    Run if and only if:
    1. Node is not a SHC member
    2. Node is an SHC member and is Captain
    @return True if condition satisfies, False otherwise
    """
    if any([not isinstance(session_key, basestring), isinstance(session_key, basestring) and not session_key.strip()]):
        raise ValueError(_('Invalid session key'))

    info = ServerInfo(session_key)
    logger = get_itoa_logger(None) if not logger else logger

    if not info.is_shc_member():
        return True

    timeout = 300  # 5 minutes
    while(timeout > 0):
        try:
            # captain election can take time on a rolling restart.
            if info.is_captain_ready():
                break
        except HTTPError as e:
            if e.status == 503:
                logger.warning('SHC may be initializing on node `%s`. Captain is not ready. Will try again.', info.server_name)
            else:
                logger.exception('Unexpected exception on node `%s`', info.server_name)
                raise
        time.sleep(5)
        timeout -= 5

    # we can fairly be certain that even after 5 minutes if `is_captain_ready`
    # is false, there is a problem
    if not info.is_captain_ready():
        raise Exception(_('Error. Captain is not ready even after 5 minutes. node=`%s`'), info.server_name)

    return info.is_captain()


def add_to_sys_path(paths):
    for path in paths:
        if path not in sys.path:
            sys.path.append(path)


def get_itoa_logger(logger_name, file_name=None):
    """
    Get a logger instance.
    """
    if isinstance(logger_name, basestring) and len(logger_name) > 0:
        LOGGER = logger_name
    else:
        LOGGER = 'itoa.common'

    if isinstance(file_name, basestring) and len(file_name) > 0:
        FILE = file_name
    else:
        FILE = 'itsi.log'

    return setup_logging(FILE, LOGGER)


def get_object(object_):
    """
    given an object, try to get a dict/list type
    merely a wrapper to json.loads(). doesnt crap out and returns None if
    invalid.
    @param object_: input object, any type
    @return dict/list if valid, None if otherwise
    """
    rval = None
    if isinstance(object_, basestring):
        try:
            rval = json.loads(object_)
        except Exception:
            pass
    elif isinstance(object_, dict):
        rval = object_
    elif isinstance(object_, list):
        rval = object_
    return rval


def extract(objects, key):
    """
    given a list of objects, extract requested values given key, dedup
    and return a list
    @type objects: dict/list
    @param objects: objects to iterate over and extract id from
    @type key: basestring
    @param key: `key` that corresponds to the id
    @return a list of object ids
    @raises Exception
    """
    ids_ = []

    # always work with list
    objects = get_object(objects)
    if not objects:
        return ids_

    if isinstance(objects, dict):
        objects = [objects]
    if not isinstance(objects, list):
        raise Exception(_('Expecting `objects` to be list/dict type and not `%s`') % type(objects).__name__)
    for i in objects:
        if i.get(key):
            ids_.append(i[key])
    return list(set(ids_))


def get_supported_itoa_operations():
    """
    Method returns a list of supported operations on ITOA object types...
    """
    return ['read', 'write', 'delete']


def get_privatizeable_object_types():
    """
    method that returns a list of object types that can have a `private`
    ownership vs `public` ownership
    i.e.
    """
    return ['home_view', 'glass_table', 'deep_dive']


def massage_string_array(string_array, separator=','):
    """
    Some of the stuff that we get from the frontend can be not in the style we expect it to be
    So we need to massage it.  We'll also trim any spacing that we find in the thing
    @return - Always an array
    """
    if string_array is None:
        return []
    elif isinstance(string_array, basestring):
        # Convert from the string specification to something we can process
        string_array = string_array.split(separator)
    if not isinstance(string_array, list):
        raise Exception(_('Unable to convert string_array - passed in a {0}').format(
            str(string_array.__class__)))
    # Strip the leading and trailing whitespace
    string_array = [i.strip() for i in string_array]
    return string_array


def validate_json(log_prefix, json_data):
    """
    Quick and dirty parsing/json validation,

    @return: Parsed json dict/list (or unaltered dict if it was a dict originally)
    @rval: dict or list parsed json
    """
    if json_data is None:
        raise Exception(log_prefix + 'Missing json_data')
    elif is_valid_dict(json_data):
        return json_data
    elif is_valid_list(json_data):
        return json_data

    try:
        data = json.loads(json_data)
    except TypeError:
        logger = get_itoa_logger(None)
        logger.exception('Unable to parse as json data: Received %s', json_data.__class__.__name__)
        raise
    return data


def remove_keys_from_dict(keys_as_list, dictionary):
    """
    given a list of keys and a dictionary, remove the key-value pairs from it
    @param keys_as_list: list of keys
    @param dictionary: dict under consideration
    @return list of keys that were removed
    """
    removed = []
    if isinstance(keys_as_list, list) and isinstance(dictionary, dict):
        for key in keys_as_list:
            attribute = dictionary.pop(key, None)
            if attribute:
                removed.append(key)
    return removed


def is_valid_dict(data):
    return isinstance(data, dict)


def is_valid_list(data):
    return isinstance(data, list)


def is_valid_num(data):
    return isinstance(data, int)


def is_string_numeric(data):
    try:
        float(data)
        return True
    except (ValueError, TypeError):
        return False


def is_string_numeric_int(data):
    try:
        int(data)
        return True
    except (ValueError, TypeError):
        return False


def is_stats_operation(statsop):
    """
    List of ITOA supported statistical operators.
    percNN is not in the list, further validation will handle the check for percNN.
    @type statsop: string
    @param statsop: input stats operator
    @type return: boolean
    @param return: True if the stats operator is in the supported list, False otherwise.
    """
    statsop = statsop.strip().lower()
    precNN = re.compile(r'^perc\d{1,2}$')
    stats_operation = ['avg', 'count', 'dc', 'max', 'min', 'sum', 'stdev', 'median',
                       'duration', 'latest', 'earliest']
    try:
        if any([
                statsop in stats_operation,
                precNN.search(statsop)
        ]):
            return True
    except Exception:
        pass

    return False


def is_valid_perc(number):
    """
    Utility function to check percNN string and if the NN
    falls into the range between 1 and 99.
    @type number: string
    @param number: number after the perc string
    @type return: boolean
    @param return: True if NN is within the expected range, False otherwise.
    """
    if is_string_numeric(number):
        perc = int(float(number))
        return 99 >= perc >= 1

    return False


def normalize_bool_flag(flag):
    """
    Normalizes a boolean flag to python bool variable.
    @param flag: input flag
    @return: bool
    """
    is_true = False
    if isinstance(flag, bool):
        is_true = flag
    elif isinstance(flag, basestring):
        if flag.strip().lower() == 'true' or flag.strip() == '1':
            is_true = True
    elif isinstance(flag, int):
        if flag == 1:
            is_true = True
    return is_true


def normalize_num_field(json_data, field, numclass=int):
    """
    Normalizes field in JSON payload to float
    NOTE: Will not raise an exception on change,
    make sure to validate that this field was updated

    @type: dict
    @param json_data: JSON payload

    @type: string
    @param field: field to normalize

    @type numclass: Class
    @param numclass: The numerical class to cast the object as, default int

    @rtype: None
    @return: JSON payload is updated if needed
    """
    if ((field in json_data) and
            ((is_valid_num(json_data[field]) or
              is_string_numeric(json_data[field])))):
        # Always cast as float first
        json_data[field] = numclass(float(json_data.get(field, 0)))
    # Else not a numeric type, do not normalize


def intersection_of_arrays(dst, src):
    """
    Compare two array and return intersection of dst and src (dst-src)
    Note: both array should be integer arrays
    :param {list} dst: list of items
    :param {list} src: list of items
    :return {list}: only element of dst which exists in src array
    """
    if not is_valid_list(dst) or not is_valid_list(src):
        return []
    return list(set(dst).intersection(set(src)))


def is_equal_lists(dst, src):
    """
    Check if elements of two array are same or not
    Note: both array should be integer arrays
    :param {list} dst: list of items
    :param {list} src: list of items
    :return {list}: only element of dst which exists in src array
    """
    if not is_valid_list(dst) or not is_valid_list(src):
        return False
    dst_set = frozenset(dst)
    src_set = frozenset(src)
    return dst_set == src_set


def dict_to_search_field_value(dictionary):
    assert is_valid_dict(dictionary)
    result = ''
    first_iter = True
    for key, value in dictionary.items():
        if first_iter:
            first_iter = False
        else:
            result += ','
        result += key + '='
        if isinstance(value, basestring):
            result += value
        elif is_valid_dict(value):
            result += dict_to_search_field_value(value)
        elif is_valid_list(value):
            parsed_items = []
            for item in value:
                if is_valid_dict(item):
                    parsed_items.append(dict_to_search_field_value(item))
                elif isinstance(item, basestring):
                    parsed_items.append(item)
                else:
                    parsed_items.append(str(item))
            result += ','.join(parsed_items)
        else:
            result += str(value)
    return result


regex_all_spaces = re.compile('^(?u)\s*$')


def is_valid_str(data):
    return isinstance(data, basestring) and (len(data) > 0) and (not re.match(regex_all_spaces, data))


regex_invalid_characters = re.compile('[="\']+')


def is_valid_name(data):
    """
    Checks to see if the string passed in is a valid string and does
    not contain invalid characters
    @param data: The string to validate name characters against
    @type data: string
    """
    return is_valid_str(data) and (not re.search(regex_invalid_characters, data))


def squish_whitespace(squishy):
    """
    Eliminate contiguous whitespace and newlines and replace them a single space.
    Also eliminates leading and trailing whitespace.

    @param squishy: string to squish whitespace in
    @type squishy: str
    @return: string with all whitespace and newline reduced to a single space
    @rtype: str
    """
    return re.sub('\s+', ' ', squishy).strip()


def post_splunk_user_message(message, session_key=None, severity='info', namespace='SA-ITOA', owner='nobody'):
    """
    Using the Messenger API passed to us by core, post a message to the user through the messages
    endpoint
    """
    if not isinstance(message, basestring):
        return False

    message = message if len(message) <= 500 else message[0:499] + '...'
    try:
        msg = SplunkRestClient(
            session_key=session_key,
            owner=owner,
            app=namespace).messages
        return msg.post(name=str(uuid1()), value=message, severity=severity)
    except Exception as e:
        # Best effort, log and continue
        logger = get_itoa_logger(None)
        logger.exception(e)
        pass
    return False


def get_conf_rest_path(conf_name, app='itsi'):
    return rest.makeSplunkdUri() + 'servicesNS/nobody/' + app + '/configs/conf-' + conf_name


def get_conf(session_key, conf_name, search=None, count=0, app='itsi'):
    getargs = {'output_mode': 'json', 'count': count}
    if is_valid_str(search):
        getargs['search'] = search

    response, content = rest.simpleRequest(
        get_conf_rest_path(conf_name, app),
        method='GET',
        getargs=getargs,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    return {'response': response, 'content': content}


def get_conf_stanza(session_key, conf_name, stanza_name, app='itsi'):
    getargs = {'output_mode': 'json'}
    rest_path = get_conf_rest_path(conf_name, app) + '/' + urllib.quote_plus(stanza_name)
    response, content = rest.simpleRequest(
        rest_path,
        method='GET',
        getargs=getargs,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    return {'response': response, 'content': content}


def get_conf_stanza_single_entry(session_key, conf_name, stanza_name, entry_name):
    uri = '/servicesNS/nobody/SA-ITOA/properties/' + conf_name + '/' + stanza_name + '/'+ entry_name
    response, content = rest.simpleRequest(
        uri,
        method="GET",
        sessionKey=session_key,
        getargs={'output_mode': 'json'},
        raiseAllErrors=False
        )
    return {'response': response, 'content': content}


def create_conf_stanza(session_key, conf_name, conf_stanza, app='itsi'):
    postargs = conf_stanza
    postargs['output_mode'] = 'json'
    response, content = rest.simpleRequest(
        get_conf_rest_path(conf_name, app),
        method='POST',
        postargs=postargs,
        sessionKey=session_key,
        raiseAllErrors=True
    )
    return {'response': response, 'content': content}


def update_conf_stanza(session_key, conf_name, conf_stanza, app='itsi'):
    postargs = conf_stanza
    postargs['output_mode'] = 'json'
    rest_path = get_conf_rest_path(conf_name, app) + '/' + urllib.quote_plus(conf_stanza.get('name', ''))
    del postargs['name']
    response, content = rest.simpleRequest(
        rest_path,
        method='POST',
        postargs=postargs,
        sessionKey=session_key,
        raiseAllErrors=True
    )
    return {'response': response, 'content': content}


def delete_conf_stanza(session_key, conf_name, conf_stanza_name, app='itsi'):
    response, content = rest.simpleRequest(
        get_conf_rest_path(conf_name, app) + '/' + urllib.quote_plus(conf_stanza_name),
        method='DELETE',
        sessionKey=session_key,
        raiseAllErrors=True
    )
    return {'response': response, 'content': content}


class ItoaBase(object):
    log_prefix = '[Itoa Base] '

    def __init__(self, session_key):
        self.session_key = session_key

    def raise_error(self, logger, message, status_code=500):
        raise ItoaError(message, logger, self.log_prefix, status_code=status_code)

    def raise_error_bad_validation(self, logger, message, status_code=400):
        raise ItoaValidationError(message, logger, self.log_prefix, status_code=status_code)


def get_object_size_in_bytes(object_name):
    """
    Return size of an object. The object can be any type of object

    @type object_name: object
    @param object_name: object name

    @rtype int
    @return: return size of object
    """
    return sys.getsizeof(str(object_name))


def is_size_less_than_50_mb(object_name):
    """
    Size of object

    @type object_name: object
    @param object_name: object name

    @rtype bool
    @return: True if size is less than 50MB otherwise False
    """
    size = get_object_size_in_bytes(object_name)
    if not size:
        raise ValueError(_('Failed to get size of object={0}.').format(object_name))
    else:
        size_in_mb = float(size) / 1024 / 1024
        # Check if size is less then 50 MB, Splunk truncate data if size of post request
        # is more than 50 MB
        # TODO: Get splunkd post request size from server.conf file
        return size_in_mb < 50


def save_batch(itoa_object,
               owner,
               data_list,
               no_batch=False,
               dupname_tag=None):
    """
    Splunk does not support the saving of an object whose size  is more than 50 MB
    Hence handle that scenario while doing batched saved.
    If the size of an object is greater than 50MB, break it down till each chunk is less than or equal to 50 MB

    @type itoa_object: instance
    @param itoa_object: one of itoa object instance

    @type owner: basestring
    @param owner: owner

    @type data_list: list
    @param data_list: list of data which need to save

    @return: a list json object contain all the failed objects
    """
    logger = get_itoa_logger('itoa.common')
    failed_json = []
    if no_batch:
        for object_data in data_list:
            results = itoa_object.get(owner, object_data.get('_key'))
            try:
                if results is None or len(results) == 0:
                    itoa_object.create(owner, object_data, dupname_tag)
                else:
                    itoa_object.update(owner, object_data.get('_key'), object_data, dupname_tag)
            except Exception:
                failed_json.append(object_data)
    else:
        if is_size_less_than_50_mb(data_list):
            logger.debug('data_list less than 50mb, ok to save now')
            itoa_object.save_batch(owner,
                                   data_list,
                                   True,
                                   dupname_tag)
        else:
            # Cut down the size and do the batch save
            total_length = len(data_list)
            logger.debug('data_list is: %s and size is more than 50mb, split the data for batch_save' % total_length)
            if total_length == 1:
                raise ValueError(_('Size of one object={0} is more than 50 MB, splunk can\'t handle that size.').format(str(itoa_object)))

            first_half = data_list[0:total_length / 2]
            second_half = data_list[total_length / 2:total_length]
            save_batch(itoa_object, owner, first_half)
            save_batch(itoa_object, owner, second_half)
    return failed_json


class FileManager(object):
    """
    Manager file operation
    """
    DELIMITER = '___'
    logger = get_itoa_logger(None)

    @staticmethod
    def delete_file(path):
        """
        Deletes the file at the path provided

        @type path: basestring
        @param path: directory path

        """
        try:
            os.remove(path)
        except OSError as e:
            FileManager.logger.warning(e)

    @staticmethod
    def is_file(path):
        """
        Check if it is file or not

        @type path: basestring
        @param path: directory path

        @rtype: bool
        @return: True or False
        """
        return os.path.isfile(path)

    @staticmethod
    def is_directory(path):
        """
        Check if it is directory

        @type path: basestring
        @param path: directory path

        @rtype: bool
        @return: True or False
        """
        return os.path.isdir(path)

    @staticmethod
    def is_exists(path):
        """
        Check if the path exist or not

        @type path: basestring
        @param path: directory path

        @rtype: bool
        @return: True or False base on existence of the path
        """
        return os.path.exists(path)

    @staticmethod
    def get_base_dir(file):
        """
        Get base dir of given file. If directory is passed then return dir

        @type file: basestring
        @param file: file path

        @return: Base directory - if file path is passed
        @rtype: basestring
        """
        if os.path.isfile(file):
            return os.path.dirname(file)
        elif os.path.isdir(file):
            return file
        elif file is None:
            return os.getcwd()

    @staticmethod
    def create_directory(path):
        """
        Create directory

        @type path: basestring
        @param path: directory path
        @return:
        """
        try:
            os.makedirs(path)
            FileManager.logger.debug('Successfully created directory, path=%s', path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                FileManager.logger.exception(e)
                raise e

    @staticmethod
    def zip_directory(root_path, name_of_zip_file):
        """
        Zip the directory

        @type path: basestring
        @param path: directory path
        """
        try:
            os.chdir(os.path.dirname(root_path))
            with zipfile.ZipFile(name_of_zip_file + '.zip',
                                 'w',
                                 zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as zf:
                for root, _, filenames in os.walk(os.path.basename(root_path)):
                    for name in filenames:
                        name = os.path.join(root, name)
                        name = os.path.normpath(name)
                        zf.write(name, name)
        except Exception as exc:
            FileManager.logger.exception(exc)
            raise

    @staticmethod
    def unzip_backup(path_to_zip_file, extract_to_path):
        """
        Unzip the backup zip file and rename the extracted folder to the parent folder name in extract_to_path

        @type path_to_zip_file: basestring
        @param path_to_zip_file: path to zip file including .zip extension

        @type extract_to_path: basestring
        @param extract_to_path: path to extract to
        """
        zip_ref = zipfile.ZipFile(path_to_zip_file, 'r')
        zip_ref.extractall(extract_to_path)
        zip_ref.close()

    @staticmethod
    def delete_working_directory(path):
        """
        Delete the working directory that contains the json files

        @type path: basestring
        @param path: directory path
        """
        try:
            shutil.rmtree(path)
        except OSError as ose:
            FileManager.logger.exception(ose)
            raise

    @staticmethod
    def write_to_file(file_path, data, flag='w+'):
        """
        Write a valid json convert-able data to the file_path

        @type file_path: basestring
        @param file_path: file_path path

        @type data: dict
        @param data: json data to write

        @type flag: basestring
        @param flag: file_path opening flags

        @return:
        """
        with open(file_path, flag) as fp:
            fp.writelines(json.dumps(data))

    @staticmethod
    def read_data(file_path, flag='r'):
        """
        Read data from given file_path and return json object

        @type file_path: basestring
        @param file_path: file_path path

        @type flag: basestring
        @param flag: file_path opening flags

        @rtype: json dict
        @return: json based dict
        """
        with open(file_path, flag) as fp:
            data = json.load(fp)

        return data

    @staticmethod
    def clean_file(file_path):
        """
        Delete content of the file

        @type file_path: basestring
        @param file_path: file path

        @return:
        """
        if os.path.exists(file_path):
            try:
                open(file_path, 'w').close()
            except Exception as exc:
                FileManager.logger.error(exc.message)
                FileManager.logger.info('Failed to clean existing file, will append data to existing file')

    @staticmethod
    def get_rolling_file_name(file_path, rolling_file_number=0):
        """
        Get rolling file name
        for example: ('/tmp/foo.txt,2) would return /tmp/foo___2.txt where ____ is the DELIMITER string

        @type file_path: basestring
        @param file_path: file path

        @type rolling_file_number: integer
        @param rolling_file_number: rolling file number

        @rtype: basestring
        @return: file name
        """
        basedir = os.path.dirname(file_path)
        basefilename = os.path.basename(file_path)
        tmp_file = basefilename[0:basefilename.rfind('.')] + FileManager.DELIMITER +\
            str(rolling_file_number) + basefilename[basefilename.rfind('.'): len(basefilename)]
        return os.path.join(basedir, tmp_file)

    @staticmethod
    def get_zip_file_names(directory_path):
        """
        Get filenames with a .zip extension in the directory provided by directory_path

        @:rtype: list
        @return: list of filenames

        """
        file_paths = glob.glob(os.path.join(directory_path,'*.zip'))
        if isinstance(file_paths, list) and len(file_paths) > 0:
            return [fpath.split(os.sep)[-1].split('.zip')[-2] for fpath in file_paths]
        else:
            return None


class SplunkUser(object):
    """
    Class to wrap Splunk's user info interactions
    """
    @staticmethod
    def fetch_user_access_info(username, session_key, logger):
        """
        Given a username, fetch the user's access control details

        @type username: string
        @param username: concerned username

        @type session_key: string
        @param session_key: splunkd session key

        @type logger: object
        @param logger: logger to use

        @rtype: dict
        @return object: json'ified access details of username
        """
        if (not isinstance(username, basestring)) or len(username.strip()) < 1:
            raise Exception(_('Expecting a valid username, "{0}" is invalid') % username)
        if (not isinstance(session_key, basestring)) or len(session_key.strip()) == 0:
            raise Exception(_('Expecting a valid session_key, "%s" is invalid') % session_key)

        uri = '/services/authentication/users/%s' % username
        getargs = {'output_mode': 'json'}
        try:
            response, content = rest.simpleRequest(
                uri,
                method='GET',
                getargs=getargs,
                sessionKey=session_key)
        except Exception as e:
            logger.exception(e)
            raise

        if response.status != 200:
            message = _('Error while polling Splunkd for user access information. Response: "%s".' \
                      ' Content: "%s".') % (response, content)
            logger.error(message)
            raise Exception(message)
        else:
            logger.debug('Fetched user access details for user "%s": %s', username, content)
            return json.loads(content)

    @staticmethod
    def fetch_role_info(role_name, session_key, logger):
        """
        Given a role name, fetch the role's details

        @type role_name: basestring
        @param role_name: concerned role

        @type session_key: string
        @param session_key: splunkd session key

        @type logger: object
        @param logger: logger to use

        @rtype: dict
        @return object: json'ified details of role
        """
        if (not isinstance(role_name, basestring)) or len(role_name.strip()) < 1:
            raise Exception(_('Expecting a valid username, "{0}" is invalid') % role_name)
        if (not isinstance(session_key, basestring)) or len(session_key.strip()) == 0:
            raise Exception(_('Expecting a valid session_key, "%s" is invalid') % session_key)

        uri = '/services/authorization/roles/%s' % role_name.replace(' ', '%20')
        getargs = {'output_mode': 'json'}
        try:
            response, content = rest.simpleRequest(
                uri,
                method='GET',
                getargs=getargs,
                sessionKey=session_key,
                raiseAllErrors=False)
        except Exception as e:
            logger.exception(e)
            raise

        if response.status != 200:
            message = _('Error while polling Splunkd for role information. Response: "%s".' \
                      ' Content: "%s".') % (response, content)
            logger.error(message)
            raise Exception(message)
        else:
            logger.debug('Fetched details for role "%s": %s', role_name, content)
            return json.loads(content)

    @staticmethod
    def get_roles_for_user(username, session_key, logger):
        """
        Given a username, fetch the roles assigned to the user

        @type username: string
        @param username: concerned username

        @type session_key: string
        @param session_key: splunkd session key

        @type logger: logging.logger
        @param logger: logger to use

        @rtype: tuple with two lists of strings
        @return: tuple of list of roles directly assigned to user and full list of roles accounting for role inheritance
        """

        # if username is nobody, replace it with admin for testing purpose
        # NOTE: this function should only be used by itsi_security_group
        if username == 'nobody':
            username = 'admin'

        try:
            user_access_info = SplunkUser.fetch_user_access_info(username, session_key, logger)
        except ResourceNotFound:
            logger.warn('User %s could not be looked up, returning no roles.', username)
            return [], []

        if not (
            isinstance(user_access_info.get('entry'), list) and
            len(user_access_info.get('entry')) == 1 and
            isinstance(user_access_info['entry'][0].get('content'), dict) and
            'roles' in user_access_info['entry'][0]['content']
        ):
            raise Exception(_('Could not find roles for the user "%s". User access info: %s') % (username, user_access_info))

        roles_for_user = user_access_info['entry'][0]['content']['roles']
        roles_for_user = roles_for_user if isinstance(roles_for_user, list) else[]
        all_roles_for_user = set(roles_for_user)
        processed_roles = set()

        def append_inherited_roles(role):
            if role in processed_roles:
                # Prevent looping forever from cyclic inheritance
                return
            else:
                processed_roles.add(role)

            # Recursively add roles via inheritance for each roles assigned to user
            role_info = SplunkUser.fetch_role_info(role, session_key, logger)
            if not (
                isinstance(role_info.get('entry'), list) and
                len(role_info.get('entry')) == 1 and
                isinstance(role_info['entry'][0].get('content'), dict) and
                'imported_roles' in role_info['entry'][0]['content']
            ):
                logger.debug('Could not fetch inherited roles for role "%s"', role)
                return

            inherited_roles = role_info['entry'][0]['content']['imported_roles']
            inherited_roles = inherited_roles if isinstance(inherited_roles, list) else []

            for inherited_role in inherited_roles:
                all_roles_for_user.add(inherited_role)
                append_inherited_roles(inherited_role)

        for role in roles_for_user:
            append_inherited_roles(role)

        return roles_for_user, list(all_roles_for_user)
