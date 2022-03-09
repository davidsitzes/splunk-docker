# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
This module handles getting results in and out of the splunk search protocol
For most things, you'll want read_chunk and write_chunk
'''
import sys
import re
import json
import abc
import cStringIO
import time
from splunk.appserver.mrsparkle.lib import i18n

from .setup_logging import setup_logging

"""
If you are reading or writing binary data, such as an image, under Windows,
the file must be opened in binary mode.
But unix does not make a distinction between text and binary modes
"""
if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)


class SearchChunkProtocol(object):
    """
    New Search Chunk Protocol 1.0 follows the below steps

    1. splunk send action type "getinfo" with header which hold meta information
    2. Command need to send back method with information like type of search
    3. Once initial hand shake is done, Splunk send data in chunks, search command process it and
       send data back to splunk with {"finished":false}. This can be infinite times
    4. When search is done, it need to send { "finished": true } to splunk to finalize the search
    """

    __metaclass__ = abc.ABCMeta

    stdin = sys.stdin
    stdout = sys.stdout
    stderr = sys.stderr

    def __init__(self, output_meta_data, is_send_ack=True, logger=None):
        """
        Initialize. It negotiate getinfo exchange fully and defined search command argument and session key
            self.session_key
            self.args

        @type output_meta_data: dict
        @param output_meta_data: output meta data which need to be send during getinfo exchange phase
                this dict must contain type ( possible values of type would be ['streaming', 'stateful', 'events',
                 'reporting']

        @type is_send_ack: bool
        @param is_send_ack: set this flag to avoid sending write back for get info handshake, if this is false, then
                write_chunk need to be called to complete handshake

        @type logger: object
        @param logger: if logger specified then overwrite the class logger
        @return:
        """
        if not (isinstance(output_meta_data, dict) and 'type' in output_meta_data.keys()):
            raise AttributeError(_("type is not defined in out_meta_data to do get-exchange phase"))

        if output_meta_data.get('type') not in ['streaming', 'stateful', 'events', 'reporting']:
            raise ValueError(_('Invalid type value'))

        if not logger:
            self.logger = setup_logging("itsi_searches.log", "itsi.command.chunk")
        else:
            self.logger = logger

        # Phase 0 getinfo exchange phase
        ret = self.read_getinfo(sys.stdin)
        if not ret:
            raise ValueError(_("Getinfo exchanges does not contain meta data"))

        metadata, body = ret
        if metadata.get('searchinfo'):
            self.session_key = metadata.get('searchinfo', {}).get('session_key')
            self.args = {}
            args = metadata.get('searchinfo', {}).get('args')
            # Convert Array to key value
            for arg in args:
                if arg.find("=") != -1:
                    key, value = arg.split("=")
                    self.logger.debug("Adding search command argument key=%s, value=%s", key, value)
                    self.args[key] = value
                else:
                    self.logger.warning("Invalid argument, arg=%s", arg)

        # Store earliest time
        earliest_time = metadata.get('earliest_time')
        if not earliest_time:
            self.logger.warning("Earliest time (earliest_time) is undefined or zero")
            earliest_time = time.time()
        self.earliest_time = float(earliest_time)
        # Send output
        # Make sure finished is defined
        if 'finished' not in output_meta_data.keys():
            output_meta_data.setdefault('finished', False)

        # Class validate function to validate search command arguments, if it fails, it should return message
        is_valid, inspector_msgs = self.validate_search_args()

        if not is_valid:
            if isinstance(inspector_msgs, list):
                self.exit_with_error(output_meta_data, inspector_msgs)
            else:
                self.exit_with_error(output_meta_data, "Invalid arguments in search command")
        else:
            if is_send_ack:
                self.write_chunk(output_meta_data, '')

        self.logger.debug('Search Chunk Protocol has initialized successfully.')

    def get_session_key(self):
        """
        Return session key

        @type: basestring
        @return: return splunkd session key
        """
        return self.session_key

    def get_search_args(self):
        """
        Get search command argument

        @type: basestring
        @return: return search command parameters
        """
        return self.args

    def read_getinfo(self, fp=None):
        """
        Read action:getinfo which is send by splunk as first chunk to external commands
        @return:
        """
        if fp is None:
            fp = self.stdin

        ret = self.read_chunk(fp)
        if not ret:
            return None
        metadata, body = ret
        return metadata, body

    def read_chunk(self, fp=None):
        """
        Read chunk and parse it

        @type fp: object
        @param fp: file descriptor to read the data from

        @rtype tuple
        @return: a tuple of metadata and body otherwise log exception and send None
        """
        if fp is None:
            fp = self.stdin

        # When search does not have any data like index=abc (abc index does not present)
        # in that case, we can't read anything from stdin so we wait until Splunk write
        # something in the pipe. Splunk will terminate if it does not write anything in the pipe

        # Because EOF and invalid index both return empty string hence using timeout to avoid infinite loop
        timeout = 5 # secs
        currentTime = time.time()
        while True:
            try:
                header = fp.readline()
            except Exception as e:
                self.logger.exception(e)
                return None

            self.logger.debug("Header='%s'", header)
            if not header or len(header) == 0:
                # If time out log and bail out
                if time.time() - currentTime >= timeout:
                    self.logger.error("Timeout while reading header of chunk command")
                    return None
                else:
                    continue
            else:
                break

        m = re.match('chunked\s+1.0\s*,\s*(?P<metadata_length>\d+)\s*,\s*(?P<body_length>\d+)\s*\n', header)
        if m is None:
            self.logger.error('Failed to parse transport header: %s', header)
            return None

        try:
            metadata_length = int(m.group('metadata_length'))
            body_length = int(m.group('body_length'))
        except Exception as e:
            self.logger.exception(e)
            self.logger.error('Failed to parse metadata or body length')
            return None

        self.logger.debug('READING CHUNK %d %d', metadata_length, body_length)

        try:
            metadata_buf = fp.read(metadata_length)
            body = fp.read(body_length)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error('Failed to read metadata or body: %s' % str(e))
            return None

        try:
            metadata = json.loads(metadata_buf)
        except Exception as e:
            self.logger.exception(e)
            self.logger.error('Failed to parse metadata JSON')
            return None

        return metadata, body

    def write_chunk(self, metadata, body, fp=None):
        """
        Send data to splunk
        @type: fp: object
        @param fp: file descriptor

        @type metadata: dict
        @param metadata: metadata which needed to be add

        @type body: basestring
        @param body: data to send to splunk. If it is None then it set to a empty string

        @return: None
        """
        self.logger.debug("Started writing chunk metadata=%s, body=%s", metadata, body)

        if fp is None:
            fp = self.stdout

        if body is None:
            body = ''

        metadata_buf = None
        if metadata:
            metadata_buf = json.dumps(metadata)
        fp.write('chunked 1.0,%d,%d\n' % (len(metadata_buf) if metadata_buf else 0, len(body)))
        if metadata:
            fp.write(metadata_buf)
        fp.write(body)
        fp.flush()
        self.logger.debug('Successfully finished chunk write')

    def add_inspector_msg(self, metadata, level, msg):
        """
        Add inspector message to meta data to show up on splunkd. If error is ERROR level then it is shown as error
        message of the command

        @type metadata: dict
        @param metadata: meta data of chunk write protocol if it is not defined then set as empty dict

        @type level - basestring (INFO|DEBUG|ERROR...)
        @param level: message level

        @type msg: basestring
        @param msg: message

        @rtype dict
        @return: return metadata back
        """
        if metadata is None:
            metadata = {}

        inspector = metadata.setdefault('inspector', {})
        msgs = inspector.setdefault('messages', [])
        if level is not None and msg is not None:
            self.logger.debug('inspector message level=%s, message=%s', level, msg)
            msgs.append([level, msg])
        return metadata

    def exit_with_error(self, metadata, msgs):
        """
        Exit command with error message
        @type metadata: dict
        @param metadata: metadata

        @type msgs: list
        @param msgs: message name

        @return: None
        """
        if metadata is None:
            metadata = {}
        metadata['finished'] = True
        for msg in msgs:
            metadata = self.add_inspector_msg(metadata, 'ERROR', msg)
        self.write_chunk(metadata, '')
        self.logger.error('Existing external command because of error=%s', msg)
        sys.exit(1)

    def get_string_buffer(self):
        """
        Instead of dealing with a string, you should use StringIO buffer which increases
        performance by a factor of two. However, cStringIO is even faster.

        Return cStringIO buffer object

        @rtype: cStringIO.StringIO
        @return: object
        """
        return cStringIO.StringIO()

    def validate_search_args(self):
        """
        (Optional) overwrite

        This function needs to be over written if there is any additional check requires for search commands
         parameters. This function is invoke during phase 0 getinfo exchange (__init__ function)

        @rtype: tuple
        @return: Tuple of flag and array of error message
        """
        return True, []

    def pre_processing(self):
        """
        (Optional) overwrite
        This function should be overwritten if you want to perform some operation before it starts reading data from
        splunk after getinfo exchange
        @return:
        """
        pass

    def post_processing(self):
        """
        (optional) overwrite
        This function should be overwritten if you want to perform some operation after it sends all data from
        splunk after getinfo exchange
        @return:
        """
        pass

    def execute(self):
        """
        Main function where we start reading data from splunkd
        @return:
        """
        self.pre_processing()
        self.logger.debug("Start reading chunk data...")
        finished = False
        # Count chunk for no data case
        chunk = 0
        while not finished:
            ret = self.read_chunk(sys.stdin)

            self.logger.debug("Read data=%s", ret)
            # break when no more data
            if not ret:
                break
            metadata, body = ret

            finished = metadata.get('finished', False)

            self.run(metadata, body, chunk)

            chunk += 1

        self.post_processing()
        self.logger.debug("Finished sending data...")

    @abc.abstractmethod
    def run(self, metadata, body, chunk):
        """
        Must override by inherit class
            - Read the passed data and write to splunkd either in chunks or yield based upon
            type of search but you must write back to splunkd

        @type metadata: dict
        @param metadata: meta send by splunkd

        @type body: string delimiter by \n
        @param body: data send by splunkd

        @type chunk: int
        @param chunk: count for which chunk are you processing

        @return: None
        """
        pass
