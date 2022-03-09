# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Ping is an example of an action that can be taken programmatically on one or
more Notable Events in ITSI.

It is implemented as a Splunk Modular Alert Action.

Chunk of the logic lies in the method `execute()` where we work on one event
at a time.

Using this as an example, you could implement other actions like telnet,
work on external ticket and then update your ITSI Event worklog, update status,
severity, owner etc...
"""

import sys
import json
import platform
import subprocess

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
from itsi.event_management.sdk.eventing import Event
from itsi.event_management.sdk.custom_event_action_base import CustomEventActionBase

class Ping(CustomEventActionBase):
    """
    Ping is an example of an action that can be taken, programmatically on an ITSI
    Event. It is implemented as a Splunk Modular Alert Action.

    Usage::
        >>> if __name__ == "__main__":
        >>>     if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        >>>         input_params = sys.stdin.read()
        >>>         ping = Ping(input_params)
        >>>         ping.execute()
    """

    DEFAULT_HOST_KEY_IN_CONFIG = 'host_to_ping'
    DEFAULT_COUNT_VALUE = '10' #packets
    DEFAULT_TIMEOUT_VALUE = '11' #seconds

    def __init__(self, settings, count_value=None, timeout_value=None):
        """
        Initialize the object
        @type settings: dict/basestring
        @param settings: incoming settings for this alert action that splunkd
            passes via stdin.

        @type count_value: basestring
        @param count_value: a string indicating the number of ICMP packets to
            send to destination.

        @type timeout_value: basestring
        @param timeout_value: (seconds) a string indicating the number of
            seconds to wait, prior to giving up in case of an ICMP timeout.

        @returns Nothing
        """
        self.logger = setup_logging("itsi_event_management.log", "itsi.event_action.ping")

        super(Ping, self).__init__(settings, self.logger)

        self.executable= 'ping'
        self.count_flag = None
        self.count_value = None
        self.timeout_flag = None
        self.timeout_value = None
        self.platform_type = None

        self._set_flags(count_value, timeout_value)

    def _set_flags(self, count_value, timeout_value):
        """
        Set some flags for count, timeout etc...
        We will consider the platform type for some of them.

        @type count_value: basestring
        @param count_value: a string indicating the number of ICMP packets to
            send to destination.

        @type timeout_value: basestring
        @param timeout_value: (seconds) a string indicating the number of
            seconds to wait, prior to giving up in case of an ICMP timeout.

        @returns Nothing
        """
        try:
            self.count_value = int(count_value)
        except (ValueError, TypeError), e:
            self.count_value = self.DEFAULT_COUNT_VALUE

        try:
            self.timeout_value = int(timeout_value)
        except (ValueError, TypeError), e:
            self.timeout_value = self.DEFAULT_TIMEOUT_VALUE

        # get platform specific flags
        if platform.system() == 'Windows':
            self.platform_type = 'windows'
            self.count_flag = '-n'
            self.timeout_flag = '-w'
        else:
            self.platform_type = '*nix'
            self.count_flag = '-c'
            self.timeout_flag = '-W'

        self.logger.debug('Environment/Platform=`%s`. Flags=`%s %s %s %s`',
            self.platform_type, self.count_flag, self.count_value,
            self.timeout_flag, self.timeout_value)

    def _get_exec_arg(self, host):
        """
        Return a list compatible with Popen which can be exec'ed

        @type host: basestring
        @param host: target host.

        @rtype: list of str
        @returns: a param consumed by Popen
        """

        self.logger.debug('Exec string=`%s %s %s %s %s %s`', self.executable,
            self.count_flag, self.count_value, self.timeout_flag,
            self.timeout_value, host)

        return [self.executable, self.count_flag, str(self.count_value), self.timeout_flag,
                str(self.timeout_value), host]

    def ping(self, host):
        """
        given a host, ping it.

        @type host: basestring
        @param host: host to ping.

        @rtype: tuple (basestring, basestring)
        @return: stdout, stderr
        """
        if any([not host,
            not isinstance(host, basestring),
            isinstance(host, basestring) and not host.strip()
            ]):
            raise Exception(_('Invalid host to ping. Received=`%s`. Type=`%s`') % (host, type(host).__name__))

        p = subprocess.Popen(
            self._get_exec_arg(host),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
            )

        out, err = p.communicate()

        self.logger.debug('Ping complete. host=`%s` stdout=`%s` stderr=`%s`',
            host, out, err)
        return out, err

    def get_host_to_ping(self, data, host_key=None):
        """
        Return the string indicating the host to ping.
        Work on the config that came with the alert action execution
        if event specific config is provided.

        @rtype: basestring
        @return: the host to ping
        """
        host_key = self.DEFAULT_HOST_KEY_IN_CONFIG if not host_key else host_key
        config = self.get_config()
        host_info = config.get(host_key, '')

        host = None

        if host_info.startswith('%') and host_info.endswith('%'):
            # if host_info starts and ends with `%` it refers to
            # another key in the event data, whose value we care about.
            # We will retrieve its value and set it as the host.
            # {
            #    'host_to_ping': '%orig_host%', # references another field below
            #    ...
            #    'orig_host': 'foobar.orig',    # we care about this field
            #    ...
            # }
            host_info = host_info.strip('%')
            host = data.get(host_info)
        else:
            # if host_info does not start/end with `%s`, its value can be taken as
            # the value of the host to ping.
            host = host_info

        if host is None or (isinstance(host,basestring) and not host.strip()):
            message = _('No host to ping.')
            self.logger.error(message)
            raise ValueError(message)

        # if host contains any port #s, strip it away
        # locahost:8000 or git.splunk.com:80
        host = host.split(':')[0]
        self.logger.debug('Host to ping=`%s`', host)
        return host

    def ping_and_update_notable_event(self, host, event_id):
        """
        Do the act of pinging the host and then go on to update the comment for
        the notable event.
        @type host: basestring
        @param host: host to ping

        @type event_id: basestring
        @param event_id: event id to ping

        @rtype: basestring | None
        @return: error, if error occurred
        """
        out, err = self.ping(host)
        error_to_return = None
        if err.strip():
            self.logger.error('Errors while running ping=`%s`', err)
            comment = 'Errors while running ping: {}'.format(err)
            error_to_return = comment
        else:
            self.logger.debug('Ping output=`%s`', out)
            comment = 'No Errors while running ping.'

        self.logger.info('Updating tags/comments for event_id: %s', event_id)
        event = Event(self.get_session_key(), self.logger)
        event.create_comment(event_id, comment)
        event.create_comment(event_id, out)
        event.create_tag(event_id, 'ping')
        return error_to_return

    def execute(self):
        """
        Execute en bulk. For each event in the results file:
        1. extract the host to ping
        2. ping host
        3. add comment

        Apart from the above, this method does nothing else.
        The rest is left to your implementation and imagination.
        """
        self.logger.debug('Received settings from splunkd=`%s`',json.dumps(self.settings))

        count = 0
        try:
            ping_failed = False
            for data in self.get_event():
                if isinstance(data, Exception):
                    # Generator can yield an Exception
                    # We cannot print the call stack here reliably, because
                    # of how this code handles it, we may have generated an exception elsewhere
                    # Better to present this as an error
                    self.logger.error(data)
                    raise data

                if not data.get('event_id'):
                    self.logger.warning('Event does not have an `event_id`. No-op.')
                    continue

                event_id = data.get('event_id')
                host = self.get_host_to_ping(data)
                ping_error = self.ping_and_update_notable_event(host, event_id)
                if ping_error is not None:
                    ping_failed = True
                count += 1
            if ping_failed is True:
                raise Exception(_('Failed to execute one or more ping actions.'))
        except ValueError, e:
            pass # best case, try every event.
        except Exception, e:
            self.logger.error('Failed to execute ping.')
            self.logger.exception(e)
            sys.exit(1)

        self.logger.info('Executed action. Processed events count=`%s`.', count)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        input_params = sys.stdin.read()
        ping = Ping(input_params)
        ping.execute()
