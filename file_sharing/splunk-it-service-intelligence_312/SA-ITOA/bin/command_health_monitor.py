# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import csv

# Core Splunk Imports
import splunk.rest
import splunk.Intersplunk
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.splunk_search_chunk_protocol import SearchChunkProtocol
from itsi.searches.compute_health_score import HealthMonitor
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi_searches.log", "itsi.command.health_monitor")


def is_debug_flag_is_set(args):
    '''
    Parse search arguments and return if debug flag is set
    :return: flag if debug is set or not
    :rtype: boolean
    '''
    i = 1
    debug = False
    while i < len(args):
        arg = args[i]
        if arg.find('debug=') != -1:
            debug = arg[arg.find('debug=') + 6:]
        else:
            splunk.Intersplunk.parseError(_("Invalid argument '%s'") % arg)
        i += 1
    return debug


class HealthMonitorCommand(SearchChunkProtocol):
    """
    A Wrapper to utilize all the SearchChunkProtocol for the health monitor command
    """
    def __init__(self):
        """
        Initializes the service health score monitor custom search command to be compatible with the
        splunk cearch chunk protocol
        """
        hand_shake_output_data = {
            'type': 'reporting'
        }
        super(HealthMonitorCommand, self).__init__(output_meta_data=hand_shake_output_data, logger=logger)
        self.read_results = []

    def run(self, metadata, body, chunk):
        """
        Read the chunk data, to then be processed for the health score calculation
        @return:
        """
        reader = csv.DictReader(body.splitlines())
        self.read_results.extend([r for r in reader])
        self.write_chunk({'finished': False}, '')

    def post_processing(self):
        """
        Performs the healthscore calculation on the read in results and writes them to
        an output buffer
        @return: None
        """
        settings = {
            'sessionKey': self.session_key
        }
        hm = HealthMonitor(self.read_results, settings, is_debug)
        results = hm.execute()
        rval_chunk = ''
        if results:
            output_buf = self.get_string_buffer()
            fieldnames = hm.get_output_fields()
            writer = csv.DictWriter(output_buf, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
            # overwrite rval_chunk to something more meaningful since we have results.
            rval_chunk = output_buf.getvalue()

        # finally, return a chunk.
        self.write_chunk({'finished': True}, rval_chunk)


if __name__ == "__main__":
    hmc = None
    is_debug = is_debug_flag_is_set(sys.argv)
    try:
        hmc = HealthMonitorCommand()
        hmc.execute()
    except Exception as e:
        logger.exception(e)
        if hmc is not None:
            hmc.exit_with_error({'finished': True}, [e.message])
        else:
            raise
