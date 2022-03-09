import sys
import csv

# Core Splunk Imports
import splunk.rest
import splunk.Intersplunk
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.splunk_search_chunk_protocol import SearchChunkProtocol
from itsi.event_management.compute_eventfield_type_summary import EventFieldAnalyzer
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi_searches.log", "itsi.command.eventfield_analyzer")


class EventFieldAnalyzerCommand(SearchChunkProtocol):
    """
    A Wrapper to utilize all the SearchChunkProtocol for the event field analyzer command
    """
    def __init__(self):
        """
        Initializes the event field analyzer custom search command to be compatible with the
        splunk search chunk protocol
        """
        hand_shake_output_data = {
            'type': 'reporting'
        }
        super(EventFieldAnalyzerCommand, self).__init__(output_meta_data=hand_shake_output_data, logger=logger)
        self.is_debug = False if 'is_debug' not in self.args else self.args['is_debug']

    def run(self, metadata, body, chunk):
        """
        Read the chunk data, to then be processed for field type segregation logic
        @return:
        """
        read_chunk = csv.DictReader(body.splitlines())
        self.process_chunk(read_chunk)

    def post_processing(self):
        self.write_chunk({'finished': True}, '')

    def process_chunk(self, chunk):
        """
        Performs the task of segregating the event fields into descriptive and categorical
        on the read in results and writes them to an output buffer
        @return: None
        """
        settings = {
            'sessionKey': self.session_key,
            'args': self.args
        }
        field_analyzer = None
        results = []
        try:
            field_analyzer = EventFieldAnalyzer(chunk, settings, self.is_debug)
            results = field_analyzer.execute()
        except Exception as e:
            logger.exception(e)
            self.exit_with_error({'finished': True}, [e.message])

        rval_chunk = ''
        if results:
            output_buf = self.get_string_buffer()
            fieldnames = field_analyzer.get_output_fields()
            writer = csv.DictWriter(output_buf, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
            # overwrite rval_chunk to something more meaningful since we have results.
            rval_chunk = output_buf.getvalue()

        # finally, return a chunk.
        self.write_chunk({'finished': False}, rval_chunk)


if __name__ == "__main__":
    field_analyser_cmd = None
    try:
        field_analyser_cmd = EventFieldAnalyzerCommand()
        field_analyser_cmd.execute()
    except Exception as e:
        logger.exception(e)
        if field_analyser_cmd is not None:
            field_analyser_cmd.exit_with_error({'finished': True}, [e.message])
        else:
            raise
