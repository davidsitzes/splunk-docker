# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import os
import re
import os.path
import sys
import ConfigParser
import datetime
import time
from collections import namedtuple

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path, maybe_makedirs, safe_remove
import splunk.rest

# try:  # noqa: F401
#     from typing import (Iterator, Sequence, Dict, List, Text, Type, Any, Optional,  # noqa: F401
#                         BinaryIO, Union, Callable, Tuple, Generator)  # noqa: F401
#     from logging import Logger  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging
from ITOA.storage.itoa_storage import ITOAStorage
from itsi.csv_import.itoa_csv_spec_transformer import BulkImportSpecTransformer
from itsi.csv_import.itoa_bulk_import_common import spool_dirloc, TransactionFilter
from itsi.csv_import.itoa_bulk_import import BulkImporter
from itsi.csv_import.itoa_bulk_import_preview_utils import build_reader

logger = setup_logging('itsi_config.log', 'itsi.async_csv_loader',
                       log_format=('%(asctime)s %(levelname)s [%(name)s] [%(module)s] [%(funcName)s] ' +
                                   '[%(process)d] [transaction:%(transaction_id)s] %(message)s'))

set_transaction = TransactionFilter()
logger.addFilter(set_transaction)

search_page = '/app/itsi/search?q=search%20index%3D_internal%20source%3D*itsi_config.log*%20sourcetype%3Ditsi_internal_log%20transaction%3A*%20%22Processing%22&display.page.search.mode=smart&dispatch.sample_ratio=1'
search_progressing = '&earliest=rt-1m&latest=rt'

modinput_checkpoint = make_splunkhome_path(['var', 'lib', 'splunk', 'modinputs', 'itsi_async_csv_loader'])

MAX_PASSES = 5  # Number of times to restart before giving up


class SplunkMessenger:
    def __init__(self, transaction_id, session_key):
        # Type: (Text, Text) -> None
        self.transaction_id = transaction_id
        self.session_key = session_key

    def _message(self, msg, severity='info'):
        # type: (Text, Text) -> None
        splunk.rest.simpleRequest('/services/messages', sessionKey=self.session_key, method='POST', postargs={
            'severity': severity,
            'name': 'message',
            'value': msg
        })

    def start(self):
        # Type: () -> None
        self._message('The bulk import process has started. [[{}|View the import process.]]'.
                      format(search_page + search_progressing))

    def stop(self):
        # Type: () -> None
        # Search should run from the time of this event back an hour to accurately track status
        # The +60 is required due to post processing that can occur and lag of indexing events
        latest_time = int(time.time()) + 60
        earliest_time = latest_time - 3600
        search_done = '&earliest=' + str(earliest_time) + '&latest=' + str(latest_time)
        self._message('The bulk import process has completed.  [[{}|View the import report.]]'.
                      format(search_page + search_done))


class RestartError(RuntimeError):
    pass


class Checkpointer:
    """
    An object that tracks the modinput checkpoint file.
    """
    def __init__(self, transaction_id):
        # type: (str) -> None
        """@param {string} transaction_id - the id of the transaction being tracked.

        When the checkpointer is started, at the beginning of a single metafile's
        processing, the work_done is initialized to zero.  Every time we acknowledge a
        batch, the work_done is incremented by one.  On a restart, the work_done is reset
        to zero.

        If work_done is reset to zero and *stays that way* on repeated restarts, we fail
        out with the RestartError exception.  For this to work, the checkpointer must only
        be updated after a batch has been succesfully saved.
        """
        self.work_done = 0
        if not os.path.isdir(modinput_checkpoint):
            logger.warning('Failed to write checkpoint file, checkpoint directory not found.')

        self.checkpoint_filename = os.path.join(modinput_checkpoint, 'checkpoint_' + transaction_id + '.conf')

        if os.path.isfile(self.checkpoint_filename):
            self._read_checkpoint()
            if self.work_done == 0:
                self.work_passes += 1
            if self.work_passes >= MAX_PASSES:
                raise RestartError(_("More than {} attempts to restart process - terminating work.").format(MAX_PASSES))
        else:
            self._init_checkpoint()

        self.work_done = 0
        self._write_checkpoint()

    def _init_checkpoint(self):
        # type: () -> None
        self.work_passes = 0
        self.position = 0

    def _read_checkpoint(self):
        # type: () -> None
        checkpoint = ConfigParser.ConfigParser()
        checkpoint.read(self.checkpoint_filename)
        self.work_done = checkpoint.getint('checkpoint', 'work_done')
        self.work_passes = checkpoint.getint('checkpoint', 'work_passes')
        self.position = checkpoint.getint('checkpoint', 'last_save')

    def _write_checkpoint(self):
        # type: () -> None
        checkpoint = ConfigParser.SafeConfigParser()
        checkpoint.add_section('checkpoint')
        checkpoint.set('checkpoint', 'last_save', str(self.position))
        checkpoint.set('checkpoint', 'work_done', str(self.work_done))
        checkpoint.set('checkpoint', 'work_passes', str(self.work_passes))
        with open(self.checkpoint_filename, 'wb') as cfgfile:
            checkpoint.write(cfgfile)
        self.work_done += 1

    @property
    def count(self):
        # type: () -> int
        return self.position

    def write(self, position):
        self.position = position
        self._write_checkpoint()
        return self.position

    def remove(self):
        # type: () -> None
        """
        Deletes the checkpoint file.
        """
        if os.path.isfile(self.checkpoint_filename):
            os.remove(self.checkpoint_filename)


class ReportingReader:
    """
    A wrapper around CSV reader that logs progress
    """

    def __init__(self, csvfile, transaction_id, messenger, checkpointer):
        # type: (file, Text, SplunkMessenger, Checkpointer) -> None
        """
        Gets the line count of the current operation, the last save point, the dialect, and
        the header; constructs an iterator suitable for consumption by the bulk import API.
        """

        self.messenger = messenger
        self.checkpointer = checkpointer

        # First pass - gather the static, how many lines in the csv file.
        csvfile.seek(0)
        count = 0
        for (count, _) in enumerate(csvfile):
            pass

        self.lines = count
        logger.info('Processing import.  Maxcount: {}'.format(self.lines))

        # Second pass - gather CSV dialect information if possible.
        self.reader = build_reader(csvfile)
        self.header = next(self.reader)

        start = self.checkpointer.count
        count = 0
        for line in xrange(0, start):
            next(self.reader)
            count += 1  # Possible off-by-one error here.  Double check.

        self.count = count
        self.messenger.start()

        # Specify what action to take when the client starts iterating.
        self.step = self.send_header

    def __iter__(self):
        # type: () -> ReportingReader
        return self

    def log(self):
        # type: () -> None
        self.checkpointer.write(self.count)
        logger.info('Processing import. Handled {} of {} rows ({}%)'.format(
            self.count, self.lines, (100 * self.count / self.lines)))

    def log_completion(self, entities_written, services_written, entity_relationships_written,
                       entities_skipped, services_skipped, entity_relationships_skipped):
        # type: (int, int, int, int, int, int) -> None
        """
        Log the total counts of everything done by importer

        @type entities_written: number
        @param entities_written: total count of entities created/updated
        @type services_written: number
        @param services_written: total count of services created/updated
        @type entity_relationships_written: number
        @param entity_relationships_written: total count of entity relationships created/updated
        @type entities_skipped: number
        @param entities_skipped: total count of entities skipped
        @type services_skipped: number
        @param services_skipped: total count of services skipped
        @type entity_relationships_skipped: number
        @param entity_relationships_skipped: total count of entity relationships skipped
        """
        msg = _('Processing import. Handled {} of {} rows ({}%). ' \
              'Entities written {}. Services written {}. Entity Relationships written {}. ' \
              'Entities skipped {}. Services skipped {}. Entity Relationships skipped {}.')

        logger.info(msg.format(self.count, self.lines, (100 * self.count / self.lines),
                               entities_written, services_written, entity_relationships_written,
                               entities_skipped, services_skipped, entity_relationships_skipped))

        msg = _('Processing completed. {} Entities created/updated. {} Services created/updated. ' \
              '{} Entity Relationships created/updated.')

        logger.info(msg.format(entities_written, services_written, entity_relationships_written))

    def send_header(self):
        # type: () -> Tuple[List[Text], Callable]
        # Returns the data to return to the client, and the next
        # operation to take.
        return (self.header, self.send_row)

    def send_row(self):
        # type: () -> Tuple[List[Text], Callable]
        # Returns the data to return to the client, and the next operation to take,
        # raising the appropriate StopIteration exception when done and cleaning up after
        # itself.
        try:
            line = next(self.reader)
        except StopIteration as si:  # noqa: F841
            self.messenger.stop()
            self.checkpointer.remove()
            raise StopIteration

        self.count += 1
        return (line, self.send_row)

    def next(self):
        # type: () -> List[Text]
        # A bit wonky, but specifies the order of activity (header, then body) clearly
        # without having to use a sentinel, which is more error-prone.
        (line, self.step) = self.step()
        return line


def get_meta_file_list(spool_dir_path):
    # type: (Text) -> List[Text]
    """
    Create itsi folder if it doesn't exist under $SPLUNK_HOME/var/spool directory
    Check if meta_<GUID>.conf file exists inside $SPLUNK_HOME/var/spool/itsi directory

    @type spool_dir_path: string
    @param spool_dir_path: path of Splunk spool directory

    @rtype: list
    @return: List of meta .conf file names
    """
    logger.info('Getting metadata files from %s' % spool_dir_path)
    if maybe_makedirs(spool_dir_path):
        logger.debug('itsi spool directory found')
        meta_file_list = [fname for fname in os.listdir(spool_dir_path)
                          if fname.endswith('.conf') and fname.startswith('meta') and
                          os.path.isfile(os.path.join(spool_dir_path, fname))]
        logger.info('meta files found %s' % meta_file_list)
        # Sort meta files in list by time of most recent content modification
        meta_file_list.sort(key=lambda fname: os.stat(os.path.join(spool_dir_path, fname)).st_mtime, reverse=True)
        return meta_file_list
    else:
        logger.error('Unable to make directory: %s' % spool_dir_path)
        return []


def parse_meta_file(meta_file_path):
    # type: (str) -> Dict[Text, Dict[Text, Text]]
    """
    Parse meta .conf file

    @type meta_file_path: string
    @param meta_file_path: path of meta .conf file

    @rtype: dict
    @return: dict of contents in meta .conf file
    Sample:
    {section1: {field1:value1, field2:value2}, section2: {field3:value3}...}
    """
    meta_file_parser = ConfigParser.ConfigParser()
    if len(meta_file_parser.read(meta_file_path)) == 0:
        message = _('Failed to read meta file: %s') % meta_file_parser
        raise Exception(message)
    if len(meta_file_parser.sections()) == 0:
        message = _('No stanza exists in meta file: %s') % meta_file_path
        raise Exception(message)
    section = meta_file_parser.sections()[0]
    return {section: dict(meta_file_parser.items(section))}


def clean_up_file(file_path):
    # type: (Text) -> None
    """
    Remove file by its full path

    @type: string
    @param file_path: full path of the file to be deleted

    @type: string
    @param current_transaction_id: transaction_id in current meta file
    """

    logger.info('Start deleting file: %s' % (file_path))
    safe_remove(file_path)
    if os.path.isfile(file_path):
        logger.error('Failed to delete file: %s' % (file_path))
        return

    logger.info('File: %s has been successfully deleted' % (file_path))


def import_csv_to_kv_store(session_key, csv_file_path, specification, checkpointer, current_transaction_id):
    # type: (Text, Text, Dict[Text, Any], Checkpointer, Text) -> None
    """
    Import csv data to kv store

    @type: string
    @param csv_file_path: csv file location

    @type: dictionary
    @param specification: import spec read from meta conf file

    @type: string
    @param current_transaction_id: transaction_id in current meta file
    """
    logger.info('Start importing csv data into kv store')
    messenger = SplunkMessenger(current_transaction_id, session_key)
    with open(csv_file_path, 'rbU') as csv_file:
        csv_reader = ReportingReader(csv_file, current_transaction_id, messenger, checkpointer)
        bulk_importer = BulkImporter(
            specification=specification,
            session_key=session_key,
            current_user=specification['uploaded_by'],
            owner='nobody'
        )

        try:
            import_results = bulk_importer.bulk_import(csv_reader, current_transaction_id)
            entities_written = import_results.get('entities', 0)
            services_written = import_results.get('services', 0)
            entity_relationships_written = import_results.get('entity_relationships', 0)
            entities_skipped = import_results.get('entities_skip_count', 0)
            services_skipped = import_results.get('services_skip_count', 0)
            entity_relationships_skipped = import_results.get('entity_relationships_skip_count', 0)
            csv_reader.log_completion(entities_written, services_written, entity_relationships_written,
                                      entities_skipped, services_skipped, entity_relationships_skipped)
            logger.info('Created/updated %s services from csv.',
                        services_written)
            logger.info('Created/updated %s entities from csv.',
                        entities_written)
            logger.info('Created/updated %s entity relationships from csv.',
                        entity_relationships_written)
            logger.info('Skipped %s services from csv',
                        services_skipped)
            logger.info('Skipped %s entities from csv',
                        entities_skipped)
            logger.info('Skipped %s entity relationships from csv',
                        entity_relationships_skipped)
            logger.info('Finished importing csv data into kv store')
        except Exception as err:
            logger.exception('Failed loading csv into kvstore.')
            raise err


def cleanup_import_file_dir(spool_dir_path):
    # type: (Text) -> None
    meta_file_match = re.compile(r'meta_(\w+)\.conf$')
    csv_file_match = re.compile(r'csv_import_(\w+)\.csv$')
    now = datetime.datetime.now()
    yesterday = now - datetime.timedelta(hours=24)

    file_list = [f for f in os.listdir(spool_dir_path)
                 if os.path.isfile(os.path.join(spool_dir_path, f))]

    def mmatch(f):
        return [meta_file_match.match(i) for i in f]

    meta_tags = [f.group(1) for f in mmatch(file_list) if f]

    CMatch = namedtuple('CMatch', ['path', 'match', 'date'])

    def cmatch(f):
        return [CMatch(os.path.join(spool_dir_path, i),
                       csv_file_match.match(i),
                       datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(spool_dir_path, i))))
                for i in f]

    conf_files = [f.path for f in cmatch(file_list)
                  if f.match and f.match.group(1) not in meta_tags and f.date < yesterday]

    for f in conf_files:
        logger.info('Deleted stale csv import file %s' % f)
        os.remove(f)


def process_bulk_import_spool(session_key, input_config):
    # type: (Text, Dict[Text, Any]) -> None
    spool_dir_path = spool_dirloc()
    meta_file_list = get_meta_file_list(spool_dir_path)

    set_transaction("pre")
    logger.info("Bulk Import Process Spool started")

    for meta_file in meta_file_list:
        meta_file_path = os.path.join(spool_dir_path, meta_file)

        try:
            import_config = parse_meta_file(meta_file_path).values()[0]
            bulk_import_spec_transformer = BulkImportSpecTransformer(import_config)
            specification = bulk_import_spec_transformer.transformed_spec
            current_transaction_id = specification['transaction_id']
            set_transaction(current_transaction_id)
            checkpointer = Checkpointer(current_transaction_id)
            logger.info('Start itsi_async_csv_loader modular input with meta file: %s.'
                        % (meta_file))

        except RestartError:
            logger.error("Too many retries.  Import marked as failed: {}".format(meta_file_path))
            failed_file_name = meta_file.replace('.conf', '.failed')
            failed_file_path = os.path.join(spool_dir_path, failed_file_name)
            os.rename(meta_file_path, failed_file_path)
            checkpointer.remove()
            return

        except Exception:
            logger.exception('Failed to process meta conf file: %s' % meta_file_path)
            # TODO TAG-12174: Post error message to Splunkweb
            continue

        # Construct csv file name based on current naming convention
        csv_file_name = 'csv_import_' + import_config.get('transaction_id') + '.csv'
        csv_file_path = os.path.join(spool_dir_path, csv_file_name)

        logger.info('Start looking for target csv file.')
        if not os.path.isfile(csv_file_path):
            logger.error('csv file: %s not found.' % (csv_file_path))
            # TODO TAG-12174: Post error message to Splunkweb
            continue

        logger.info('Target csv file found. Start importing csv data from: %s'
                    % (csv_file_path))

        # Before attempting any imports, first try to wait for KV store to get initialized
        kvstore = ITOAStorage()
        kvstore.wait_for_storage_init(session_key)

        try:
            import_csv_to_kv_store(session_key, csv_file_path, specification, checkpointer, current_transaction_id)
        except Exception:
            logger.exception('Failed loading csv file.')
            # TODO TAG-12174: Post error message to Splunkweb
            continue

        logger.info('Finished importing csv data from: %s' % (csv_file_path))

        # Clean up both meta file and csv file after data import completes
        clean_up_file(meta_file_path)
        clean_up_file(csv_file_path)

    cleanup_import_file_dir(spool_dir_path)
