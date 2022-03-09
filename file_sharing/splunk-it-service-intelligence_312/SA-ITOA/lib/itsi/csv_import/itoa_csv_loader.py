# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import csv
import base64
import StringIO
import uuid

from ITOA.setup_logging import setup_logging
from itoa_bulk_import import BulkImporter
from itoa_bulk_import_common import DEFAULT_UPDATE_TYPE

logger = setup_logging('itsi_config.log', 'itsi.csv.loader')
LOG_CHANGE_TRACKING = '[change_tracking] '

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


def _get_csv_reader(csv_data, csv_delimiter=None, csv_quotechar=None):
    # type: (str, Optional[str], Optional[str]) -> csv._Reader
    """
    wrapper for returning an instance of csv reader
    @param cls: class reference
    @param csv_data: actual csv data
    @param csv_delimiter: delimiter for csv data
    @param csv_quotechar: quotechar for csv data
    @return csv reader object
    """
    data = '\n'.join(base64.b64decode(csv_data).splitlines())
    f = StringIO.StringIO(data)
    delimiter = base64.b64decode(csv_delimiter) if csv_delimiter is not None else ','
    quoteChar = base64.b64decode(csv_quotechar) if csv_quotechar is not None else '"'
    return csv.reader(f, delimiter=delimiter, quotechar=quoteChar)


class CSVLoader(object):
    """
    A wrapper that makes the bulk_import tool according to the CVSLoader protocol.
    """

    @classmethod
    def validate_update_type(cls, update_type):
        # type: (Any, str) -> bool
        # Superseded by the BulkImport parser pass.  Provided so client code won't die.
        return True

    @classmethod
    def default_update_type(cls):
        # type: (Any) -> str
        LOG_PREFIX = '[default_update_type] '
        logger.debug('%s Returning default "update type" - %s', LOG_PREFIX, DEFAULT_UPDATE_TYPE)
        return DEFAULT_UPDATE_TYPE

    def __init__(self, owner, import_spec, session_key, current_user, preview_only_mode=False, csv_reader=None):
        # type: (str, dict, str, str, bool, Optional[csv._Reader]) -> None
        """
        @param owner: owner; for permissions
        @type: string

        @param import_spec: a raw import specification
        @type: dict

        @param session_key: splunkd session key
        @type: string

        @param current_user: current user
        @type: string

        @param preview_only_mode: Boolean indicating if its preview only, or if caller wants to commit
        @param csv_reader: optional csv reader object. we'll make our own from import_spec
        """

        self.bulk_importer = BulkImporter(import_spec, session_key, current_user, owner)
        self.preview_only_mode = preview_only_mode
        if csv_reader:
            self.csv_data = csv_reader
        else:
            self.csv_data = _get_csv_reader(
                import_spec.get('csvData', None),
                import_spec.get('delimiter'),
                import_spec.get('quotechar'))

    def load_csv(self):
        # type: () -> Dict[Text, Any]
        """
        Handle and save csv data. Handles both entities and services

        @return: keys of newly-added objects
        @type: list(string)
        """

        # Kinda cool: your normal csv_reader object returns a generator that fetchs line
        # after line, raising the PyVM-managed StopIteration at the end.  Done *this* way,
        # we use a *lot* less memory.
        tid = str(uuid.uuid1())[0:8]
        return self.bulk_importer.bulk_import(self.csv_data, tid)

    def preview_merge(self, entities):
        # type: (Sequence[dict]) -> Iterator[Dict[Text, Any]]
        def pairtodict(seq):
            # type: (Sequence[EntityPair]) -> Iterator[Dict[Text, Any]]
            for i in seq:
                yield {'existing': i.existing, 'preview': i.preview}
        return pairtodict(self.bulk_importer.get_entity_preview(self.csv_data))
