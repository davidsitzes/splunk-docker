# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Contains operational code for building preview views of services and entities.
Moved into a module of its own to facilitate testing.
"""

import csv
from itoa_bulk_import import BulkImporter, unicodify_source
from itoa_bulk_import_common import ImportConfig

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple, Generator  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401

DEFAULT_PREVIEW_SAMPLE_LIMIT = 100


class ItoaObjectPreviewer(object):
    action = ''

    def __init__(self, spec, session_key, current_user, owner):
        # type: (Dict[Text, Any], str, str, Text) -> None
        """
        @param spec: The JSON form of a Bulk Import Specification
        @param session_key: A valid Splunk session key
        @param current_user: the current user logged in
        @param owner: The owner of the objects to be retrieved.
        """
        self.config = ImportConfig(session_key, owner)
        self.bulk_importer = BulkImporter(spec, session_key, current_user, owner)

    def __call__(self, source, transaction_id):
        raise NotImplementedError


class ServicePreviewer(ItoaObjectPreviewer):
    action = 'service_preview'

    def __call__(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, Any]
        """
        Returns the preview of sources to be saved to KVStore.
        @param source: An iterator that provides rows of data from CSV, Search, or other resource
        """
        return self.bulk_importer.get_service_preview(source, transaction_id)


class EntityPreviewer(ItoaObjectPreviewer):
    """
    Extracts only the entity preview data from a bulk import specification in the spool.
    Number of entities is limited to the hard-coded preview limit specified in this source
    file.
    """
    action = 'entity_preview'

    def __call__(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, Any]
        """
        Returns the length-limited preview of entities to be saved to KVStore.
        @param source: An iterator that provides rows of data from CSV, Search, or other resource
        """

        def length_limited_source(s):
            # type: (Iterator[Sequence[str]]) -> Generator[Sequence[str], None, None]
            # A simple generator that limits the number of rows delivered to the
            # BulkImporter to the length specified above.

            limit = self.config.get('preview_sample_limit', DEFAULT_PREVIEW_SAMPLE_LIMIT)
            count = 0
            while count < limit:
                yield next(s)
                count += 1

        return self.bulk_importer.get_entity_preview(length_limited_source(source), transaction_id)


class TemplatePreviewer(ItoaObjectPreviewer):
    action = 'template_preview'

    def __call__(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, Any]
        """
        Returns the preview of service templates that will be linked to the services when created.

        @param source: An iterator that provides rows of data from CSV, Search, or other resource
        @type: iterator
        """
        return self.bulk_importer.get_template_preview(source, transaction_id)


class RowPreviewer(object):
    action = 'row_preview'

    def __init__(self, spec, session_key, current_user, owner):
        # type: (Dict[Text, Any], str, str, Text) -> None
        """
        @param spec: The JSON form of a Bulk Import Specification
        @param session_key: A valid Splunk session key
        @param current_user: the current user logged in
        @param owner: The owner of the objects to be retrieved.
        """
        self.spec = spec
        self.session_key = session_key
        self.current_user = current_user
        self.owner = owner

    def __call__(self, source, transaction_id):
        # type: (Iterator[Sequence[str]], Text) -> Dict[Text, Text]
        """
        Returns all row data that matches the spec for the given source.

        @param source: An iterator that provides rows of data from CSV, Search, or other resource
        @param transaction_id: A unique key for this transaction
        """
        unicoded_source = unicodify_source(source)
        column_names = self._get_column_names(unicoded_source)
        column_pos = self._get_column_positions(column_names)

        for key in self.spec.keys():
            assert key in column_pos, '{} is not a valid column for transaction {}'.format(key, transaction_id)

        matched_rows = []
        for row in unicoded_source:
            if self._row_matches_spec(row, self.spec, column_pos):
                row_as_dict = self._row_to_dict(row, column_pos)
                matched_rows.append(row_as_dict)

        return matched_rows

    def _get_column_names(self, source):
        # type: Iterator[Sequence[str]] -> Sequence[str]
        """
        Returns the column names for the given source.

        @param source: An iterator that provides rows of data from CSV, Search, or other resource
        """
        try:
            columns = next(source)
        except StopIteration:
            return {}
        return columns

    def _get_column_positions(self, columns):
        # type: Sequence[str] -> Dict
        """
        Returns the mapping of column name to its index in a row of data.

        @param columns: A list of column names
        """
        positions = {}
        for index, column in enumerate(columns):
            positions[column.strip()] = index
        return positions

    def _row_matches_spec(self, row, spec, column_pos):
        # type: (Sequence[str], Dict, Dict) -> bool
        """
        Returns True if the given row satifies the criteria defined in spec.

        @param row: A row of data
        @param spec: A spec describing the row to search and match for
        @param column_pos: The mapping of column name to its positional index
        """
        for key, value in spec.iteritems():
            pos = column_pos[key]
            if value != row[pos]:
                return False
        return True

    def _row_to_dict(self, row, column_pos):
        # type: (Sequence[str], Dict) -> Dict
        """
        Converts the given row to a dict, with the column names as keys

        @param row: A row of data
        @column_pos: The mapping of column name to its positional index
        """
        result = {}
        for key, pos in column_pos.iteritems():
            assert pos < len(row), 'Expected at least {} values for row: {}'.format(pos, row)
            result[key] = row[pos]
        return result


def build_reader(csvfile):
    try:
        dialect = csv.Sniffer().sniff(csvfile.read(8192), delimiters=[',', '|', ';', '^', '	'])
    except:
        dialect = csv.excel()
    # Under what circumstances would we ever want this to be different? It's the Excel default.
    if dialect.quotechar in ['"', '\'']:
        dialect.doublequote = True
    csvfile.seek(0)
    return csv.reader(csvfile, dialect)
