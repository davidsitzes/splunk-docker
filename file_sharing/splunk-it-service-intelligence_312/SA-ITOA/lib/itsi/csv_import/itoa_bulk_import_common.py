# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
from ITOA.itoa_exceptions import ItoaError
from collections import namedtuple, MutableMapping
from itertools import islice
from exceptions import KeyError
import logging
import splunk.entity
import os.path

from splunk.clilib.bundle_paths import make_splunkhome_path

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class TransactionFilter(logging.Filter):
    """
    The TransactionFilter adds a persistent new value to the logging record that we use to track the
    transaction_id in a consistent manner.
    """
    def __init__(self):
        # type: () -> None
        super(TransactionFilter, self).__init__()
        self.transaction = 'NOT_SET'

    def __call__(self, transaction):
        # type: (str) -> None
        self.transaction = transaction

    def filter(self, record):
        # type: (Any) -> bool
        record.transaction_id = self.transaction
        return True

logger = setup_logging('itsi_config.log', 'itsi.csv.loader',
                       log_format=('%(asctime)s %(levelname)s [%(name)s] [%(module)s] [%(funcName)s] ' +
                                   '[%(process)d] [transaction:%(transaction_id)s] %(message)s'))

set_transaction = TransactionFilter()
logger.addFilter(set_transaction)


class CSVLoaderBadReq(ItoaError):
    def __init__(self, message, logger=logger, log_prefix='[ITOA Import Error]', status_code=400):
        # type: (str, logging.Logger, str, int) -> None
        super(CSVLoaderBadReq, self).__init__(message, logger, log_prefix, status_code)


class CSVLoaderError(ItoaError):
    def __init__(self, message, logger=logger, log_prefix='[ITOA Import Error]', status_code=500):
        # type: (str, logging.Logger, str, int) -> None
        super(CSVLoaderError, self).__init__(message, logger, log_prefix, status_code)


SERVICE = 'service'
ENTITY = 'entity'
TEMPLATE = 'template'
ENTITY_RELATIONSHIP = 'entity_relationship'
SERVICE_TEMPLATE = 'service_template'
SERVICE_KEY = SERVICE
ENTITY_KEY = ENTITY
ENTITY_RELATIONSHIP_KEY = ENTITY_RELATIONSHIP
SERVICE_IMPORT = 1
ENTITY_IMPORT = 2
SERVICE_ENTITY_IMPORT = SERVICE_IMPORT & ENTITY_IMPORT
INVALID_IMPORT = '"invalid import" '
UPSERT_UPDATE_TYPE = 'upsert'
REPLACE_UPDATE_TYPE = 'replace'
APPEND_UPDATE_TYPE = 'append'
DEFAULT_UPDATE_TYPE = UPSERT_UPDATE_TYPE
SUPPORTED_UPDATE_TYPES = [UPSERT_UPDATE_TYPE, REPLACE_UPDATE_TYPE, APPEND_UPDATE_TYPE]

ENTITY_RELATIONSHIP_TRIPLE_FIELDS = ['subject_identifier', 'object_identifier', 'predicate']

# temporary keys that we might add to objects being imported from CSV data
OBJECT_UPDATED = 'updated'
OBJECT_RELATIONSHIP = 'relationship'
OBJECT_TEMPORARY_KEYS = [OBJECT_UPDATED, OBJECT_RELATIONSHIP]

TypeSpec = namedtuple('TypeSpec', ['name', 'type'])


def spool_dirloc():
    return make_splunkhome_path(['var', 'itsi', 'import'])


def spool_fileloc(filename):
    return os.path.join(spool_dirloc(), filename)


def stripall(l):
    # type: (List[Text]) -> List[Text]

    """
    Utility function to strip all contents of a list, if they're strings

    @param l: A list of strings
    @type: list

    @return: a list of strings
    @rtype: list
    """
    return [isinstance(s, basestring) and s.strip() or s for s in l]


def filtblnk(l):
    # type: (List[Text]) -> List[Text]
    """
    Utility function to filter all blank entries out of a list of strings

    @param l: A list of strings
    @type: list

    @return: a list of strings
    @rtype: list
    """
    return [a for a in l if len(a)]


class _ItsiObjectCache(MutableMapping):
    def __init__(self, *args, **kwargs):
        self._cache = dict()

    def __getitem__(self, key):
        # type: (str) -> Any
        return self._cache[key]

    def __delitem__(self, key):
        # type: (str) -> None
        del self._cache[key]

    def __iter__(self):
        # type: () -> Iterator
        return iter(self._cache)

    def __len__(self):
        # type: () -> int
        return len(self._cache)

    def __str__(self):
        # type: () -> str
        return str(self._cache)

    def __setitem__(self, key, value):
        # type: (str, Any) -> None
        self._cache[key] = value
        return None


def new_relationship_record(depends_on=None, depends_on_me=None):
    # type: (Optional[List], Optional[List]) -> Dict[Text, List]
    """
    Utility function - returns a component of the dependency graph between
    services.

    @param depends_on: the titles of services a services depends upon
    @type: list of strings

    @params depends_on_me: the titles of services depending on a service
    @type: list of strings

    @return: a keyed dictionary of the above
    @rtype: dict
    """
    return {
        u'depends_on': (depends_on and depends_on or []),
        u'depends_on_me': depends_on_me and depends_on_me or []
    }


def window(seq, n=2):
    # type: (List[Any], int) -> Iterator
    """
    Given a sequence (a finite, concrete iterable), return a sliding
    window of width 'n' over the data from the iterable, i.e.
    window(['a', 'b', 'c', 'd'], 2) -> [('a', 'b'), ('b', 'c'), ('c', 'd')]

    @param seq: the sequence to window
    @type: iterator

    @param n: the width of the window
    @type: integer

    @return: an iterator of tuples representing the current window
    @rtype: iterator
    """
    it = iter(seq)
    result = tuple(islice(it, n))
    if len(result) == n:
        yield result
    for elem in it:
        result = result[1:] + (elem,)
        yield result


class ImportConfig:

    def __init__(self, session_key, owner='nobody', namespace='SA-ITOA'):
        # type: (str, str, str) -> None
        conf = splunk.entity.getEntity('/configs/conf-itsi_settings', 'import', owner=owner, namespace=namespace, sessionKey=session_key)
        self.cache = self.clean_properties(conf.properties)

    @staticmethod
    def clean_properties(properties):
        # type: (Dict[Text, Any]) -> Dict[Text, Any]
        return dict([(name, value) for name, value in properties.items() if name[0:4] != 'eai:' and name[0] != '_'])

    @staticmethod
    def typeConv(val):
        # type: (str) -> Union[str, int]
        if val.strip().isdigit():
            return int(val)
        return val

    def get(self, key, default=None):
        # type: (str, Union[str, int, None]) -> Union[str, int, None]
        if key in self.cache:
            return self.typeConv(self.cache[key])
        return default

    def __getitem__(self, key):
        # type: (str) -> Union[str, int]
        if key in self.cache:
            return self.typeConv(self.cache[key])
        raise KeyError(_('Key %s not found') % key)
