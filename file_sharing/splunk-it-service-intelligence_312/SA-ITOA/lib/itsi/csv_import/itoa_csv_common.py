from ITOA.setup_logging import setup_logging
from itsi.itsi_const import ITOAObjConst
from collections import namedtuple, MutableMapping
from itertools import islice
from functools import partial


class CSVLoaderBadReq(Exception):
    def __init__(self, msg):
        '''
        @type msg: basestring
        @param msg: basestring indicating error message
        '''
        self.msg = msg


class CSVLoaderError(Exception):
    def __init__(self, msg):
        self.msg = msg

logger = setup_logging('itsi_config.log', 'itsi.csv.loader')


SERVICE = 'service'
ENTITY = 'entity'
SERVICE_KEY = SERVICE
ENTITY_KEY = ENTITY
SERVICE_ONLY_IMPORT = 1
ENTITY_ONLY_IMPORT = 2
SERVICE_ENTITY_IMPORT = SERVICE_ONLY_IMPORT & ENTITY_ONLY_IMPORT
INVALID_IMPORT = '"invalid import" '
UPSERT_UPDATE_TYPE = 'upsert'
REPLACE_UPDATE_TYPE = 'replace'
APPEND_UPDATE_TYPE = 'append'
DEFAULT_UPDATE_TYPE = UPSERT_UPDATE_TYPE
SUPPORTED_UPDATE_TYPES = [UPSERT_UPDATE_TYPE, REPLACE_UPDATE_TYPE, APPEND_UPDATE_TYPE]

# temporary keys that we might add to objects being imported from CSV data
OBJECT_UPDATED = 'updated'
OBJECT_RELATIONSHIP = 'relationship'
OBJECT_TEMPORARY_KEYS = [OBJECT_UPDATED, OBJECT_RELATIONSHIP]

TypeSpec = namedtuple('TypeSpec', ['name', 'type'])
stripall = partial(map, lambda a: isinstance(a, basestring) and a.strip() or a)
filtblnk = partial(filter, lambda a: (isinstance(a, basestring) and len(a)))


class _ItsiObjectCache(MutableMapping):
    def __init__(self, *args, **kwargs):
        self._cache = dict()

    def __getitem__(self, key): return self._cache[key]
    def __delitem__(self, key): del self._cache[key]
    def __iter__(self): return iter(self._cache)
    def __len__(self): return len(self._cache)
    def __setitem__(self, key, value):
        self._cache[key] = value
        return None

def new_relationship_record(depends_on=None, depends_on_me=None):
    return {
        'depends_on': (depends_on and depends_on or []),
        'depends_on_me': depends_on_me and depends_on_me or []
    }

def window(seq, n=2):
    '''
    Given a sequence (a finite, concrete iterable), return a sliding
    window of width 'n' over the data from the iterable, i.e.
    window(['a', 'b', 'c', 'd'], 2) -> [('a', 'b'), ('b', 'c'), ('c', 'd')]

    '''
    it = iter(seq)
    result = tuple(islice(it, n))
    if len(result) == n:
        yield result
    for elem in it:
        result = result[1:] + (elem,)
        yield result

