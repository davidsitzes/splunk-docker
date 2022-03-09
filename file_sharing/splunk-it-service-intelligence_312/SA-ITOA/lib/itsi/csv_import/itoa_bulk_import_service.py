# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itsi.itsi_const import ITOAObjConst

RESERVED_WORDS = ITOAObjConst.ENTITY_INTERNAL_KEYWORDS

# try:  # noqa: F401
#     from typing import Iterable, Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple, Mapping  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class ImportedService(object):
    """
    Represents a service to be imported: its fields, validations, and parsing.  An entity in this format
    is assumed to be a dictionary of:
        title: Text
        description: Text
        services_impacted: List[Text]
    ... as well as anything manifested from the original service, but including KPIs,
    two-way dependency relationships, and keys (either generated or already present in
    Storage).
    """

    def __init__(self, imported_service):
        # type: (Dict[Text, Any]) -> None
        self.title = imported_service['title']
        self.identifying_name = self.title.lower().strip()
        self.description = set(imported_service.get('description', []))
        self.clone_service_id = imported_service.get('clone_service_id', None)  # type: Optional[Text]
        self.i_depend_upon = set()  # type: Set[Text]
        self.depends_on_me = set()  # type: Set[Text]
        self.entities = set()       # type: Set[Text]

    def __str__(self):
        import pprint
        return pprint.pformat(self.to_storage_repr(), indent=4)
