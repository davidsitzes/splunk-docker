# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itoa_bulk_import_common import _ItsiObjectCache

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_service import ImportedService  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


# INTRODUCTION
# ============
#
# The service cache exists so that service objects (indexed by their identifying name)
# can be tracked and managed through a common interface.  Service objects are by their nature
# much more complex than entities, and can't simply be abstracted into a simple interface.


class ServiceCache(_ItsiObjectCache):
    """
    The ServiceCache isolates all of those functions and methods that are service-related into a
    single class with a simple, straightforward api based on dictionaries.  A Service is added to
    the cache via the dictionary syntax, i.e. service_cache[service['title']] = service, and all
    of the balancing of that service's dependencies are done automatically.

    A utility function supporting the association of an entity with its services for bulk-import has
    been provided.

    Utility functions that support the merging inbound services with their stored counterparts are found
    toward the end of this class.
    """
    def _update_cache(self, identifying_name, service):
        # type: (Text, ImportedService) -> None
        # for a given service keyed by title, if it's already present merge the new service with the
        # existing one, and affirm all service relationships.
        #
        # @param title: the title of the service to be stored
        # @type: string
        #
        # @param service: the service to be stored
        # @type: dict
        #
        # @return: None
        current = self._cache.get(identifying_name, None)
        if current:
            for field in ['i_depend_upon', 'depends_on_me', 'description', 'entities']:
                setattr(service, field, getattr(current, field).union(getattr(service, field)))

        self._cache[identifying_name] = service

    def _update_relationships(self, service):
        # Update forward and backward relationships.
        for st in service.i_depend_upon:
            depservice = self._cache[st]
            depservice.depends_on_me = depservice.depends_on_me.union([service.identifying_name])

        for st in service.depends_on_me:
            depservice = self._cache[st]
            depservice.i_depend_upon = depservice.i_depend_upon.union([service.identifying_name])

        return None

    def __setitem__(self, title, service):
        # type: (Text, ImportedService) -> None
        """
        Add or update a service in the cache, using the syntax of dictionaries.  The service added
        (and all of its dependencies) will be updated according to the rules of services.

        @param key: a service title
        @param value: a service
        @returns None
        """
        self._update_cache(title, service)
        self._update_relationships(service)
        return None

    def update_with(self, service):
        # type: (Union[ImportedService, List[ImportedService]]) -> None
        """
        Convenience version of __setitem__(key, value)
        @param service: the service or services to put into the cache
        @type: dict
        """
        if (isinstance(service, list)):
            for svc in service:
                self._update_cache(svc.identifying_name, svc)
            for svc in service:
                self._update_relationships(svc)
            return

        self._update_cache(service.identifying_name, service)
        self._update_relationships(service)
