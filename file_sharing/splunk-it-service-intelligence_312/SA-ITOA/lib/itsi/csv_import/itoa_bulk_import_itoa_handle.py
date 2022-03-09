# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity_relationship import ItsiEntityRelationship
from itsi.objects.itsi_service_template import ItsiBaseServiceTemplate
from itoa_bulk_import_common import SERVICE, ENTITY, ENTITY_RELATIONSHIP, SERVICE_TEMPLATE

# try:  # noqa: F401
#     from typing import Type, Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from ITOA.itoa_object import ItoaObject  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


class ItoaHandle(object):
    """
    The ITOAHandle object creates straightforward instances of the ItsiService and
    ItsiEntity objects to be used by the ITOABulkImport class and the objects which
    compose it.  It provides only the bare mininum needed, and restrict the use
    of the API to those objects that need it.
    """
    def __init__(self, owner, session_key, current_user):
        # type: (str, str, str) -> None
        """
        @param owner: the owner of the current transaction
        @type: string

        @param session_key: the current session key
        @type: string

        @param current_user: the user logged in and performing the transaction
        @type: string

        @return: self
        @type: object
        """
        self.owner = owner
        self.session_key = session_key
        self.current_user = current_user
        self._entity = None  # type: Optional[ItsiEntity]
        self._service = None  # type: Optional[ItsiService]
        self._entity_relationship = None  # type: Optional[ItsiEntityRelationship]
        self._service_template = None # type: Optional[ItsiBaseServiceTemplate]

    @property
    def entity(self):
        # type: () -> ItsiEntity
        if not self._entity:
            self._entity = ItsiEntity(self.session_key, self.current_user)
        return self._entity

    @property
    def service(self):
        # type: () -> ItsiService
        if not self._service:
            self._service = ItsiService(self.session_key, self.current_user)
        return self._service

    @property
    def entity_relationship(self):
        # type: () -> ItsiEntityRelationship
        if not self._entity_relationship:
            self._entity_relationship = ItsiEntityRelationship(self.session_key, self.current_user)
        return self._entity_relationship

    @property
    def service_template(self):
        # type: () -> ItsiBaseServiceTemplate
        if not self._service_template:
            self._service_template = ItsiBaseServiceTemplate(self.session_key, self.current_user)
        return self._service_template

    def __call__(self, object_type):
        # type: (str) -> Union[ItsiEntity, ItsiService]
        """
        Depending on the parameter, return either an ItsiService object or an ItsiEntity
        object, but one meant to work only with the owner of the current KVStore operation.

        @param objecttype: SERVICE or ENTITY or ENTITY_RELATIONSHIP
        @type enum

        @return: initialized ItsiService or ItsiEntity object, respectively
        @type: ItoaObject
        """

        keys = {
            ENTITY: 'entity',
            ENTITY_RELATIONSHIP: 'entity_relationship',
            SERVICE: 'service',
            SERVICE_TEMPLATE: 'service_template'
        }

        if object_type not in keys.keys():
            raise Exception(_('[itoa_bulk_import:ItoaHandle] called with unrecognized object type: {)').format(object_type))

        return getattr(self, object_type)
