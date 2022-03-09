# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from ITOA.itoa_common import get_itoa_logger
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from .utils import object_collection_mapping
from maintenance_services.constants import OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE

logger = get_itoa_logger('maintenance_services.object.operative_maintenance_record', 'maintenance_services.log')

_OBJECT_TYPE = OPERATIVE_MAINTENANCE_RECORD_OBJECT_TYPE

class OperativeMaintenanceRecord(ItoaObject):
    '''
    Implements record manipulations for operative maintenance log.
    Used as the primary interface to populate the collection/lookup for operative maintenance objects.
    '''

    log_prefix = '[Operative Maintenance Record] '

    def __init__(self, session_key, current_user_name):
        super(OperativeMaintenanceRecord, self).__init__(
            session_key,
            current_user_name,
            _OBJECT_TYPE,
            collection_name=object_collection_mapping[_OBJECT_TYPE],
            title_validation_required=False
        )

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        '''
        Additional setup performed during edit/create operations.
        Primarily involves normalizing in_maintenance field.

        Will skip schema validations since this API is only used by the maintenance minder to perform updates.
        No public API is exposed to update using this API.
        If this changes, we must add validations for schema on update/create.

        @type: string
        @param owner: "owner" user performing the operation

        @type: list of dict
        @param objects: list of records being processed as JSON

        @type: string
        @param req_source: source initiating this operation, for tracking

        @type: string
        @param method: type of CRUD operation being performed

        @rtype: None
        @return: None
        '''
        for json_data in objects:
            # Assume json_data is valid

            in_maintenance = str(json_data.get('in_maintenance', 0))
