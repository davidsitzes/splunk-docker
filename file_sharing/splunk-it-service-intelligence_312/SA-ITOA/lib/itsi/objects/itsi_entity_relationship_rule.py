# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from ITOA.itoa_exceptions import ItoaValidationError

logger = utils.get_itoa_logger('itsi.object.entity_relationship_rule')


class ItsiEntityRelationshipRule(ItoaObject):
    """
    Implements ITSI entity relationship rule
    """

    collection_name = 'itsi_entity_relationship_rules'
    itoa_object_type = 'entity_relationship_rule'

    def __init__(self, session_key, current_user_name):
        super(ItsiEntityRelationshipRule, self).__init__(
            session_key,
            current_user_name,
            self.itoa_object_type,
            collection_name=self.collection_name
        )

    def _validate_additional_required_fields(self, objects):
        """
        Any additional setup that is required to be done
        before a write operation (create or update) is invoked on this object

        @type objects: list
        @param objects: list of objects being written

        @return: None, throws exceptions on errors
        """
        for json_data in objects:

            if not all([utils.is_valid_str(json_data.get('predicate')),
                       utils.is_valid_str(json_data.get('subject_identifier_field')),
                       utils.is_valid_str(json_data.get('object_identifier_field'))]):
                self.raise_error_bad_validation(
                    logger,
                    'Need specify subject_identifier_field, object_identifier_field, predicate.'
                )

            if (not all([json_data.get('predicate_rules') is not None and
                        utils.is_valid_dict(json_data.get('predicate_rules')),
                        utils.is_valid_str(json_data.get('subject_entity_search')),
                        utils.is_valid_str(json_data.get('object_entity_search'))])
                ) \
                    and not utils.is_valid_str(json_data.get('entity_relationship_search', None)):
                self.raise_error_bad_validation(
                    logger,
                    'Need specify either subject_entity_search, object_entity_search and predicate_rules, '
                    'or entity_relationship_search.'
                )

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT,
                            transaction_id=None):
        """
        Any additional setup that is required to be done
        before a write operation (create or update) is invoked on this object

        @type owner: basestring
        @param owner: request owner. "nobody" or some username.

        @type objects: list
        @param objects: list of objects being written

        @type req_source: basestring
        @param req_source: Source requesting this operation.

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.

        @return: None, throws exceptions on errors
        """
        self._validate_additional_required_fields(objects)
