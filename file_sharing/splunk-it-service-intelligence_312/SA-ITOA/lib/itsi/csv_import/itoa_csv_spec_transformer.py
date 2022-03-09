# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import json

from splunk.appserver.mrsparkle.lib import i18n
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.csv_import.itoa_bulk_import_common import logger

"""
Module that's designed to transform the format of import specification to expected
dictionary type object, which can be consumed by itoa_csv_loader.py. As of 11/18/2016 this
module is only used by itsi_async_csv_loader modular input.
"""


class BulkImportSpecTransformer(object):
    """
    Class that transforms config data to expected specification dictionary, which can be consumed by itoa_csv_loader.py

    For a entity only bulk import, the sample data would look something like this:
    Sample config data:
    {
        'transaction_id': '29ef1849',
        'uploaded_by': 'admin'
        'entity_identifier_fields': 'name',
        'entity_informational_fields': 'family,product,vendor',
        'entity_title_field: 'name',
        'update_type': 'UPSERT',
        'entity_relationship_spec': {'hosts':'vm1, vm2', 'hostedBy':'host_id'}
    }

    Sample transformed spec:
    {
        'transaction_id': '29ef1849',
        'uploaded_by': 'admin'
        'entity':
            {
                'titleField': 'name',
                'informationalFields': [family,product,vendor]
                'identifierFields': 'name'
            }
        'update_type':'UPSERT',
        'entity_relationship':
            {
                'subjectField': 'name',
                'entity_relationship_spec': {'hosts':['vm1', 'vm2'], 'hostedBy':['host_id']}
            }
    }

    """

    # Class variables
    LIST_KEYS = ['selected_services', 'service_rel', 'service_description_column', 'entity_identifier_fields',
                 'entity_informational_fields', 'entity_description_column', 'entity_service_columns',
                 'service_dependents']
    DICT_KEYS = ['entity_field_mapping']
    DICT_KEYS_FROM_STRING = ['entity_relationship_spec']
    FIELDS_TO_REMOVE = ['host', 'name', 'entity_type', 'index']
    SERVICE_FIELDS_MAPPING = {'service_title_field': 'titleField',
                              'service_description_column': 'descriptionColumns',
                              'service_enabled': 'serviceEnabled',
                              'service_clone_id': 'serviceClone',
                              'service_security_group': 'serviceSecurityGroup',
                              'service_template_field': 'serviceTemplate',
                              'backfill_enabled': 'backfillEnabled'}
    ENTITY_FIELDS_MAPPING = {'entity_title_field': 'titleField', 'entity_identifier_fields': 'identifyingFields',
                             'entity_informational_fields': 'informationalFields',
                             'entity_description_column': 'descriptionColumns',
                             'entity_service_columns': 'service_column', 'entity_field_mapping': 'fieldMapping'}
    ENTITY_RELATIONSHIP_FIELDS_MAPPING = {'entity_title_field': 'subjectField',
                                          'entity_relationship_spec': 'entity_relationship_spec'}
    SERVICE_KEY = 'service'
    ENTITY_KEY = 'entity'
    TEMPLATE_KEY = 'template'
    ENTITY_RELATIONSHIP_KEY = 'entity_relationship'
    DEFAULT_UPDATE_TYPE = 'UPSERT'

    def __init__(self, import_info):
        self.bulk_import_spec = import_info
        self.validate_import_info(self.bulk_import_spec)

    @staticmethod
    def validate_import_info(import_info):
        """
        Validate config data that's passed in
        @type: dictionary
        @param import_info: object that contains metadata information about entities and services
        """
        if import_info is None or not isinstance(import_info, dict):
            msg = _('Error. Expected import_info to be type: dict. Actual import_info type is: %s') % type(import_info).__name__
            raise TypeError(msg)
        if not import_info:
            msg = _('Error. import_info is empty.')
            raise Exception(msg)
        if 'service_title_field' not in import_info and 'entity_title_field' not in import_info:
            msg = _('Error. Invalid import_info. Please make sure at least '
                   'one of service_title_field and entity_title_field key exists in import_info')
            raise KeyError(msg)

        if 'entity_relationship_spec' in import_info and 'entity_title_field' not in import_info:
            msg = _('Error. Invalid import_info. Please make sure entity_title_field key exists '
                   'when entity_relationship_spec key exists in import_info')
            raise KeyError(msg)

        if 'entity_relationship_spec' in import_info and 'entity_title_field' not in import_info:
            msg = _('Error. Invalid import_info. Please make sure entity_title_field key exists ' \
                  'when entity_relationship_spec key exists in import_info')
            raise KeyError(msg)

        # transaction_id is a required field
        if 'transaction_id' not in import_info or 'uploaded_by' not in import_info:
            msg = _('Required fields not found. Please make sure both "transacion_id" and "uploaded_by" '
                   'are included in meta file')
            raise KeyError(msg)

    @classmethod
    def normalize_fields(cls, import_info):
        """
        Normalize necessary fields inside spec object
        @type: dictionary
        @param import_info: object that contains metadata information about entities and services
        """
        # update_type needs to be updateType and default value sets to UPSERT
        if 'update_type' not in import_info:
            import_info['updateType'] = cls.DEFAULT_UPDATE_TYPE
        else:
            import_info['updateType'] = import_info.get('update_type')
            import_info.pop('update_type', None)

        for key in import_info.keys():
            if key in cls.LIST_KEYS:
                import_info[key] = ITOAInterfaceUtils.make_array_of_strings(import_info[key])
            if key in cls.DICT_KEYS:
                import_info[key] = ITOAInterfaceUtils.make_dict_from_kv_string(import_info[key])
            if key in cls.DICT_KEYS_FROM_STRING:
                val = ITOAInterfaceUtils.make_dict_from_string(import_info.get(key))
                if val is not None and len(val) > 0:
                    import_info[key] = val
            if key in cls.FIELDS_TO_REMOVE:
                import_info.pop(key, None)

    @classmethod
    def transform(cls, import_info):
        """
        Transform service related fields to be under key 'service' and the same for entity
        @type: dictionary
        @param import_info: object that contains metadata information about entities and services
        """
        if 'service_title_field' in import_info:
            service_fields_to_transform = set.intersection(set(import_info.keys()),
                                                           set(cls.SERVICE_FIELDS_MAPPING.keys()))

            import_info[cls.SERVICE_KEY] = cls._transform_fields(import_info, service_fields_to_transform,
                                                                 cls.SERVICE_FIELDS_MAPPING)

        if 'template' in import_info:
            template_spec = import_info[cls.TEMPLATE_KEY]

            try:
                import_info[cls.TEMPLATE_KEY] = json.loads(template_spec)
            except (ValueError, TypeError) as err:
                import_info[cls.TEMPLATE_KEY] = {}

                logger.warning(
                    'Failed to parse specification for service template: {0} with error: {1}'.format(template_spec, err)
                )

        if 'entity_title_field' in import_info:
            entity_fields_to_transform = set.intersection(set(import_info.keys()),
                                                          set(cls.ENTITY_FIELDS_MAPPING.keys()))

            import_info[cls.ENTITY_KEY] = cls._transform_fields(import_info, entity_fields_to_transform,
                                                                cls.ENTITY_FIELDS_MAPPING)

            if 'entity_relationship_spec' in import_info:
                entity_rel_fields_to_transform = set.intersection(set(import_info.keys()),
                                                                  set(cls.ENTITY_RELATIONSHIP_FIELDS_MAPPING.keys()))

                import_info[cls.ENTITY_RELATIONSHIP_KEY] = cls._transform_fields(import_info,
                                                                                 entity_rel_fields_to_transform,
                                                                                 cls.ENTITY_RELATIONSHIP_FIELDS_MAPPING)

    def _get_transformed_spec(self):
        """
        Return transformed spec object
        @rtype: dictionary
        @return: a dict type object that can be used by itoa_csv_loader
        """
        self.normalize_fields(self.bulk_import_spec)
        self.transform(self.bulk_import_spec)
        return self.bulk_import_spec

    @staticmethod
    def _transform_fields(import_info, fields_to_transform, fields_mapping):
        """
        Return a dict object with value of fields in fields_to_transform moved to a new field based on fields_mapping

        @type: dictionary
        @param import_info: object that contains metadata information about entities and services

        @type: set
        @param fields_to_transform: set that contains all fields needed to transform

        @type: dictionary
        @param fields_mapping: dict that contains the mapping between keys existed in import_info and new field names

        @rtype: dictionary
        @return: a dict type object with new fields and value and old keys removed
        """
        transformed_fields_obj = {}
        for key in fields_to_transform:
            transformed_fields_obj[fields_mapping[key]] = import_info[key]
        return transformed_fields_obj

    transformed_spec = property(_get_transformed_spec)
