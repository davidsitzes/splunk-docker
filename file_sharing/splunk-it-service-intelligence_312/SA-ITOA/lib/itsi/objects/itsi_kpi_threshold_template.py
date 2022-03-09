# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.itoa_common import is_valid_str, is_valid_dict, is_valid_list, get_itoa_logger
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_time_block_utils import ItsiTimeBlockUtils
from itsi.service_template.service_template_utils import ServiceTemplateUtils

logger = get_itoa_logger('itsi.object.kpi_threshold_template')


class ItsiKpiThresholdTemplate(ItoaObject):
    '''
    Implements ITSI Threshold Policy Template
    '''

    log_prefix = '[ITSI KPI Threshold Template] '
    collection_name = 'itsi_services'
    default_policy_name = 'default_policy'

    def __init__(self, session_key, current_user_name):
        super(ItsiKpiThresholdTemplate, self).__init__(
            session_key, current_user_name, 'kpi_threshold_template', collection_name=self.collection_name,
            is_securable_object=True)

    def validate_time_policies(self, time_policy_spec_container):
        # Assume time_policy_spec_container has already been validated for valid dict

        if (
            ('policies' not in time_policy_spec_container) or
            (not is_valid_dict(time_policy_spec_container['policies']))
        ):
            time_policy_spec_container['policies'] = {
                self.default_policy_name: {'title': 'Default'}
            }

        def validate_policy_type(policy):
            if (
                ('policy_type' not in policy) or
                (not is_valid_str(policy['policy_type']))
            ):
                policy['policy_type'] = 'static'

            if (
                not any(
                    policy['policy_type'].lower() == valid_policy_type.lower()
                    for valid_policy_type in ['static', 'stdev', 'quantile', 'range']
                )
            ):
                policy['policy_type'] = 'static'

        def validate_policy_title(policy):
            if (
                ('title' not in policy) or
                (not is_valid_str(policy['title']))
            ):
                self.raise_error_bad_validation(
                    logger,
                    'Invalid KPI threshold template policy title specified. ' +
                    'Specified invalid title: "{0}"'.format(policy['title'])
                )

            normalized_title = policy['title'].lower()
            if normalized_title in policy_titles:
                self.raise_error_bad_validation(
                    logger,
                    'Duplication of policy title is not allowed. Duplicate policy title: "{0}"'.format(policy['title'])
                )
            policy_titles[normalized_title] = True

        def validate_time_blocks(policy, time_blocks):
            """
            Validates if time blocks are good, assumes this isnt invoked on default policy

            @type policy: dict
            @param policy: policy to validate time blocks for

            @type time_blocks: list of dict
            @param time_blocks: append time block from policy to array

            @return None, but appends time blocks to in/out param time_blocks
            """
            # ensure time blocks don't collide
            if (('time_blocks' not in policy) or (not is_valid_list(policy['time_blocks']))):
                policy['time_blocks'] = []
            policy_time_blocks = policy['time_blocks']

            if len(policy_time_blocks) == 0:
                return

            # UI currently is built for only one time block structure per policy since drop down controls
            # for preview assume one duration across start times. For the sake of REST API, raise error in this case
            if len(policy_time_blocks) > 1:
                self.raise_error_bad_validation(
                    logger,
                    _('Policies with more than one time block definition are not supported.')
                )

            # validate no conflict amongst time blocks of same policy
            if ItsiTimeBlockUtils.check_time_block_conflict(policy_time_blocks):
                self.raise_error_bad_validation(
                    logger,
                    _('Overlapping time blocks within same policy are not allowed.')
                )

            # validate no conflict between time blocks across all policies/time blocks seen so far
            if ItsiTimeBlockUtils.check_time_block_conflict_between(policy_time_blocks, time_blocks):
                self.raise_error_bad_validation(
                    logger,
                    _('Overlapping time blocks across multiple policies are not allowed.')
                )
            time_blocks += policy_time_blocks

        policy_validation_methods = {
            'policy_type': validate_policy_type,
            'title': validate_policy_title,
            'aggregate_thresholds': ITOAInterfaceUtils.validate_aggregate_thresholds,
            'entity_thresholds': ITOAInterfaceUtils.validate_entity_thresholds
        }

        policy_titles = {}
        time_blocks = []
        for policy_name, policy in time_policy_spec_container['policies'].iteritems():
            if not is_valid_dict(policy):
                # Ignore bad policies
                continue

            for policy_key in policy_validation_methods:
                policy_validation_methods[policy_key](policy)
                # else no validation is needed, ignore

            if (policy_name != self.default_policy_name):
                # Skip validation for collision with default policy
                validate_time_blocks(policy, time_blocks)

        if self.default_policy_name not in time_policy_spec_container['policies'].keys():
            self.raise_error_bad_validation(
                logger,
                _('Default policy cannot be removed from a KPI time policy specification.')
            )

        # Force/overwrite non-modifiable params on default policy instead of failing on them
        # Default policy is the "gap filler", its always present in all time blocks
        # Any overlap with user defined policy caused user defined policy to take precedence
        time_policy_spec_container['policies'][self.default_policy_name]['time_blocks'] = []

    def validate_kpi_threshold_templates(self, kpi_threshold_templates):
        '''
        Method to validate a KPI threshold template object and fix required fields to expected schema
        This method does not repeat validations for fields
        that are common across objects in the base like _key and title
        @type list od dict
        @param kpi_threshold_templates: array of KPI threshold template objects

        @return: None, raises exception when validation fails
        On successful return, passed in KPI threshold templates comply to expected schema
        '''
        # Assume kpi_template_list has already been validated for valid JSON and an array

        for kpi_threshold_template in kpi_threshold_templates:
            if not is_valid_dict(kpi_threshold_template):
                self.raise_error_bad_validation(
                    logger,
                    _('Invalid KPI threshold template specified. KPI threshold templates must be dictionaries.')
                )

            for bool_field in ['adaptive_thresholds_is_enabled', 'time_variate_thresholds']:
                if (
                    (bool_field not in kpi_threshold_template) or
                    (not isinstance(kpi_threshold_template[bool_field], bool))
                ):
                    kpi_threshold_template[bool_field] = False
            for str_field in ['description', 'adaptive_thresholding_training_window']:
                if (
                    (str_field not in kpi_threshold_template) or
                    (not is_valid_str(kpi_threshold_template[str_field]))
                ):
                    kpi_threshold_template[str_field] = ''

            if ('time_variate_thresholds_specification' not in kpi_threshold_template):
                kpi_threshold_template['time_variate_thresholds_specification'] = {}
            self.validate_time_policies(kpi_threshold_template['time_variate_thresholds_specification'])

    @staticmethod
    def update_kpi_threshold_from_kpi_threshold_template(kpi, kpi_thresholds_template):
        if is_valid_dict(kpi) and is_valid_dict(kpi_thresholds_template):
            if kpi_thresholds_template:
                kpi['adaptive_thresholding_training_window'] = \
                    kpi_thresholds_template.get('adaptive_thresholding_training_window')
                kpi['time_variate_thresholds'] = kpi_thresholds_template.get('time_variate_thresholds')
                kpi['adaptive_thresholds_is_enabled'] = kpi_thresholds_template.get('adaptive_thresholds_is_enabled')
                kpi['time_variate_thresholds_specification'] = \
                    kpi_thresholds_template.get('time_variate_thresholds_specification')
            else:
                kpi['kpi_threshold_template_id'] = ''
                # keep the rest of the values as it is

    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        refresh_jobs_change_details = {}
        refresh_jobs = []

        if method == CRUDMethodTypes.METHOD_DELETE:
            change_handler_mode = 'service_kpi_thresholds_template_delete'
        elif (method == CRUDMethodTypes.METHOD_UPDATE or
              method == CRUDMethodTypes.METHOD_CREATE or
              method == CRUDMethodTypes.METHOD_UPSERT):
            change_handler_mode = 'service_kpi_thresholds_template_update'

        for json_data in objects:
            # Assuming the incoming threshold template is a valid json object
            refresh_jobs_change_details['kpi_thresholds_template'] = json_data
            refresh_jobs.append(self.get_refresh_job_meta_data(change_handler_mode,
                                json_data.get('_key', ''), 'kpi_threshold_template',
                                change_detail=refresh_jobs_change_details,
                                transaction_id=transaction_id))

        is_refresh_required = len(refresh_jobs) > 0
        return is_refresh_required, refresh_jobs

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        self.validate_kpi_threshold_templates(objects)

    def can_be_deleted(self, owner, objects, raise_error=False, transaction_id=None):
        # Do not allow delete of kpi threshold template if it's used by service templates
        results = ServiceTemplateUtils(self.session_key, self.current_user_name).get_objects_not_used_by_service_templates(self.object_type,
                                                                                                                           objects)
        if raise_error and not results:
            self.raise_error_bad_validation(
                logger,
                _('KPI threshold template cannot be deleted because it is being used by one or more service templates.'))

        return results
