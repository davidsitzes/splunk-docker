from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from ITOA.itoa_common import get_itoa_logger, normalize_num_field, is_valid_str, is_valid_num

logger = get_itoa_logger('itsi.object.event_management_state')

class ItsiEventManagementState(ItoaObject):
    '''
    Implements ITSI event management state to store settings for event management view
    '''

    log_prefix = '[ITSI Event Management State] '
    collection_name = 'itsi_event_management'

    def __init__(self, session_key, current_user_name):
        super(ItsiEventManagementState, self).__init__(
            session_key,
            current_user_name,
            'event_management_state',
            collection_name=self.collection_name,
            title_validation_required=True
            )

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        # Do validations for data consistency
        for json_data in objects:
            # Assume json_data is valid
            normalize_num_field(json_data, 'fetchLimit')
            normalize_num_field(json_data, 'realTimeRefreshRate')

            str_types = ['earliest']
            for str_type in str_types:
                # 'earliest' time can be relative string or epoch number
                if not is_valid_str(json_data.get(str_type)) and not is_valid_num(json_data.get(str_type)):
                    self.raise_error_bad_validation(
                        logger,
                        'An invalid value is specified for {0}. Specify a valid value.'.format(str_type)
                    )

            if not 'filterCollection' in json_data:
                json_data['filterCollection'] = []

            if not isinstance(json_data['filterCollection'], list):
                self.raise_error_bad_validation(
                        logger,
                        'Invalid filterCollection list specified. Specify a valid filterCollection list.'
                    )
