import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.temporary_kpi')

class ItsiTemporaryKpi(ItoaObject):
    '''
    Implements ITSI Temporary KPI
    '''

    log_prefix = '[ITSI Temporary Storage] '
    collection_name = 'itsi_temporary_storage'

    def __init__(self, session_key, current_user_name):
        super(ItsiTemporaryKpi, self).__init__(session_key, current_user_name, 'temporary_kpi',
                                               collection_name=self.collection_name,
                                               title_validation_required=False)
