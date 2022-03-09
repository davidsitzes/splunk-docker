import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.home_view')

class ItsiHomeView(ItoaObject):
    '''
    Implements ITSI home view
    '''

    log_prefix = '[ITSI Home View] '
    collection_name = 'itsi_service_analyzer'

    def __init__(self, session_key, current_user_name):
        super(ItsiHomeView, self).__init__(session_key,
                                           current_user_name,
                                           'home_view',
                                           collection_name=self.collection_name,
                                           title_validation_required=False)
