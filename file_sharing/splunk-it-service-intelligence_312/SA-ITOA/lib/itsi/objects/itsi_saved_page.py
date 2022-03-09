import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.saved_page')

class ItsiSavedPage(ItoaObject):
    '''
    Implements ITSI Saved Page
    '''

    log_prefix = '[ITSI Saved Page] '

    def __init__(self, session_key, current_user_name):
        super(ItsiSavedPage, self).__init__(session_key, current_user_name, 'saved_page',
                                            title_validation_required=False)