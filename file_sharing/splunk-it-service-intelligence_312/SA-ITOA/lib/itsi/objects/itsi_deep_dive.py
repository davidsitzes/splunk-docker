import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.deep_dive')


class ItsiDeepDive(ItoaObject):
    '''
    Implements ITSI Deep Dive
    '''

    log_prefix = '[ITSI Deep Dive] '
    collection_name = 'itsi_pages'

    def __init__(self, session_key, current_user_name):
        super(ItsiDeepDive, self).__init__(session_key,
                                           current_user_name,
                                           'deep_dive',
                                           collection_name=self.collection_name,
                                           title_validation_required=False)
