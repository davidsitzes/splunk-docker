import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.migration')

class ItsiMigration(ItoaObject):
    '''
    Implements ITSI Migration
    '''

    log_prefix = '[ITSI Migration] '
    collection_name = 'itsi_migration'

    def __init__(self, session_key, current_user_name):
        super(ItsiMigration, self).__init__(session_key,
                                            current_user_name,
                                            'migration',
                                            collection_name=self.collection_name,
                                            title_validation_required=False)
