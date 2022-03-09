# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject

logger = utils.get_itoa_logger('itsi.object.glass_table')

class ItsiGlassTable(ItoaObject):
    '''
    Implements ITSI Glass Table
    '''

    log_prefix = '[ITSI Glass Table] '
    collection_name = 'itsi_pages'

    def __init__(self, session_key, current_user_name):
        super(ItsiGlassTable, self).__init__(session_key,
                                             current_user_name,
                                             'glass_table',
                                             collection_name=self.collection_name,
                                             title_validation_required=False)
