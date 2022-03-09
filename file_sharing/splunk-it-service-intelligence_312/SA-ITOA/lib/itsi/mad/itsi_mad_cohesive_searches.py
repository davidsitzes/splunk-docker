# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
ITSI does not manage Anomaly Detection search directly, it manages through
a set of MAD restful endpoints.
This class provides the context manager interface which is invoked by the service
change handlers.
'''

import json
from . import itsi_mad_searches


class ItsiMADCohesiveContextManager(itsi_mad_searches.ItsiMADContextManager):
    '''
    ITSI Level MAD Context Manager
    Contains functions specific to Cohesive Anomaly Detection

    All the MAD rest level exceptions are suppressed, but the exception log will be
    logged in the itsi_mad_context_mgr.log.
    '''
    log_prefix = '[ITSI MAD Cohesive Context Manager]'
    collection_name = 'itsi_service'

    def __init__(self, session_key, app='SA-ITSI-MetricAD', owner='nobody'):
        super(ItsiMADCohesiveContextManager, self).__init__(session_key, app, owner, type='cohesive')
