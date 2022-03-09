# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that runs on startup. It does the following:
1. Initializes HEC on this Search Head.
2. Creates and chowns pertinent HEC tokens.
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
from ITOA.event_management.hec_utils import HECUtil

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

class ITSINotableEventHECInit(ModularInput):
    """
    Class that implements all the required steps. See method `do_run`.
    """

    title = _('IT Service Intelligence HEC Initializer')
    description = _('Initializes Splunk HEC, creates and sets the right ACL values for HEC tokens consumed by the ITSI Notable Events Review.')
    handlers = None
    app = 'SA-ITOA'
    name = 'itsi_notable_event_hec_init'
    use_single_instance = False
    use_kvstore_checkpointer = False
    use_hec_event_writer = False

    def extra_arguments(self):
        return [{
            'name': "log_level",
            'title': _("Logging Level"),
            'description': _("This is the level at which the modular input will log data; "
                               "DEBUG, INFO, WARN, ERROR.  Defaults to WARN")
        }]

    def do_run(self, input_config):
        """
        This is the method called by splunkd when mod input is enabled.
        It initializes Splunk HEC on this SH and acquires the token.

        @param input_config: config passed down by splunkd
        """
        logger = setup_logging('itsi_event_management.log', 'itsi.event_management')

        # this modular input must run on all search heads in a SHC, so we will
        # not do any SHC specific checks.
        TOKEN = 'token'
        INDEX = 'index'
        HOST = 'host'
        SOURCE = 'source'
        SOURCETYPE = 'sourcetype'
        APP = 'app'
        ISUSEACK = 'is_use_ack'

        tokens_info = [
            {
                TOKEN: _('Auto Generated ITSI Event Management Token'),
                INDEX: 'itsi_tracked_alerts',
                HOST: None,
                SOURCE: None,
                SOURCETYPE: 'stash',
                APP: 'itsi',
                ISUSEACK: False,
            },
            {
                TOKEN: _('Auto Generated ITSI Notable Event Retention Policy Token'),
                INDEX: 'itsi_notable_archive',
                HOST: None,
                SOURCE: None,
                SOURCETYPE: 'stash',
                APP: 'itsi',
                ISUSEACK: False,
            },
            {
                TOKEN: _('Auto Generated ITSI Notable Index Audit Token'),
                INDEX: 'itsi_notable_audit',
                HOST: None,
                SOURCE: 'Notable Event Audit',
                SOURCETYPE: 'stash',
                APP: 'itsi',
                ISUSEACK: False,
            },
            {
                TOKEN: _('itsi_group_alerts_token'),
                INDEX: 'itsi_grouped_alerts',
                HOST: None,
                SOURCE: 'itsi_group_alerts',
                SOURCETYPE: 'stash',
                APP: 'itsi',
                ISUSEACK: False,
            },
            {
                TOKEN: _('itsi_group_alerts_sync_token'),
                INDEX: 'itsi_grouped_alerts',
                HOST: None,
                SOURCE: 'itsi_group_alerts',
                SOURCETYPE: 'stash',
                APP: 'itsi',
                ISUSEACK: True,
            }

        ]

        try:
            logger.info('Initializing HEC.')

            for ti in tokens_info:
                msg = _('token: `%s`, index: `%s`, host: `%s`, source: `%s`, '
                    'sourcetype: `%s` app: `%s`') % (ti[TOKEN], ti[INDEX],
                        ti[HOST], ti[SOURCE], ti[SOURCETYPE], ti[APP])
                logger.info('Acquiring %s', msg)
                HECUtil.setup_hec_token(
                    session_key=self.session_key,
                    token_name=ti[TOKEN],
                    index=ti[INDEX],
                    host=ti[HOST],
                    source=ti[SOURCE],
                    sourcetype=ti[SOURCETYPE],
                    app=ti[APP], is_use_ack=ti[ISUSEACK]
                )
                logger.info('Completed acquisition for token=`%s`', ti[TOKEN])
            logger.info('HEC Initialization complete.')
        except Exception as e:
            logger.error('Failed to initialize HEC. Will try again.')
            logger.exception(e)
            raise

if __name__ == "__main__":
    worker = ITSINotableEventHECInit()
    worker.execute()
