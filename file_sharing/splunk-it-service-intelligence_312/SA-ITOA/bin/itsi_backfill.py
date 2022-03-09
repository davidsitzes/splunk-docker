# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import logging

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.backfill import ItsiBackfillCore
from ITOA.itoa_common import post_splunk_user_message, modular_input_should_run

from SA_ITOA_app_common.solnlib.modular_input import ModularInput
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi_backfill_services.log", "itsi.backfill_services")

class BackfillModularInputException(Exception):
    pass

class ItsiBackfillModularInput(ModularInput):
    '''
    - Delegate the work to ItsiBackfillCore class

    Mod input does the following:
    1. startup actions:
        - clear completed requests
        - check in-progress jobs and sleep until they complete
        - instantiate JobProcessor classes
    2. backfill loop:
        - retrieve new backfill requests from kv store
        - for every new request, set up BackfillRequestManager and BackfillJobQueue
        - check if JobProcessors are idle and if so, feed them from the queue
    '''

    title                    = _("IT Service Intelligence Backfill Manager")
    description              = _("Supervises long-running backfill jobs that generate " \
                               "summarized KPI metrics from raw data.")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_backfill'
    use_single_instance      = True
    use_kvstore_checkpointer = False
    use_hec_event_writer     = False


    def extra_arguments(self):
        return [
            {
                'name'        : "log_level",
                'title'       : _("Logging Level"),
                'description' : _("This is the level at which the modular input will log data")
            }
        ]

    def show_message(self, message):
        post_splunk_user_message(message, session_key=self.session_key)

    def do_run(self, stanzas):
        """
        This is the method called by splunkd when mod input is enabled.
        @param stanzas: config stanzas passed down by splunkd
        """

        if not modular_input_should_run(self.session_key, logger=logger):
            logger.info("Modular input will not run on this node.")
            return

        # Single instance mode for safety only, so we only want the first stanza
        stanza_config = stanzas.itervalues().next()
        level = stanza_config.get("log_level", 'INFO').upper()
        if level not in ["ERROR", "WARN", "WARNING", "INFO", "DEBUG"]:
            level = "INFO"

        logger.setLevel(logging.getLevelName(level))

        # Main Logic
        logger.debug("Running ITSI backfill manager!")

        try:
            backfill_core = ItsiBackfillCore(self.session_key,
                    modular_input_should_run, messenger=self.show_message, logger=logger)
            backfill_core.start()
        except Exception:
            logger.exception("Backfill core job exception")

        logger.debug("Exiting modinput")
        return

if __name__ == "__main__":
    worker = ItsiBackfillModularInput()
    worker.execute()
    sys.exit(0)
