# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA import itoa_refresh_queue_utils
from ITOA.itoa_common import modular_input_should_run
from ITOA.setup_logging import setup_logging

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

logger = setup_logging("itsi_refresher.log", "itsi.object.refresher")

class ItsiRefresherModularInput(ModularInput):
    '''
    Mod input does the following -
        pulls refresh jobs from queue in kv store
        passes job to proper handler
        handles successful or failed completion of job
        repeats
    '''

    title                    = _("IT Service Intelligence Refresher")
    description              = _("Ensures data integrity and eventual consistency of ITSI " \
                               "configuration. This runs as a single instance.")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_refresher'
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


    def do_run(self, stanzas):
        """
        - This is the method called by splunkd when mod input is enabled.
        We need to set up our logger properly

        @param stanzas: config stanzas passed down by splunkd
        """
        if len(stanzas) == 0:
            #If this ends up getting run without any stanzas defined, then we should abort early
            return
        logger.debug('Running itsi refresher')
        # Single instance mode for safety only, so we only want the first stanza
        stanza_config = stanzas.itervalues().next()
        level = stanza_config.get("log_level", 'INFO').upper()
        if level not in ["ERROR", "WARN", "WARNING", "INFO", "DEBUG"]:
            level = "INFO"

        self.refresh_core = itoa_refresh_queue_utils.ITSIRefresherCore(self.session_key, logger)

        if not modular_input_should_run(self.session_key, logger=logger):
            self.refresh_core.logger.info("Will not run modular input on this node.")
            return

        self.refresh_core.setup_adapter()

        processed_job_count = self.refresh_core.main_refresh_loop()
        self.refresh_core.logger.debug("process exiting after processing %s jobs", processed_job_count)

        return

if __name__ == "__main__":
    worker = ItsiRefresherModularInput()
    worker.execute()
    sys.exit(0)
