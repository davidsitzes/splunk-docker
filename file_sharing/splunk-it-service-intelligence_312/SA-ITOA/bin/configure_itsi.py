# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import logging

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.itsi_utils import ItsiSettingsImporter
from ITOA.itoa_common import post_splunk_user_message, modular_input_should_run

from SA_ITOA_app_common.solnlib.modular_input import ModularInput
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi_config.log", "itsi.configurator")

class ConfigureITSI(ModularInput):
    """
    Just a basic modular input responsable for configuring ITSI.
    Here are just one of the many amazing things it does
        - Import entities from the conf file system into the statestore

    """
    title                    = _("IT Service Intelligence Configurator")
    description              = _("Configure IT Service Intelligence")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'configure_itsi'
    use_single_instance      = False
    use_kvstore_checkpointer = False
    use_hec_event_writer     = False

    def __init__(self):
        logger.debug("[ConfigureITSI] [init] initialization complete")
        super (ConfigureITSI, self).__init__()

    def extra_arguments(self):
        return [
            {
                'name'        : "log_level",
                'title'       : _("Logging Level"),
                'description' : _("This is the level at which the modular input will log data")
            },
            {
                'name'        : "is_configured",
                'title'       : _("Configuration flag"),
                'description' : _("Old configuration")
            }
        ]


    def do_run(self, input_config):
        """
        First part, we need to find the ITSI stanzas, and then move them into the statestore
        The stanzas are just organized by type (entity, kpi, service) etc.  We are just going
        to do a 1:1 import into the statestore
        """
        if not modular_input_should_run(self.session_key, logger=logger):
            logger.info("Modular input will not run on this node.")
            return

        logger.info("Check and import data from conf to kv store")
        itsi_settings_importer = ItsiSettingsImporter(session_key=self.session_key)
        try:
            is_all_import_success = itsi_settings_importer.import_itsi_settings(owner='nobody')
            if not is_all_import_success:
                post_splunk_user_message(
                    _('Failures occurred while attempting to import some IT Service Intelligence settings from '
                    'configuration files for apps and modules. '
                    'Check the logs to get information about which settings failed to be imported.'),
                    session_key=self.session_key
                )
        except Exception as e:
            message = _("Importing IT Service Intelligence settings from conf files " \
                      "for apps and modules failed with: %s") % str(e)
            logger.exception(message)
            post_splunk_user_message(message, session_key=self.session_key)

        logger.info("Successfully imported IT Service Intelligence settings from conf files for apps and modules.")


if __name__ == "__main__":
    worker = ConfigureITSI()
    worker.execute()
    sys.exit(0)
