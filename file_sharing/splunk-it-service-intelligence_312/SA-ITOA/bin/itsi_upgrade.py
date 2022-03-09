# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that runs on startup if needed and handles migration
scenarios.
"""

import sys
import time

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.upgrade.itsi_migration import ItsiMigration
from ITOA.itoa_common import modular_input_should_run, get_itoa_logger

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

class ItsiMigratorModularInput(ModularInput):
    """
    Mod input that handles Upgrades which is primarily migration of data
    from older version to current version
    """

    title                    = _("IT Service Intelligence Migration Modular Input")
    description              = _("Migrate schema from old version from new version")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_upgrade'
    use_single_instance      = False
    use_kvstore_checkpointer = False
    use_hec_event_writer     = False

    def extra_arguments(self):
        return [{
                'name'        : "log_level",
                'title'       : _("Logging Level"),
                'description' : _("This is the level at which the modular input will log data")
            }]

    def do_run(self, input_config):
        """
        - This is the method called by splunkd when mod input is enabled.
        @param input_config: config passed down by splunkd
        """
        logger = get_itoa_logger("itsi.upgrade", "itsi_migration.log")
        if not modular_input_should_run(self.session_key, logger):
            return

        ItsiMigration(self.session_key).run_migration()

if __name__ == "__main__":
    worker = ItsiMigratorModularInput()
    worker.execute()
    sys.exit(0)
