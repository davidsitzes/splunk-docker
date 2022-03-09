# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.itoa_common import modular_input_should_run, get_itoa_logger

from maintenance_services.maintenance_operations.operative_maintenance_log import OperativeMaintenanceLog

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

class MaintenanceMinderModularInput(ModularInput):
    """
    Mod input dodicated to populate operative maintenance log for maintenance services
    """

    title                    = _("Maintenance Minder Modular Input")
    description              = _("Maintenance minder to populate operative maintenance " \
                               "log for maintenance services.")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'maintenance_minder'
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

        @type: object
        @param input_config: config passed down by splunkd
        """

        logger = get_itoa_logger("itsi.maintenance_minder", "maintenance_services.log")
        if not modular_input_should_run(self.session_key, logger=logger):
            logger.info("Will not run modular input on this node.")
            return

        OperativeMaintenanceLog(self.session_key).populate_operative_maintenance_log()


if __name__ == "__main__":
    worker = MaintenanceMinderModularInput()
    worker.execute()
