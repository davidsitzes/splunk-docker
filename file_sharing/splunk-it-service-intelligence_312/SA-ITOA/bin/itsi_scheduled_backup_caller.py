# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that checks and runs ITSI scheduled backup
"""

import sys
import time

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import modular_input_should_run, get_itoa_logger
from itsi.scheduled_backup.backup_scheduler import BackupScheduler
from ITOA.storage.itoa_storage import ITOAStorage

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

class ItsiScheduledBackupModularInput(ModularInput):
    """
    Mod input that handles ITSI scheduled backup 
    """

    title                    = _('IT Service Intelligence Scheduled Backup Modular Input')
    description              = _('Performs auto backup on a regular basis')
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_scheduled_backup_caller'
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
        logger = get_itoa_logger("itsi.scheduled_backup", "itsi_scheduled_backup.log")

        logger.info('ITSI_schedule_backup is called.')

        if not modular_input_should_run(self.session_key, logger):
            return

        kvstore = ITOAStorage()
        if kvstore.wait_for_storage_init(self.session_key):
            BackupScheduler(self.session_key).run_scheduled_backup()
        else:
            logger.error('KV Store unavailable for Scheduled Backup. Exiting.')
            sys.exit(1)


if __name__ == "__main__":
    worker = ItsiScheduledBackupModularInput()
    worker.execute()
    sys.exit(0)
