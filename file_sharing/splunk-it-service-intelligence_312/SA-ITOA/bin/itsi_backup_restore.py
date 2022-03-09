# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.backup_restore import itsi_backup_restore_utils
from ITOA.storage.itoa_storage import ITOAStorage
from SA_ITOA_app_common.solnlib.modular_input import ModularInput
from SA_ITOA_app_common.solnlib.server_info import ServerInfo

class ItsiBackupRestoreModularInput(ModularInput):
    """
    Mod input dodicated to populate operative maintenance log for maintenance services
    """

    title                    = _('IT Service Intelligence Backup Restore Jobs Processor')
    description              = _('Runs backup and restore jobs')
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_backup_restore'
    use_single_instance      = False
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


    def do_run(self, input_config):
        """
        This is the method called by splunkd when mod input is enabled.

        @type: object
        @param input_config: config passed down by splunkd
            input_config is a dictionary key'ed by the name of the modular
            input, its value is the modular input configuration.
        """

        # input_config is a dictionary key'ed by the name of the modular
        # input, its value is the modular input configuration.
        input_config = input_config.values()[0]

        level = input_config.get('log_level', 'WARN').upper()
        if level not in ("ERROR", "WARN", "WARNING", "INFO", "DEBUG"):
            level = "INFO"

        info = ServerInfo(self.session_key)
        self.jobs_processor = itsi_backup_restore_utils.ITSIBackupRestoreJobsProcessor(
            self.session_key,
            info,
            log_level=level
        )
        if info.is_shc_member():
            self.jobs_processor.logger.info(
                'Running modular input on shc member with search_head_id %s',
                info.guid
            )

        # Wait for KV Store to initialize or we will accidentally clean up deleted jobs
        kvstore = ITOAStorage()
        if kvstore.wait_for_storage_init(self.session_key):
            self.jobs_processor.logger.debug('Running ITSI Backup Restore Jobs Processor')
            processed_job_count = self.jobs_processor.run()
            self.jobs_processor.logger.debug('Mod input process exiting after processing %s jobs', processed_job_count)
        else:
            self.jobs_processor.logger.error('KV Store unavailable for Backup Restore Agent, exiting, expect restart')
            sys.exit(1)

if __name__ == "__main__":
    worker = ItsiBackupRestoreModularInput()
    worker.execute()
    sys.exit(0)
