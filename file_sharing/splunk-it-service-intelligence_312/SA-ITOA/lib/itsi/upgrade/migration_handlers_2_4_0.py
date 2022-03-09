from migration.migration import MigrationFunctionAbstract
from ITOA.setup_logging import setup_logging

from itsi.objects.itsi_backup_restore import ItsiBackupRestore

logger = setup_logging("itsi_config.log", "itsi.migration")

class BackupRestoreJobsMigrationChangeHandler_from_2_3_0(MigrationFunctionAbstract):
    '''
    The class handling backup restore job migrations

    Note that this handler is only needed during migration, its not needed during restore since backup/restore
    jobs are only migrated, never restored
    '''

    def __init__(self, session_key, owner='nobody', app='itsi'):
        """
        Initialize
        @type session_key: basestring
        @param session_key: session_key

        @type owner: basestring
        @param owner: namespace

        @return:
        """
        super(BackupRestoreJobsMigrationChangeHandler_from_2_3_0, self).__init__(session_key)
        self.session_key = session_key
        self.owner = owner

    def execute(self):
        '''
        Backup restore jobs from 2.4.0 need host id populated for the host containing the backup location
        This handler populated the host for all jobs during migration

        This is a best effort in populating search head ids for jobs with local migration zip paths that
        we could recognize.

        @rtype boolean
        @return True on success. False otherwise.
        '''
        status = False
        try:
            all_backup_restore_jobs = list(self.get_object_iterator('backup_restore'))
            status = self.save_object('backup_restore', all_backup_restore_jobs)
        except Exception as exc:
            logger.exception('Encountered an error. Please try to save backup/restore jobs manually via UI ' \
                 'or contact Splunk support. Details %s', str(exc))
            return status
        return status
