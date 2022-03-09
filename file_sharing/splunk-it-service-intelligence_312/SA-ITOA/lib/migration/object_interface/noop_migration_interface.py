# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.


from .base_migration_interface import BaseMigrationInterface

class NoopMigrationInterface(BaseMigrationInterface):
    """
        Interface  which does nothing
    """

    def _iterator_from_kvstore(self, object_type):
        pass

    def migration_get(self, object_type, limit=100):
        return None

    def migration_save_single_object_to_kvstore(self, object_type, validation=True, dupname_tag=None):
        pass

    def migration_delete_kvstore(self, object_type):
        pass
