

_migration_handler_manifest = None


def get_registered_migration_handler():
	global _migration_handler_manifest
	if _migration_handler_manifest is None:
		from .migration_manifest import migration_manifest
		_migration_handler_manifest = migration_manifest
	return _migration_handler_manifest
