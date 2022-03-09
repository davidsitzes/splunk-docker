# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
from itoa_bulk_import_common import logger
import copy

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Any, Optional, Union, Callable, Tuple  # noqa: F401
#     from itoa_bulk_import_itoa_handle import ItoaHandle  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401


def _is_shkpi(kpi):
	# type: (Dict[Text, Any]) -> bool
	# Decide if the current kpi is an shkpi
	#
	# @param kpi: a kpi
	# @return: bool
	return 'ServiceHealthScore' in kpi.get('title')


class ServiceSource(object):
	"""
	Create new instances of a service.  Needs to be its own class because it may be called
	upon to return modified copies of an existing service ("clone" mode).  That copy is
	fetched once and memoized.
	"""

	def __init__(self, itoa_handle, enabled=False, sec_grp=GLOBAL_SECURITY_GROUP_CONFIG.get('key'), source='unknown', backfill_enabled=False):
		# type: (ItoaHandle, bool, Text) -> None
		"""
		@param itoa_handle: the interface to ITOAObject store
		@param source: the source of the data
		@return: self
		"""
		self.source = source
		self.enabled = enabled
		self.sec_grp = sec_grp
		self.itoa_handle = itoa_handle
		self.cloned_service_singleton = None  # type: Optional[Dict[Text, Any]]
		self.backfill_enabled = backfill_enabled

	def _get_new_service(self, title, desc='', relationship=None):
		"""
		Creates and returns a new service object with passed in params

		@param title: Service title
		@type: string

		@param desc: A description of the service
		@type: string

		@param relationship: A map of related services
		@type: dict

		@return: A new service
		@type: dict
		"""
		key = ITOAInterfaceUtils.generate_backend_key()
		return {
			'_key': key,
			'title': title,
			'identifying_name': title.strip().lower(),
			'description': desc,
			'object_type': 'service',
			'create_source': self.source,
			'services_depends_on': [],
			'sec_grp': self.sec_grp,
			'services_depending_on_me': [],
			'enabled': (self.enabled and 1) or 0,
			'entity_rules': [],
			'backfill_enabled': (self.backfill_enabled and 1) or 0
		}

	def _get_cloned_service(self, service_id, title, desc, relationship):
		"""
		Returns the service specified, from which new services will be cloned.  This
		interface creates and returns only one service per transaction, however large,
		and memoizes it after the first request.

		@param service_id: The service to be cloned
		@type: string

		@param title: The service title
		@type: string

		@param desc: A description of the service
		@type: string

		@param relationship: A map of related services
		@type: dict

		@return: A cloned service
		@type: dict
		"""
		if self.cloned_service_singleton is None:
			possible_cloned_service_singleton = self.itoa_handle.service.get(self.itoa_handle.owner, service_id)
			if possible_cloned_service_singleton:
				self.cloned_service_singleton = possible_cloned_service_singleton

		# The customer gets this list from a drop-down, but it's also possible this comes
		# from an inputs.conf file, and the source service may no longer exist.
		if not self.cloned_service_singleton:
			logger.error(('[bulk_import:get_clone_service] Request for source service {} denied; '
						  'using blank service, which is probably not what you want.').format(service_id))
			return self._get_new_service(title, desc, relationship)

		key = ITOAInterfaceUtils.generate_backend_key()
		service = copy.deepcopy(self.cloned_service_singleton)
		service.update({
			'_key': key,
			'title': title,
			'description': desc,
			'identifying_name': title.strip().lower(),
			'services_depends_on': [],
			'sec_grp': self.sec_grp,
			'services_depending_on_me': [],
			'enabled': (self.enabled and 1) or 0,
			'backfill_enabled': (self.backfill_enabled and 1) or 0
		})
		if 'entity_rules' not in service:
			service['entity_rules'] = []
		service['kpis'] = [kpi for kpi in service.get('kpis', []) if not _is_shkpi(kpi)]
		for kpi in service['kpis']:
			kpi['_key'] = ITOAInterfaceUtils.generate_backend_key()
		service['kpis'].append(ITOAInterfaceUtils.generate_shkpi_dict(key))
		return service

	def __call__(self, title, desc='', relationship=None, clone_service_id=None):
		"""
		Creates and returns a new service object with passed in parameters.  If
		a clone_service_id is supplied, the new service object will be initialized
		with values from the cloned service object.

		@param title: service title
		@type: string

		@param desc: a description of the service
		@type: string

		@param relationship: a map of related services
		@type: dict

		@param clone_service_id: A service to be cloned, if any
		@type: string

		@return: a new service with a unique shkpi
		@type: dict
		"""
		if clone_service_id:
			return self._get_cloned_service(clone_service_id, title, desc, relationship)

		return self._get_new_service(title, desc, relationship)
