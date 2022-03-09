# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from itoa_change_handler import ItoaChangeHandler
from itsi.objects.itsi_service import ItsiService
from itsi.service_template.service_template_utils import ServiceTemplateUtils


class ServiceTemplateDeleteHandler(ItoaChangeHandler):
	"""
	Source:
		this job is only created by single service template delete or bulk
		service templates delete

	This handler does the following:
		- unlink or delete all the services linked to service template(s)
	"""

	def deferred(self, change, transaction_id=None):
		"""
		Unlink or delete services after deletion of service template(s).
		@type change: dict
		@param change: object describing the change that occurred
		Example:
			{
				_key: system generated key
				create_time: epoch time of the CUD event that occurred
				changed_object_key: [key(s) of the changed object(s)]
				changed_object_type: String identifier of the object type in the changed_object
				change_type: The type of change that occurred
				object_type: 'refresh_job'
				change_detail: change detail required by this change handler
			}
			- @type change.change_detail: dict
			- @param change.change_detail: change detail required by change handler
			Example:
				{
					'<base_service_template1_key>': ['linked_service1_id', 'linked_service2_id'],
					'<base_service_template2_key>': ['linked_service3_id', 'linked_service4_id']
				}
		@type transaction_id: basestring
		@param transaction_id: transaction id for instrumentation purposes.
		@return: bool
		"""
		owner = 'nobody'
		if change.get('change_type') != 'delete_base_service_template':
			raise ValueError(_('Expected change_type to be delete_base_service_template. '
							 'But, received %s', change.get('change_type')))

		if change.get('changed_object_type') != 'base_service_template':
			raise ValueError(_('Expected changed_object_type to be base_service_template. '
							 'But, received %s', change.get('change_type')))

		change_detail = change.get('change_detail', {})
		if not isinstance(change_detail, dict):
			raise TypeError(_('Expected change_detail to be an instance of dictionary. '
							'But, received change_detail="%s", of type %s.'),
							change_detail, type(change_detail).__name__)

		deleted_service_template_keys = change.get('changed_object_key', [])
		if not isinstance(deleted_service_template_keys, list):
			raise TypeError(_('Expected changed_object_key to be an instance of list. '
							'But, received changed_object_key="%s", of type %s.'),
							deleted_service_template_keys,
							type(deleted_service_template_keys).__name__)

		ret = False
		try:
			self._update_linked_services(deleted_service_template_keys, change_detail, owner,
										 transaction_id=transaction_id)
			ret = True
		except Exception as e:
			self.logger.exception('Error while un-linking or deleting services, after deletion '
								  'of service_templates="%s". exception="%s"',
								  deleted_service_template_keys, e)

		return ret

	def _update_linked_services(self, deleted_service_template_ids, change_detail, owner,
								transaction_id=None):
		"""
		Unlink or delete services from deleted service templates

		@type delete_service_template_ids: list
		@param delete_service_template_ids: list of deleted service template keys
		@type change_detail: dict
		@param change_detail: change detail containing map from service
		template id to linked services
		@type owner: basestring
		@param owner: owner
		@type transaction_id: basestring
		@param transaction_id: transaction id for instrumentation purposes.
		@return: None
		"""
		service_interface = ItsiService(self.session_key, 'nobody')
		service_fetch_filter = {
			'$or': []
		}
		linked_services_list = []
		for service_template_id in deleted_service_template_ids:
			for service_id in change_detail.get(service_template_id, []):
				service_fetch_filter['$or'].append({
					'_key': service_id
				})
				linked_services_list.append(service_id)
		if len(service_fetch_filter['$or']) > 0:
			linked_services = service_interface.get_bulk(owner, filter_data=service_fetch_filter,
														 req_source='ServiceTemplateDeleteHandler',
														 transaction_id=transaction_id)
			if not len(linked_services) > 0:
				self.logger.error('Could not find services linked to deleted service template(s) in kvstore, while'
								  ' unlinking services from deleted service template(s). deleted_service_templates="%s", '
								  'linked_services="%s", transaction_id="%s"',
								  deleted_service_template_ids, linked_services_list, transaction_id)
				return

			# TODO: handle else case of deleting linked services after deletion of service templates
			# using delete_linked_services flag in change_detail
			if not change_detail.get('delete_linked_services', False):
				ServiceTemplateUtils.unset_service_template_fields_in_services(linked_services)
				service_interface.batch_save_backend(owner, linked_services, transaction_id=transaction_id)

				self.logger.info('Unlinked services linked to service template(s), after service template(s) deletion.'
								 'deleted_service_templates="%s", unlinked_services="%s", transaction_id="%s"',
								 deleted_service_template_ids, linked_services_list, transaction_id)
