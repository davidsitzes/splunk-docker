# $(copyright)

import copy
import uuid
from splunk.appserver.mrsparkle.lib import i18n
from itoa_change_handler import ItoaChangeHandler
from ITOA import itoa_common as utils
from ITOA.itoa_factory import instantiate_object
from itsi.objects.itsi_kpi import ItsiKpi
from ITOA.itoa_object import CRUDMethodTypes


class BaseServiceTemplateUpdateHandler(ItoaChangeHandler):
	"""
	Whenever a service template is updated, changes to all the linked
	services could be pushed out using this change handler.

	NOTE: update of service after service template creation from service,
	is done synchronously, not using this change handler.
	"""
	current_user_name = 'nobody'
	owner = 'nobody'

	def deferred(self, change, transaction_id=None, scheduled_for_later=False):
		"""
		Updates KPIs, entity rules, health scores and KPIs' thresholds, of services
		linked to updated service templates.

		Logic below can handle multiple impacted objects in a change request. But, we should
		only request one impacted object per request, considering the amount of processing
		that might be needed to process a single change job.

		NOTE: For each key in changed_object_key list, provide a changed object key to change
		detail map in change_detail field.

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
					'<base_service_template1_key>': {
							'kpi_update_required': True
							'overwrite_health_scores': True,
							'overwrite_kpi_thresholds': False,
							'overwrite_entity_rules': False,
							'old_kpis': {
								'<_key_of_old_kpi1>': '<title_of_old_kpi1>',
								'<_key_of_old_kpi2>': '<title_of_old_kpi2>'
							}
						}
				}
				- change.change_detail.overwrite_health_scores: True or False
				- change.change_detail.overwrite_kpi_thresholds: 'all', 'unchanged' or 'none'
				- change.change_detail.overwrite_entity_rules: True or False
				- change.change_detail.service_template_id: _key of base service template which was updated
				- change.change_detail.service_template_id: _key of base service template which was updated
				- change.change_detail.kpi_update_required: True or False
				- change.change_detail.old_kpis: only needed when kpi_update_required is True.
					map of old kpis _keys to old kpi titles
		@type transaction_id: basestring
		@param transaction_id: transaction id for instrumentation purposes.
		@type scheduled_for_later: bool
		@param scheduled_for_later: True, if processing job scheduled for a later time. else, False.
		@return: bool
		"""
		if change.get('change_type') != 'base_service_template_update':
			raise ValueError(_('Expected change_type to be `base_service_template_update`. '
							'But, received `{}`.').format(change.get('change_type')))

		if change.get('changed_object_type') != 'base_service_template':
			raise ValueError(_('Expected changed_object_type to be `base_service_template`. '
							'But, received `{}`.').format(change.get('change_type')))

		change_details = change.get('change_detail', {})
		if not isinstance(change_details, dict):
			raise TypeError(_('Expected change_detail to be an instance of dictionary. '
							'But, received change_detail=`{0}`, of type {1}.').
							format(change_details, type(change_details).__name__))

		changed_object_keys = change.get('changed_object_key', [])
		if not isinstance(changed_object_keys, list):
			raise TypeError(_('Expected changed_object_key to be an instance of list. '
							'But, received changed_object_key=`{0}`, of type {1}.').
							format(changed_object_keys, type(changed_object_keys).__name__))

		service_template_interface = instantiate_object(self.session_key, self.current_user_name, 'base_service_template', logger=self.logger)
		service_interface = instantiate_object(self.session_key, self.current_user_name, 'service', logger=self.logger)

		service_template_get_filter = {
			'$or': []
		}
		service_template_sync_status_map = {}
		success = True
		for service_template_key in changed_object_keys:
			try:
				if not utils.is_valid_str(service_template_key):
					self.logger.error('Skipping the service template with invalid key, found while updating services'
									  ' with changes in service template. service_template_key="%s", transaction_id="%s"',
									  service_template_key, transaction_id)
					continue

				self.logger.info('Updating linked services, after update of service template. service_template="%s"',
								 service_template_key)

				change_detail = change_details.get(service_template_key, {})
				old_kpis = change_detail.get('old_kpis', {})
				overwrite_health_scores = change_detail.get('overwrite_health_scores', False)
				overwrite_entity_rules = change_detail.get('overwrite_entity_rules', False)
				overwrite_kpi_thresholds = change_detail.get('overwrite_kpi_thresholds', 'none')
				kpi_update_required = change_detail.get('kpi_update_required', False)

				if kpi_update_required or overwrite_entity_rules:
					service_template_sync_status_map[service_template_key] = {}
					service_template_get_filter['$or'].append({'_key': service_template_key})
					try:
						# considering, the consumer of this change handler would always use one change job
						# for one service template, performing below kvstore fetch for each service template.
						updated_service_template = service_template_interface.get(
							self.owner, service_template_key, req_source='base_service_template_update', transaction_id=transaction_id
						)
						# change sync status to syncing in following cases:
						#	 1. sync status is not already 'syncing' and current job type is 'scheduled for later'
						#	 2. sync status is not already 'syncing', current job type is 'scheduled for now' and
						#	  no push changes job is scheduled for later.
						if updated_service_template.get('sync_status', '') != 'syncing' and \
							(scheduled_for_later or not (updated_service_template.get('sync_status') == 'sync scheduled' and
									updated_service_template.get('scheduled_time'))):
							updated_service_template['sync_status'] = 'syncing'
							service_template_interface.batch_save_backend(
								self.owner, [updated_service_template], transaction_id=transaction_id
							)
						impacted_services_get_filter = {
							'$or': []
						}
						impacted_services_keys = []
						for service_id in updated_service_template.get('linked_services', []):
							impacted_services_get_filter['$or'].append({
									'_key': service_id
								})
							impacted_services_keys.append(service_id)

						if len(impacted_services_get_filter['$or']) > 0:
							impacted_services = service_interface.get_bulk(self.owner, filter_data=impacted_services_get_filter,
																		   req_source='base_service_template_update',
																		   transaction_id=transaction_id)

							if not len(impacted_services) > 0:
								self.logger.error('Could not find services linked to service template in kvstore, while updating services'
												' with service template changes. service_template="%s", linked_services="%s", '
												'transaction_id="%s"', service_template_key, impacted_services_keys, transaction_id)
								continue

							self.logger.debug('Number of linked services = %s, to be updated after service template update.'
											  ' service_template="%s", transaction_id="%s"',
											  len(impacted_services), service_template_key, transaction_id)

							deleted_kpi_keys = old_kpis.keys()
							new_kpi_keys = []
							if kpi_update_required:
								for kpi in updated_service_template.get('kpis', []):
									if kpi.get('_key') in deleted_kpi_keys:
										deleted_kpi_keys.remove(kpi['_key'])
									else:
										new_kpi_keys.append(kpi['_key'])

								self.logger.debug('After service_template="%s" update, deleted_kpis_keys="%s" and'
												  ' new_kpis_keys="%s". transaction_id="%s"',
												  service_template_key, deleted_kpi_keys, new_kpi_keys, transaction_id)

							for service in impacted_services:
								self.logger.info('Updating content of linked service="%s", after service_template="%s" update.'
												 'transaction_id="%s"', service.get('_key'), service_template_key, transaction_id)

								if kpi_update_required:
									self._update_service_kpis_from_service_template(service, updated_service_template, new_kpi_keys,
																					deleted_kpi_keys, old_kpis, service_interface,
																					overwrite_health_scores, overwrite_kpi_thresholds,
																					transaction_id)
								if overwrite_entity_rules:
									service['entity_rules'] = updated_service_template.get('entity_rules', [])

								service['base_service_template_id'] = updated_service_template.get('_key')
								service['serviceTemplateId'] = updated_service_template.get('serviceTemplateId', '')

						# enable flag to skip service template linking by service interface, to avoid circular updates
						service_interface.skip_service_template_update = True
						service_interface.save_batch(self.owner, impacted_services, validate_names=False,
													 req_source='base_service_template_update', method=CRUDMethodTypes.METHOD_UPDATE,
													 transaction_id=transaction_id)

						# update sync status to synced
						self._update_service_template_status(service_template_sync_status_map[service_template_key], sync_status='synced')

					except Exception as e:
						self.logger.exception(_('Error while updating services linked to service_template="%s". '
											  'Exception="%s"'), service_template_key, e)

						# update sync status to sync failed and save the error
						self._update_service_template_status(
							service_template_sync_status_map[service_template_key], sync_status='sync failed', last_sync_error=str(e)
						)

			except Exception as e:
				self.logger.exception(_('Error while updating services linked to service_template="%s". '
									  'Exception="%s"'), service_template_key, e)
				success = False
		# ideally, there should be only one service template to update. still, use batch save to update
		# sync status for service template, only if service template has no push job scheduled
		if service_template_sync_status_map:
			# fetch persisted templates again to make sure we have latest service templates
			# changes and then update sync status
			persisted_service_templates = service_template_interface.get_bulk(
				self.owner, filter_data=service_template_get_filter,
				req_source='base_service_template_update', transaction_id=transaction_id
			)
			filtered_service_templates_to_update = []
			for persisted_service_template in persisted_service_templates:
				service_template_id = persisted_service_template.get('_key')
				if service_template_id in service_template_sync_status_map:
					if persisted_service_template.get('sync_status') != 'sync scheduled':
						persisted_service_template.update(service_template_sync_status_map[service_template_id])
						self._cleanup_scheduled_job_fields(persisted_service_template)
						filtered_service_templates_to_update.append(persisted_service_template)

			if len(filtered_service_templates_to_update) > 0:
				service_template_interface.batch_save_backend(
					self.owner, filtered_service_templates_to_update, transaction_id=transaction_id
				)
		return success

	def _update_service_kpis_from_service_template(self, service, service_template, new_kpi_keys, deleted_kpi_keys,
												   old_kpi_key_to_title_map, service_interface,
												   overwrite_health_scores=False, overwrite_kpi_thresholds='none', transaction_id=None):
		"""
		Updates KPIs linked to service template in a service, with the updated KPIs in service template.

		@type service: dict
		@param service: linked service object to template to be updated
		@type service_template: dict
		@param service_template: service template object from which service has to be updated
		@type new_kpi_keys: list of basestring
		@param new_kpi_keys: list of new kpis keys in service template
		@type deleted_kpi_keys: list of basestring
		@param deleted_kpi_keys: list of deleted kpis keys in service template
		@type old_kpi_key_to_title_map: dict
		@param old_kpi_key_to_title_map: kpi key to title map for old kpis in service template
		@type service_interface: ItsiService
		@param service_interface: instantiated object of ItsiService interface
		@type overwrite_health_scores: bool
		@param overwrite_health_scores: overwrite or not kpi urgency, used to calculate service health score
		@type overwrite_kpi_thresholds: String
		@param overwrite_kpi_thresholds: overwrite kpi thresholds on 'all', 'unchanged', 'none' kpis of the linked services
		@type transaction_id: basestring
		@param transaction_id: transaction id for instrumentation purposes.
		@return: None
		"""

		service_kpi_from_title_map = {}
		# used for finding stale KPIs in service which no longer exist in service template
		service_kpis_linked_to_template = {}
		for kpi in service.get('kpis', []):
			if kpi.get('_key').startswith(service_interface.shkpi_starts_with):
				continue
			service_kpi_from_title_map[kpi.get('title')] = kpi
			if kpi.get('base_service_template_id'):
				service_kpis_linked_to_template[kpi.get('_key')] = kpi.get('title')

		if overwrite_kpi_thresholds.lower() not in ('all', 'unchanged'):
			overwrite_kpi_thresholds = 'none'

		for kpi in service_template.get('kpis', []):
			if kpi.get('_key') in new_kpi_keys:
				# new kpi case
				self.logger.debug(
					'Adding the new_kpi="%s" to linked_service="%s", which was added to service_template="%s". transaction_id="%s"',
					kpi.get('title'), service.get('_key'), service_template.get('_key'), transaction_id
				)

				if kpi.get('title') in service_kpi_from_title_map and not \
					service_kpi_from_title_map[kpi.get('title')].get('base_service_template_id', ''):
					# custom kpi with the same name already exists in service. update the name of existing kpi.
					service_kpi_from_title_map[kpi.get('title')]['title'] = kpi.get('title') + '_custom_' + str(uuid.uuid1())
					service_kpi_from_title_map[kpi.get('title')]['base_service_template_id'] = ''
				new_kpi = copy.deepcopy(kpi)
				service_interface.add_required_fields_to_new_kpi_from_servcie_template(new_kpi, service_template.get('_key'))
				service['kpis'].append(new_kpi)
			else:
				# use old kpi title in service template, to find mapping in service
				old_kpi_title = old_kpi_key_to_title_map[kpi['_key']]

				self.logger.debug(
					'Updating the kpi="%s" in linked_service="%s", after update of service_template="%s".'
					'transaction_id="%s"',
					kpi.get('_key'), service.get('_key'), service_template.get('_key'), transaction_id
				)
				# kpi update case
				if old_kpi_title in service_kpi_from_title_map:
					# service template kpi exists in services. hence, update kpi
					original_kpi_key = service_kpi_from_title_map[old_kpi_title].get('_key')
					original_kpi_urgency = service_kpi_from_title_map[old_kpi_title].get('urgency', '5')
					threshold_fields = ItsiKpi.get_kpi_threshold_fields()

					# handle KPI thresholds
					self.logger.debug(
						'overwrite_kpi_thresholds="%s", while updating linked service with service template content. '
						'service_template_id="%s", service_id="%s", transaction_id="%s"' %
						(overwrite_kpi_thresholds, service_template.get('_key'), service.get('_key'), transaction_id)
					)
					update_flag = True
					changed = service_kpi_from_title_map[old_kpi_title].get('linked_kpi_thresholds_updated', False)
					temp_kpi = copy.deepcopy(kpi)
					for field in threshold_fields:
						temp_kpi.pop(field, None)
						# we need to perform KPI thresholds update by going through each threshold attribute in KPI. As,
						# some of the thresholds attributes in KPI are dicts, which contain list of threshold levels.
						# Therefore, update operation on KPI dict, would not work correctly in case of removal of threshold
						# levels, as update operation on dict would only add new information, but not delete existing
						# information from dict.
						if overwrite_kpi_thresholds == 'all' or (overwrite_kpi_thresholds == 'unchanged' and not changed):
							service_kpi_from_title_map[old_kpi_title][field] = copy.deepcopy(kpi.get(field, ''))

						# if content of service KPI thresholds and service template KPI thresholds is same, then remove
						# the linked_kpi_thresholds_updated flag
						if changed and update_flag and service_kpi_from_title_map[old_kpi_title].get(field, '') != kpi.get(field, ''):
							update_flag = False

					if overwrite_kpi_thresholds == 'unchanged' and changed:
						self.logger.debug(
							'Found KPI with changed thresholds in linked service. Not updating KPI\'s thresholds with service '
							'template KPI\'s thresholds updates. service_id="%s", kpi="%s", service_template_id="%s", transaction_id="%s"'
							% (service.get('_key'), kpi.get('title'), service_template.get('_key'), transaction_id)
						)

					service_kpi_from_title_map[old_kpi_title].update(temp_kpi)
					del temp_kpi

					if update_flag:
						service_kpi_from_title_map[old_kpi_title].pop('linked_kpi_thresholds_updated', None)

					# if overwrite_health_scores is False, restore old urgency field
					if not overwrite_health_scores:
						service_kpi_from_title_map[old_kpi_title]['urgency'] = original_kpi_urgency

					service_kpi_from_title_map[old_kpi_title]['_key'] = original_kpi_key
					service_kpi_from_title_map[old_kpi_title]['base_service_template_id'] = service_template.get('_key')

					# pop the service KPI key which maps to service template KPI
					service_kpis_linked_to_template.pop(original_kpi_key, None)
				else:
					# service template kpi does not exist in service. possibly, coz user deleted it.
					# therefore, simply append as new kpi
					new_kpi = copy.deepcopy(kpi)
					service_interface.add_required_fields_to_new_kpi_from_servcie_template(new_kpi, service_template.get('_key'))
					service['kpis'].append(new_kpi)

		# deleted kpi case
		for deleted_kpi_key in deleted_kpi_keys:
			deleted_kpi_title = old_kpi_key_to_title_map.get(deleted_kpi_key)
			if deleted_kpi_title in service_kpi_from_title_map and \
						service_kpi_from_title_map[deleted_kpi_title].get('base_service_template_id', '') == \
						service_template.get('_key'):
				self.logger.debug(
					'Deleting the kpi="%s" from linked_service="%s", after update of service_template="%s". transaction_id="%s"',
					deleted_kpi_key, service.get('_key'), service_template.get('_key'), transaction_id
				)
				# pop the service kpi key which is being deleted, from service kpis map
				service_kpis_linked_to_template.pop(service_kpi_from_title_map[deleted_kpi_title].get('_key'), None)

				service['kpis'].remove(service_kpi_from_title_map[deleted_kpi_title])

		# now, whatever is left in `service_kpis_linked_to_template` map is/are stale
		# service KPI(s) linked to template. delete all of them.
		for kpi_key, kpi_title in service_kpis_linked_to_template.iteritems():
			if kpi_title in service_kpi_from_title_map:
				kpi_to_delete = service_kpi_from_title_map[kpi_title]
				if kpi_to_delete.get('_key') == kpi_key and kpi_to_delete.get('base_service_template_id'):
					self.logger.debug(
						'Deleting stale kpi="%s" linked to service_template="%s", from service="%s" ". transaction_id="%s"',
						kpi_key, service_template.get('_key'), service.get('_key'), transaction_id
					)
					service['kpis'].remove(kpi_to_delete)

	@staticmethod
	def _update_service_template_status(service_template, sync_status, last_sync_error=''):
		"""
		Update service template sync status

		@type service_template: dict
		@param service_template: service template object from which service has to be updated
		@type sync_status: string
		@param sync_status: sync status of service template
		@type last error: string
		@param deleted_kpi_keys: error message if service template sync fails. default to empty string
		@return: None
		"""
		service_template['sync_status'] = sync_status
		service_template['last_sync_error'] = last_sync_error

	@staticmethod
	def _cleanup_scheduled_job_fields(service_template):
		"""
		Cleans up scheduled for later push fields
		@type service_template: dict
		@param service_template: service template updated
		@return: None
		"""
		service_template.pop('scheduled_time', None)
		service_template.pop('scheduled_job', None)

