# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import copy
import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_kpi import ItsiKpi, ANOMALY_DETECTION_ATTRBUTES, GENERATED_SEARCH_ATTRIBUTES, BACKFILL_ATTRIBUTES
from ITOA.datamodel_interface import DatamodelInterface
from ITOA.storage import itoa_storage
from ITOA.itoa_exceptions import ItoaDatamodelContextError
from itsi.objects.itsi_kpi_base_search import ItsiKPIBaseSearch, \
	BASE_SEARCH_KPI_ATTRIBUTES, BASE_SEARCH_METRIC_KPI_ATTRIBUTES
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.objects.itsi_backup_restore import ItsiBackupRestore

logger = utils.get_itoa_logger('itsi.object.base_service_template')


class ItsiBaseServiceTemplate(ItoaObject):
	"""
	Implements ITSI Service Template ItoaObject methods
	"""

	def __init__(self, session_key, current_user_name):
		super(ItsiBaseServiceTemplate, self).__init__(session_key,
													  current_user_name,
													  'base_service_template',
													  collection_name='itsi_base_service_template',
													  is_securable_object=True)
		self.service_interface = ItsiService(self.session_key, self.current_user_name)
		self.services = {}

		# used to skip service template processing for services
		# this flag is only used in the backup and restore case for the base service template object.
		self.skip_service_template_update = False
		self.persisted_service_template_map = {}

##################################################
# Helper methods
##################################################

	def _validate_payload(self, owner, objects, method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
		"""
		Perform validation on Base Service Template object payload, before processing
		it and saving to kvstore.

		@type owner: basestring
		@param owner: request owner. "nobody" or some username.

		@type objects: list
		@param objects: List of base service template type objects

		@type method: basestring
		@param method: operation type. Defaults to upsert.

		@type transaction_id: basestring
		@param transaction_id: transaction id for end-end tracing.
		"""
		logger.info('Validating payload to upsert Base Service Template object(s). transaction_id="%s"', transaction_id)

		if method in (CRUDMethodTypes.METHOD_UPSERT, CRUDMethodTypes.METHOD_UPDATE):
			# in case of upsert, we can use service validation utility to validate a base service template
			self.service_interface.validate_kpis(owner, objects, method, transaction_id, for_base_service_template=True)
			# check if all kpis are shared base kpis in update request
			# Note: we might allow cloning an adhoc/datamodel kpi in service template payload in the future
			for object in objects:
				# since service and kpi object are already validated above, we skip it here
				for kpi in object.get('kpis', []):
					if kpi.get('search_type') != 'shared_base':
						self.raise_error_bad_validation(logger, 'Invalid kpi type for updating service template. '
																'Expected only shared base search kpis, '
																'received {}.'.format(kpi.get('search_type')))

		elif method == CRUDMethodTypes.METHOD_CREATE:
			# A new base service template can be created from a service or from an existing service template (clone operation).
			# Therefore, only performing the validation on payload sent by UI for creation of template.
			# Since, base service template is a templatized service
			# (already in kvstore), no need to perform the validation on the created base service template.

			if not utils.is_valid_list(objects):
				self.raise_error_bad_validation(logger, 'Invalid data for creating the service template. '
														'Expected a list of json object, received {}.'.format(type(objects).__name__))
			for object in objects:
				if not isinstance(object, dict):
					self.raise_error_bad_validation(logger, 'Invalid data for creating service template '
															'from service. Expected a json object, '
															'received {}.'.format(type(objects).__name__))

				service_id = object.get('service_id', None)
				base_service_template_id = object.get('base_service_template_id', None)
				if service_id is None and base_service_template_id is None:
					self.raise_error_bad_validation(logger,
													'service_id or base_service_template_id field is required to create'
													'a service template.')

	@staticmethod
	def _cleanup_base_service_template_content(base_service_template):
		"""
		Cleanup fields from base service templates, which are redundant.
		@param base_service_template: base service template object
		"""
		keys_to_cleanup = ['reschedule_sync_msg']
		if not len(base_service_template.get('serviceTemplateId', '')) > 0:
			keys_to_cleanup.append('serviceTemplateId')

		for k in keys_to_cleanup:
			base_service_template.pop(k, None)

		logger.debug('Cleaned up fields="%s", from service_template="%s"',
					 keys_to_cleanup, base_service_template.get('_key', ''))

	@staticmethod
	def _cleanup_base_kpi_template_content(base_service_template):
		"""
		Cleanup fields from KPIs in base service templates, which are redundant.
		@param base_service_template: base service template object
		"""
		base_kpi_templates = base_service_template.get('kpis', [])

		for kpi_template in base_kpi_templates:
			keys_to_cleanup = GENERATED_SEARCH_ATTRIBUTES + ANOMALY_DETECTION_ATTRBUTES + BACKFILL_ATTRIBUTES +\
								['service_id', 'enabled', 'type', 'linked_kpi_thresholds_updated']

			if kpi_template.get('search_type', '') != 'shared_base':
				keys_to_cleanup.extend(['base_search_metric', 'base_search_id'])
			if kpi_template.get('search_type', '') != 'datamodel':
				keys_to_cleanup.extend(['datamodel', 'datamodel_filter'])
			if kpi_template.get('kpi_template_kpi_id', None) == '':
				keys_to_cleanup.extend(['kpi_template_kpi_id'])

			for k in keys_to_cleanup:
				kpi_template.pop(k, None)
			logger.debug(
				'Cleaned up fields="%s", from kpi="%s" in service_template="%s"',
				keys_to_cleanup, kpi_template.get('_key', ''), base_service_template.get('_key', '')
			)

	@staticmethod
	def _if_kpis_updated(old_kpis, new_kpis):
		"""
		Compares new kpis with persisted kpis of service template,
		to determine if kpis are being changed in update request or not.

		@type old_kpis: list of dict
		@param old_kpis: kpis in persisted service template
		@type new_kpis: list of dict
		@param new_kpis: kpis in update request for service template
		@return: bool
		"""
		kpis_updated = False
		if len(old_kpis) != len(new_kpis):
			kpis_updated = True
		else:
			for old_kpi, new_kpi in zip(old_kpis, new_kpis):
				if new_kpi.get('_key') != old_kpi.get('_key'):
					kpis_updated = True
					break
				elif new_kpi != old_kpi:
					kpis_updated = True
					break
		return kpis_updated

	@staticmethod
	def _normalize_overwrite_kpi_thresholds_flag(flag):
		"""
		Normalizes overwrite_kpi_thresholds flag value.
		@param flag:
		@return:
		"""
		value = 'none'
		if isinstance(flag, basestring):
			if flag.lower() == 'all':
				value = 'all'
			elif flag.lower() == 'unchanged':
				value = 'unchanged'
		return value

	def _get_linked_services_update_job(self, service_template, persisted_service_template_map, transaction_id=None):
		"""
		Checks if update of service template requires refresh of linked services. If so, returns
		list of refresh jobs for service template (typically one job). If not, returns empty list.

		@type service_template: dict
		@param service_template: service template object for which update is requested
		@type persisted_service_template_map: dict
		@param persisted_service_template_map: persisted service template map in kvstore for which
				update is requested
		@type transaction_id: string
		@param transaction_id: for instrumentation purposes
		@return: list of refresh jobs to update services linked to template
		"""
		linked_services_update_jobs = []
		change_type = 'base_service_template_update'
		overwrite_entity_rules = utils.normalize_bool_flag(service_template.get('overwrite_entity_rules', False))
		overwrite_health_scores = utils.normalize_bool_flag(service_template.get('overwrite_health_scores', False))
		overwrite_kpi_thresholds = self._normalize_overwrite_kpi_thresholds_flag(
			service_template.get('overwrite_kpi_thresholds', 'none')
		)

		if len(service_template.get('linked_services', [])) > 0:

			old_kpis = persisted_service_template_map.get(service_template.get('_key'), {}).get('kpis', [])
			# if overwrite flag for health score or thresholds is set, consider, kpi update is required.
			# no need to perform old kpis and new kpis comparison to find out, if kpis actually changed.
			# as, user may want to revert linked services to service template without making any
			# changes to template.
			if overwrite_health_scores or overwrite_kpi_thresholds.strip().lower() in ('all', 'unchanged'):
				kpi_update_required = True
			else:
				new_kpis = service_template.get('kpis', [])
				kpi_update_required = self._if_kpis_updated(old_kpis, new_kpis)

			if kpi_update_required or overwrite_entity_rules:
				if overwrite_entity_rules:
					logger.debug('Entity rules update is needed for services linked to service template. service_template="%s". '
								 'transaction_id="%s"', service_template.get('_key'), transaction_id)

				change_detail = {
					service_template.get('_key'): {
						'kpi_update_required': kpi_update_required,
						'overwrite_health_scores': overwrite_health_scores,
						'overwrite_kpi_thresholds': overwrite_kpi_thresholds,
						'overwrite_entity_rules': overwrite_entity_rules
					}
				}
				if kpi_update_required:
					logger.debug('KPIs update is needed for services linked to service template. service_template="%s". '
								 'transaction_id="%s"', service_template.get('_key'), transaction_id)
					old_kpi_key_to_title_map = {}
					for old_kpi in old_kpis:
						old_kpi_key_to_title_map[old_kpi['_key']] = old_kpi.get('title')
					change_detail[service_template.get('_key')]['old_kpis'] = copy.deepcopy(old_kpi_key_to_title_map)

				linked_services_update_jobs.append(
					self.get_refresh_job_meta_data(
						change_type,
						service_template.get('_key'),
						self.object_type,
						change_detail,
						transaction_id
					)
				)

				if not service_template.get('scheduled_time', False):
					logger.info('Added refresh job of type base_service_template_update, to push out service '
								'template changes to its linked services. service_template="%s", transaction_id="%s"',
								service_template.get('_key'), transaction_id)

		return linked_services_update_jobs

	def _convert_adhoc_datamodel_search(self, owner, templatized_service, service_to_update):
		"""
		Convert adhoc search and data model search into shared base search. Update service template and service object at the same time

		@type owner: basestring
		@param owner: request owner. "nobody" or some username
		@type templatized_service: dict
		@param templatized_service: service template object
		@type service_to_update: dict
		@param service_to_update: service object in kvstore
		@return: None. Raise error if soomething goes wrong
		"""
		def _generate_kpi_base_search_title(service_title, kpi_title, kpi_key):
			"""
			Generate kpi base search title
	
			@type service_title: basestring
			@param service_title: service title
			@type kpi_title: basestring
			@param kpi_title: kpi title
			@type kpi_key: basestring
			@param kpi_key: kpi key
			@return: basestring. Generated Kpi base search title
			"""
			# enforce a limit on title length and add the last 8 digits of kpi key to avoid duplicate title
			return "{}:{}_{}".format(service_title,
									 kpi_title,
									 kpi_key[:8])

		kpi_map = {}

		for kpi in service_to_update.get('kpis', []):
			if kpi.get('_key', '').startswith(self.service_interface.shkpi_starts_with):
				continue
			kpi_map[kpi.get('title')] = kpi

		for kpi in templatized_service.get('kpis', []):

			if kpi.get('search_type') == 'shared_base':
				continue

			# Create a kpi base search from adhoc search
			kpi_base_search = ITOAInterfaceUtils.generate_kpi_base_search()
			kpi_base_search_id = ITOAInterfaceUtils.generate_backend_key()
			kpi_base_search['_key'] = kpi_base_search_id
			kpi_base_search['title'] = _generate_kpi_base_search_title(templatized_service.get('title'), kpi.get('title'), kpi.get('_key'))

			# Copy common fields from kpi
			common_fields = BASE_SEARCH_KPI_ATTRIBUTES + ['description']
			common_fields.remove('sec_grp')

			metric_fields = BASE_SEARCH_METRIC_KPI_ATTRIBUTES

			for common_field in common_fields:
				# alert_period has to be explicitly converted to str or the kpi load fails
				# Please note the inconsisitency between alert_period in adhoc kpi (int) and shared base kpi (string)
				if common_field == 'alert_period':
					kpi_base_search[common_field] = str(kpi.get(common_field, ''))
				else:
					kpi_base_search[common_field] = kpi.get(common_field, '')

			# Create metric.
			# For now, a new kpi base search is created for every kpi.
			# The performance could be further improved by merging similar base searches into one
			# This is out of the scope of PBL-12547
			metric = {}
			metric_key = ITOAInterfaceUtils.generate_backend_key()
			for metric_field in metric_fields:
				metric[metric_field] = kpi.get(metric_field, '')
				metric['title'] = '{}({})'.format(kpi.get('aggregate_statop', ' '), kpi.get('threshold_field', ' '))
				metric['_key'] = metric_key

			if 'metrics' in kpi_base_search:
				kpi_base_search['metrics'].append(metric)
			else:
				kpi_base_search['metrics'] = [metric]

			# Special handling for datamodel search
			if kpi.get('search_type') == 'datamodel':
				if not utils.is_valid_dict(kpi.get('datamodel')):
					self.raise_error_bad_validation(logger, "Invalid datamodel defined for KPI {}".format(kpi.get('title')))

				datamodel = kpi.get('datamodel').get('datamodel')
				datamodel_obj = kpi.get('datamodel').get('object')

				datamodel_dict = DatamodelInterface.get_datamodel(self.session_key,
																  '',
																  itoa_storage.ITOAStorage().get_app_name(),
																  datamodel
																  )

				dm = datamodel_dict.get(datamodel)
				if dm is None:
					message = _("Could not locate specified datamodel {}").format(datamodel)
					logger.error(message)
					raise ItoaDatamodelContextError(message, logger)
				dm_objects = dm['objects']
				for object in dm_objects:
					if object.get('objectName') == datamodel_obj:
						break

				# Use ObjectSearch String
				# If datamodel filter exists, append it to the search string
				search_string = object.get('objectSearch')
				if kpi.get('datamodel_filter_clauses'):
					search_string +=  ' | search ' +  kpi['datamodel_filter_clauses']
				kpi_base_search['base_search'] = search_string

			# save kpi base search
			kpi_base_search_interface = ItsiKPIBaseSearch(self.session_key, self.current_user_name)
			kpi_base_search_interface.create(owner, kpi_base_search)

			logger.debug('kpi base search ="{}" is created from kpi ="{}", service = "{}"'.format(kpi_base_search['title'],
																								  kpi.get('title'),
																								  service_to_update.get('title')))

			# update kpi object
			# no need to generate searches since it's generated automatically
			for each_kpi in [kpi, kpi_map[kpi.get('title')]]:
				each_kpi['search_type'] = 'shared_base'
				each_kpi['base_search_id'] = kpi_base_search_id
				each_kpi['base_search_metric'] = metric_key
				each_kpi['base_search'] = kpi_base_search['base_search']

			logger.info('successfully converted kpi = "{}" in service = "{}" to kpi base search ="{}"'.format(kpi.get('title'),
																											  service_to_update.get('title'),
																											  kpi_base_search['title']))

	def generate_persisted_service_template_map(self, owner, objects, transaction_id=None):
		"""
		Utility function to generate persisted service template map. It's shared by do_addtional_setup and identify_dependencies
		@type owner: basestring
		@param owner: request owner. "nobody" or some username.

		@type objects: list
		@param objects: List of base service template type objects

		@type transaction_id: basestring
		@param transaction_id: transaction id for end-end tracing.
		"""
		templates_get_filter = {
			'$or': []
		}
		templates_keys_list = []
		for service_template in objects:
			templates_get_filter['$or'].append({
				'_key': service_template.get('_key')
			})
			templates_keys_list.append(service_template.get('_key'))

		if len(templates_get_filter['$or']) > 0:
			persisted_service_templates = self.get_bulk(
				owner, filter_data=templates_get_filter,
				fields=['_key', 'kpis', 'entity_rules', 'linked_services', 'sync_status'], transaction_id=transaction_id
			)
		for service_template in persisted_service_templates:
			self.persisted_service_template_map[service_template.get('_key')] = service_template

##################################################
# ItoaObject specific methods
##################################################

	def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
		"""
		Any additional setup to be done for Base Service Template object(s).
		@type owner: basestring
		@param owner: request owner. "nobody" or some username.

		@type objects: list
		@param objects: List of base service template type objects

		@type req_source: basestring
		@param req_source: Source requesting this operation.

		@type method: basestring
		@param method: operation type. Defaults to upsert.

		@type transaction_id: basestring
		@param transaction_id: transaction id for end-end tracing.
		"""
		self._validate_payload(owner, objects, method, transaction_id)

		if method in (CRUDMethodTypes.METHOD_UPDATE, CRUDMethodTypes.METHOD_UPSERT):
			self.generate_persisted_service_template_map(owner, objects, transaction_id)

		for object in objects:
			"""
			User can create a base service template from a service or from a service template Therefore, creation payload
			will look something like below:
			eg. {
					'service_id': <key_of_service_to_create_template_from>, 
					'title': 'new_base_service_template', 
					'_owner': 'nobody', 
					'sec_grp': <key_of_sec_grp>,
					....
				}
			i.e either 'service_id' or 'base_service_template_id' need to be present in the request payload.
			"""

			def _add_sync_status_metadata(service_template_object):
				"""
				Adds sync_status('synced') and last_sync_error('') to the service template object being created
				@type service_template_object: dict
				@param service_template_object: object that needs to be created
				"""
				service_template_object['sync_status'] = 'synced'
				service_template_object['last_sync_error'] = ''

			def _overwrite_title_and_description(request_object, service_template_object):
				"""
				Overwrites the title and description of the service template object with the fields from the request object
				@type request_object: dict
				@param request_object: request object
				@type: service_template_object: dict
				@param service_template_object: object that needs to be updated
				"""
				service_template_object['title'] = request_object.get('title', '')
				service_template_object['description'] = request_object.get('description', '')

			if method == CRUDMethodTypes.METHOD_CREATE:

				# if 'base_service_template_id' and 'service_id' are both present, we will treat it as a clone operation.
				# This assumption is made since the base_service_template_id is not part of the service template object,
				# it needs to be explicitly provided which means its an intended clone operation.

				base_service_template_id = object.get('base_service_template_id', None)
				if base_service_template_id:
					logger.debug('Clonining base service template base_service_template_id="%s" to create base service template. '
								 'transaction_id="%s"', base_service_template_id, transaction_id)
					cloned_service_template = self._clone_base_service_template(owner, base_service_template_id,
																				req_source, transaction_id )

					# update the object with templatized service
					object.update(cloned_service_template)

					# remove 'base_service_template_id' field from the request object
					object.pop('base_service_template_id', None)
					# remove 'service_id' from the request since we have handled this as a clone operation
					object.pop('service_id', None)
				else:
					service_id = object.get('service_id', None)
					logger.debug('Templatizing service_id="%s" to create base service template. '
								 'transaction_id="%s"', service_id, transaction_id)

					templatized_service = self.service_interface.templatize(owner, service_id, req_source=req_source,
																				for_base_service_template=True)

					service_to_update = self.service_interface.get(owner, service_id, req_source=req_source,
												   transaction_id=transaction_id)

					if templatized_service is None:
						self.raise_error_bad_validation(logger, 'Could not find service object with id `{}`. Cannot create base '
														'service template from non-existent service'.format(service_id))

					# Convert adhoc searches and data model searches to shared base search
					self._convert_adhoc_datamodel_search(owner, templatized_service, service_to_update)

					self.services[service_to_update.get('_key')] = service_to_update

					# link service to template
					templatized_service['linked_services'] = []
					templatized_service['linked_services'].append(service_id)

					# overwrite title and description from the request
					_overwrite_title_and_description(object, templatized_service)

					# update the object with templatized service
					object.update(templatized_service)

				# add sync status metadata to the updated object
				_add_sync_status_metadata(object)


			# set the value field for entity rule_item to empty string for rule_type matchesblank or notmatchesblank
			def _set_value_for_blank_entity_rule_types(template_object):
				for entity_rule in template_object.get('entity_rules', []):
					for rule_item in entity_rule.get('rule_items', []):
						if rule_item.get('rule_type', None) == 'matchesblank' or rule_item.get('rule_type',
																							   None) == 'notmatchesblank':
							rule_item['value'] = ''

			_set_value_for_blank_entity_rule_types(object)

			if not len(object.get('entity_rules', [])) > 0:
				object['entity_rules'] = []

			# cleanup service and kpi content.
			ItsiBaseServiceTemplate._cleanup_base_service_template_content(object)
			ItsiBaseServiceTemplate._cleanup_base_kpi_template_content(object)

			# replace linked_services and sync_status fields with the value stored in kvstore
			if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:
				if not self.skip_service_template_update and object.get('_key') in self.persisted_service_template_map:
					object['linked_services'] = self.persisted_service_template_map[object.get('_key')].get('linked_services', [])
					object['sync_status'] = self.persisted_service_template_map[object.get('_key')].get('sync_status', 'synced')

			object['total_linked_services'] = len(object['linked_services'])

			# generate key for new base service template
			if not utils.is_valid_str(object.get('_key', '')):
				object['_key'] = ITOAInterfaceUtils.generate_backend_key()

		logger.info('Completed additional setup to upsert Base Service Template objects. transaction_id="%s"', transaction_id)

	def _clone_base_service_template(self,owner, base_service_template_id, req_source, transaction_id):
		"""
		Clones the base service template with id base_service_template_id. Removes fields that should not be part of the clone
		Regenerates _key for all kpis.
		@type ownner: basestring
		@param owner: 'nodoby' or user performing the operation

		@type base_service_template_id: basestring
		@param base_service_template_id: service template id that is to be cloned

		@type req_source: basestring
		@param req_source: request source

		@type transaction_id: basestring
		@param transaction_id: transaction id for end-end tracing

		@rtype: object
		@return:
			{object}: cloned base service template object
		"""
		base_service_template_to_clone = self.get(owner, base_service_template_id, req_source=req_source,
													   transaction_id=transaction_id)

		if base_service_template_to_clone is None:
			self.raise_error_bad_validation(logger, 'Could not find service template object with id `{}`. Cannot create base '
													'service template from non-existent service template'.format(base_service_template_id))

		# clean up keys not required in the new service template object and the ones we want to retain from the request
		# NOTE: we will not retain the 'service_id' field since this template is not created from a service
		# NOTE: not removing sec_grp, since for service template it should always be global and cannot be changed
		internal_fields = [key for key in base_service_template_to_clone.keys() if key.startswith('mod_')]
		internal_fields += ['acl', '_user', '_owner']
		keys_to_cleanup = ['_key', 'linked_services', 'service_id', 'base_service_template_id', 'title', 'description',
						   'identifying_name', 'scheduled_time', 'scheduled_job'] + internal_fields
		for key in keys_to_cleanup:
			base_service_template_to_clone.pop(key, None)
		base_service_template_to_clone['linked_services'] = []

		for kpi in base_service_template_to_clone.get('kpis', []):
			kpi['_key'] = ITOAInterfaceUtils.generate_backend_key()

		return base_service_template_to_clone

	def identify_dependencies(self, owner, base_service_templates, method, req_source='unknown', transaction_id=None):
		"""
		Identity dependencies of service templates and add refresh jobs.
		NOTE: one refresh job is being added for each service template update, as there could
		be 100s of linked services to be updated after service template update.

		@type owner: basestring
		@param {string} owner: user which is performing this operation
		@type base_service_templates: list
		@param base_service_templates: service templates to validate for dependency
		@type method: basestring
		@param method: method name
		@type req_source: basestring
		@param req_source: request source
		@rtype: tuple
		@return:
			{boolean} set to true/false if dependency update is required
			{list} list - list of refresh job
		"""
		refresh_jobs = []

		if self.skip_service_template_update:
			return len(refresh_jobs) > 0, refresh_jobs

		if not self.persisted_service_template_map and method in (CRUDMethodTypes.METHOD_UPDATE, CRUDMethodTypes.METHOD_UPSERT, CRUDMethodTypes.METHOD_DELETE):
			self.generate_persisted_service_template_map(owner, base_service_templates, transaction_id)

		if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:

			for service_template in base_service_templates:
				refresh_job = self._get_linked_services_update_job(service_template, self.persisted_service_template_map,
																   transaction_id=transaction_id)

				# update service template to scheduled if there are linked services
				if refresh_job:
					service_template['sync_status'] = 'sync scheduled'

					backup_restore_interface = ItsiBackupRestore(self.session_key, self.current_user_name)
					if backup_restore_interface.is_any_backup_restore_job_in_progress(owner, req_source=req_source):
						if not service_template.get('scheduled_time'):
							# if backup/restore is in progress, reschedule the sync job from
							# current time to a later time
							service_template['scheduled_time'] = utils.get_current_utc_epoch()
							# set localized message
							service_template['reschedule_sync_msg'] = _('Service template changes cannot be pushed now'
																		' because a backup/restore is currently in '
																		'progress. The service template sync has been '
																		'scheduled for a later time.')

					if service_template.get('scheduled_time'):
						# refresh queue job processor requires changed_object_key to be a list
						# manually convert it here
						refresh_job[0]['changed_object_key'] = [refresh_job[0]['changed_object_key']]
						# we don't want to overwrite an existing scheduled job completely, as we might loose
						# some information in change_detail needed for correctly updating linked services
						if service_template.get('scheduled_job'):
							persisted_change_detail = service_template['scheduled_job'].get('change_detail', {})
							new_change_detail = refresh_job[0].get('change_detail', {})
							template_key = service_template.get('_key')
							if template_key in persisted_change_detail:
								# only update old_kpis dict, if last service template update did not
								# update any of KPIs content
								if not persisted_change_detail[template_key].get('kpi_update_required', False):
									persisted_change_detail[template_key]['old_kpis'] = \
										new_change_detail.get(template_key).get('old_kpis', {})

								if persisted_change_detail[template_key].get('kpi_update_required', False) or \
									new_change_detail.get(template_key).get('kpi_update_required', False):

									persisted_change_detail[template_key]['kpi_update_required'] = True
								else:
									persisted_change_detail[template_key]['kpi_update_required'] = False

								# always update all the overwrite options provided by user
								persisted_change_detail[template_key]['overwrite_entity_rules'] = \
									new_change_detail.get(template_key).get('overwrite_entity_rules', False)
								persisted_change_detail[template_key]['overwrite_health_scores'] = \
									new_change_detail.get(template_key).get('overwrite_health_scores', False)
								persisted_change_detail[template_key]['overwrite_kpi_thresholds'] = \
									new_change_detail.get(template_key).get('overwrite_kpi_thresholds', 'none')
							# no change details found for previously scheduled job. overwrite it completely
							else:
								service_template['scheduled_job'] = refresh_job[0]
						# there's no previously defined scheduled job, which has not executed yet.
						else:
							service_template['scheduled_job'] = refresh_job[0]
					else:
						refresh_jobs.extend(refresh_job)
						service_template.pop('scheduled_job', None)

				service_template.pop('overwrite_health_scores', None)
				service_template.pop('overwrite_kpi_thresholds', None)
				service_template.pop('overwrite_entity_rules', None)
				service_template.pop('is_scheduled', None)

			logger.info('Total refresh jobs added after update of service template objects = %s. transaction_id="%s".'
						 ' updated_service_templates="%s"', len(refresh_jobs), transaction_id,
						[service_template.get('_key') for service_template in base_service_templates])

		if method == CRUDMethodTypes.METHOD_DELETE:
			change_type = 'delete_base_service_template'
			linked_services_map = {}
			deleted_service_template_ids = []
			for service_template in self.persisted_service_template_map.values():
				deleted_service_template_ids.append(service_template['_key'])
				linked_services_map[service_template['_key']] = service_template.get('linked_services', [])

			if len(deleted_service_template_ids) > 0:
				refresh_jobs.append(
					self.get_refresh_job_meta_data(
						change_type,
						deleted_service_template_ids,
						self.object_type,
						change_detail=linked_services_map,
						transaction_id=transaction_id
					)
				)
				logger.info('Added refresh job of type delete_base_service_template, to unlink or delete services '
							'linked to deleted service template(s). service_template="%s", transaction_id="%s"',
							deleted_service_template_ids, transaction_id)
		return len(refresh_jobs) > 0, refresh_jobs

	def post_save_setup(self, owner, ids, base_service_templates, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
		"""
		Link service to service template after creating service template from service.
		NOTE: Not needed in case of create of service template from service template (clone). In this case 'service_id' is None
		NOTE: Not needed in case of update of service template.

		@type owner: string
		@param owner: user who is performing this operation
		@type ids: List of dict identifiers in format {"_key": <key>} returned by kvstore, pairity with objects passed in
		@param ids: list of dict
		@type base_service_templates: list of dictionary
		@param base_service_templates: list of objects being written
		@type req_source: string
		@param req_source: string identifying source of this request
		@type method: string
		@param method: method name
		@type transaction_id: basestring
		@param transaction_id: transaction id for instrumentation purposes.
		@return: none, throws exceptions on errors
		"""
		# NOTE: Assuming, we don't support bulk creation of service templates through this endpoint.
		# If we start supporting bulk creation of service templates, then we would have to handle linking of
		# services in bulk to created service templates (synchronously/asynchronously depending on performance).
		if method == CRUDMethodTypes.METHOD_CREATE:
			# Looping through the list, even though there would only be one service template
			# in the list, as we're only addressing CREATE request here.
			for service_template in base_service_templates:
				service_template_to_unlink = None
				service_id = service_template.get('service_id', None)
				service_template_id = service_template.get('_key')

				service_to_update = self.services.get(service_id) if service_id else None

				if service_id and service_to_update is None:
					self.raise_error_bad_validation(logger, 'Could not find cached service `{}`. Please debug.'.format(service_id))

				if not service_to_update:
					logger.info('service_template="%s" created from another service template. No service linkage update '
								'required ', service_template_id)
					continue
				
				if utils.is_valid_str(service_to_update.get('base_service_template_id', '')):
					service_template_to_unlink = service_to_update.get('base_service_template_id')

				service_to_update['base_service_template_id'] = service_template_id
				for kpi in service_to_update.get('kpis', []):
					if kpi.get('_key', '').startswith(self.service_interface.shkpi_starts_with):
						continue
					kpi['base_service_template_id'] = service_template_id

				# enable below flag to skip service template linking by service interface, to avoid circular updates
				# NOTE: Once we start supporting bulk creation of service templates through this endpoint, start
				# using bulk update instead of single update to update services with the link to service template.
				self.service_interface.skip_service_template_update = True
				self.service_interface.update(owner, service_id, service_to_update, transaction_id=transaction_id)

				logger.info('service="%s" linked to service template, after creation '
							'of service_template="%s"', service_id, service_template_id)

				# if service used for template creation was previously linked to another template, unlink that
				# service template from the service.
				if service_template_to_unlink:
					previously_linked_template = self.get(owner, service_template_to_unlink, req_source=req_source,
														  transaction_id=transaction_id)

					updated_linked_services = [linked_service for linked_service in
											   previously_linked_template.get('linked_services', [])
											   if linked_service != service_id]
					previously_linked_template['linked_services'] = updated_linked_services
					self.skip_service_template_update = True
					self.update(owner, service_template_to_unlink, previously_linked_template, transaction_id=transaction_id)
					self.skip_service_template_update = False

					logger.info('service="%s" which was used to create service_template="%s", was previously linked to '
								'another service template. Previously linked service template %s, has been unlinked from'
								' the service.', service_id, service_template_id, service_template_to_unlink)

	def save_batch(
			self,
			owner,
			service_templates_list,
			validate_names,
			dupname_tag=None,
			req_source='unknown',
			ignore_refresh_impacted_objects=False,
			method=CRUDMethodTypes.METHOD_UPSERT,
			is_partial_data=False,
			transaction_id=None):
		"""
		Only address bulk update requests. If, request is for bulk creation of service templates,
		then raise error.

		@type owner: string
		@param owner: user who is performing this operation
		@type service_templates_list: list
		@param service_templates_list: list of objects to upsert
		@type validate_names: bool
		@param validate_names: validate_names is a means for search commands and csv load to by pass
								perf hit from name validation in scenarios they can safely skip
		@type req_source: string
		@param req_source: string identifying source of this request
		@type is_partial_data: bool
		@param is_partial_data: indicates if payload passed into each entry in data_list is a subset of object structure
			when True, payload passed into data is a subset of object structure
			when False, payload passed into data is the entire object structure
			Note that KV store API does not support partial updates
			This argument only applies to update entries since on create, entire payload is a MUST
		@rtype: list of strings
		@return: ids of objects upserted on success, throws exceptions on errors
		"""
		if len(service_templates_list) > 0 and not self.skip_service_template_update:
			get_bulk_filter = {
				'$or': []
			}
			object_key_list = []  # used to skip duplicate keys
			for service_template in service_templates_list:
				# if _key is missing for a service template, assume it's a create request
				if not utils.is_valid_str(service_template.get('_key', '')):
					self.raise_error(logger,
									 'Bulk creation of Service Template objects is not supported or id field '
									 'missing for at least one of the objects in bulk update request.',
									 status_code=405)
				elif service_template.get('_key') not in object_key_list:
					object_key_list.append(service_template.get('_key'))
					get_bulk_filter['$or'].append({
						'_key': service_template.get('_key')
					})

			persisted_service_templates = self.get_bulk(owner, req_source=req_source, filter_data=get_bulk_filter,
														fields=['_key'], transaction_id=transaction_id)

			# if some of the template objects in request do no exist in kvstore.
			# means, it is a create request for some of the objects in requested objects list.
			if len(get_bulk_filter['$or']) > len(persisted_service_templates):
				self.raise_error(logger,
								'Bulk creation of Service Template objects is not supported.',
								status_code=405)

		# if data list contains no service template creation request, then proceed with the normal save batch process.
		result_ids = super(ItsiBaseServiceTemplate, self).save_batch(owner, service_templates_list, validate_names, dupname_tag=dupname_tag,
														req_source=req_source,
														ignore_refresh_impacted_objects=ignore_refresh_impacted_objects,
														method=method, is_partial_data=is_partial_data,
														transaction_id=transaction_id)
		self.skip_service_template_update = False
		return result_ids
