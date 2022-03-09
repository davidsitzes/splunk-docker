# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import splunk
import re
from migration.migration import MigrationFunctionAbstract
from ITOA.setup_logging import setup_logging
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch
from itsi.objects.itsi_kpi import ItsiKpi
from itsi.objects.itsi_entity import ItsiEntity
from ITOA.saved_search_utility import SavedSearch
from itsi.itsi_utils import ITOAInterfaceUtils as utils
import ITOA.itoa_common as itoa_utils
from itsi.itsi_const import ITOAObjConst

logger = setup_logging("itsi_migration.log", "itsi.migration")

REGEX_INVALID_CHARS_IN_FIELDNAMES = re.compile('^\$|[=.,"\']+')

CONFLICTING_FIELDS_VALIDATION_MSG = 'Entities with Info fields conflicting with Alias fields'
EMPTY_FIELD_NAME_MSG = 'Entity/Entities With Empty Identifier And/Or Informational Fields Name'
INVALID_SPECIAL_CHARS_FIELD_NAME_MSG = 'Entity/Entities With Invalid Special Characters In Identifier And/Or Informational Fields'
FIELD_NAME_WITH_INTERNAL_KEYWORDS_MSG = 'Entity/Entities With Identifier And/Or Informational Fields Containing Internal Keywords'
FIELD_DOESN_NOT_EXIST_AT_TOP_LEVEL_MSG = 'Entity/Entities With Identifier And/Or Informational Fields Not Existing At Top-Level'
INCORRECT_FORMAT_FIELD_AT_TOP_LEVEL_MSG = 'Entity/Entities With Top-Level Identifier And/Or Informational Field Values Not In List Format'


def is_inconsistent_entity(entity):
	"""
	Perform the validation to determine if the entity passed in is an inconsistent entity defined in ITSI.
	@param entity: entity object
	@return: True, if entity is inconsistent. Else, False
	"""
	message = ''
	# validate there are no common fields between identifier and info fields
	identifier_fields_set = set(entity.get('identifier', {}).get('fields', []))
	info_fields_set = set(entity.get('informational', {}).get('fields', []))
	common_fields_set = identifier_fields_set.intersection(info_fields_set)
	if common_fields_set:
		message = CONFLICTING_FIELDS_VALIDATION_MSG
		return True, message

	found = False
	# validate identifier and informational fields in entity object
	field_types = ['identifier', 'informational']
	for field_type in field_types:
		if found:
			break
		field_blob = entity.get(field_type, {})
		if not isinstance(field_blob, dict):
			continue
		for field_name in field_blob.get('fields', []):
			if not itoa_utils.is_valid_str(field_name):
				message = EMPTY_FIELD_NAME_MSG
				found = True
				break
			if re.search(REGEX_INVALID_CHARS_IN_FIELDNAMES, field_name):
				message = INVALID_SPECIAL_CHARS_FIELD_NAME_MSG
				found = True
				break
			if field_name in ITOAObjConst.ENTITY_INTERNAL_KEYWORDS:
				message = FIELD_NAME_WITH_INTERNAL_KEYWORDS_MSG
				found = True
				break
			if field_name not in entity:
				message = FIELD_DOESN_NOT_EXIST_AT_TOP_LEVEL_MSG
				found = True
				break
			if not isinstance(entity.get(field_name), list):
				message = INCORRECT_FORMAT_FIELD_AT_TOP_LEVEL_MSG
				found = True
				break

	return found, message


def entity_valid(session_key):
	status = False
	entity_interface = ItsiEntity(session_key, 'nobody')
	entities_in_kvstore = entity_interface.get_bulk('nobody')
	inconsistent_entities = {}
	for entity_object in entities_in_kvstore:
		inconsistent_entity_found, validation_message = is_inconsistent_entity(entity_object)
		if inconsistent_entity_found:
			entity_info = {'title': entity_object.get('title'), '_key': entity_object.get('_key')}
			if validation_message in inconsistent_entities:
				inconsistent_entities[validation_message].append(entity_info)
			else:
				inconsistent_entities[validation_message] = [entity_info]

	if inconsistent_entities:
		logger.info('Here is the list of all the inconsistent entities categorized by the type of inconsistency.')
		for validation_msg in inconsistent_entities:
			logger.info('############  ' + validation_msg + '  ############')
			for inconsistent_entity in inconsistent_entities[validation_msg]:
				logger.info("Entity Key: %s,		Entity Title: %s", inconsistent_entity.get('_key'), inconsistent_entity.get('title'))
		logger.info('## END ##')
		logger.info('Navigate to the Entities lister page (Configure > Entities) and fix the duplications, then restart Splunk.')
	else:
		status = True

	return status

class ServiceTemplateMigrationHandler(MigrationFunctionAbstract):
	"""
	Migration handler to add total_linked_services field to service template object
	"""
	def __init__(self, session_key):
		super(ServiceTemplateMigrationHandler, self).__init__(session_key)
		self.session_key = session_key

	def _fetch_and_migrate(self):
		status = True
		try:
			object_collection = []
			service_templates = self.get_object_iterator('base_service_template')
			for service_template in service_templates:
				service_template['total_linked_services'] = len(service_template.get('linked_services', []))
				utils.remove_illegal_character_from_entity_rules(service_template.get('entity_rules', []))
				object_collection.append(service_template)
			self.save_object('base_service_template', object_collection)

		except Exception, e:
			logger.exception('Fail to update base service templates')
			status = False
		return status

	def execute(self):
		"""
		Method called by migration pipeline. Just a wrapper.
		"""
		return self._fetch_and_migrate()


class ServiceMigrationHandler(MigrationFunctionAbstract):
	"""
	Migration handler to re-create all KPI searches in the savedsearch.conf that has service entity filter
	enabled, so that if the entity terms have value that contain "\", they are replaced by "\\\" on recreation.
	Note: The character "\" is special char in SPL

	AND

	Migration handler to remove 'id' from the entity_rules in the service object
	Note: ITOA-11342 fixes the issue caused by saving the id field in the entity_rules while bulk import
	"""

	def __init__(self, session_key):
		super(ServiceMigrationHandler, self).__init__(session_key)
		self.session_key = session_key

	def _fetch_and_migrate(self):
		"""
		Fetch all the searches
		"""
		base_searches_to_update = []
		status = True
		try:
			object_collection = []
			services = self.get_object_iterator('service')
			for service in services:
				utils.remove_illegal_character_from_entity_rules(service.get('entity_rules', []))
				itsi_kpi = ItsiKpi(self.session_key, "nobody")
				kpis = service.get('kpis', [])
				for kpi in kpis:
					if kpi['search_type'] == 'shared_base' and \
									kpi.get('base_search_id') is not None and \
									kpi.get('base_search_id') not in base_searches_to_update and \
									kpi.get('is_service_entity_filter') is True:
						base_searches_to_update.append(kpi['base_search_id'])

					elif (kpi['search_type'] == 'adhoc' or kpi['search_type'] == 'datamodel') and \
									kpi.get('is_service_entity_filter') is True:
						try:
							saved_search_settings = itsi_kpi.generate_saved_search_settings(kpi,
																							service.get('entity_rules'),
																							service.get('sec_grp'))
							self._create_saved_search(saved_search_settings, acl_update=False)
						except Exception:
							# saved searches will be generated when saving services
							logger.info('Could not generate saved adhoc search for KPI: {}. '
										'This may be okay in non-persistent restore.'.format(kpi['title']))

				object_collection.append(service)

			for bs_id in base_searches_to_update:
				try:
					adhoc_search = ItsiSharedAdhocSearch(self.session_key, bs_id)
					if len(adhoc_search.services) > 0:
						adhoc_search.create_splunk_search(acl_update=False)
				except Exception:
					# saved searches will be generated when saving services
					logger.info('Could not generate saved search for base search : {}. '
								'This may be okay in non-persistent restore.'.format(bs_id))

			self.save_object('service', object_collection)

		except Exception, e:
			logger.exception('Fail to update services')
			status = False
		return status

	def _create_saved_search(self, saved_search_settings, acl_update):
		ret = SavedSearch.update_search(self.session_key, saved_search_settings.get('name'), 'itsi', 'nobody',
										**saved_search_settings)
		if ret:
			# Successfully updated the saved search
			logger.info("Successfully created/update saved search=%s", saved_search_settings.get('name'))
			if acl_update:
				ret = SavedSearch.update_acl(
					self.session_key,
					saved_search_settings.get('name'),
					'nobody')
				if not ret:
					msg = _(
						"ACL update failed for saved search %s. Manual update required.") % saved_search_settings.get(
						'name')
					logger.error(msg)
		else:
			# Search creation failed
			message = _("Failed to create saved search %s.") % saved_search_settings.get('name')
			logger.error(message)
			raise Exception(message)
		return ret

	def execute(self):
		"""
		Method called by migration pipeline. Just a wrapper.
		"""
		return self._fetch_and_migrate()


class MadUriMigrator(MigrationFunctionAbstract):
	"""
	Migration handler to update the URI in the MAD Context Collection.
	With ITSI 3.1.1, the full URI is no longer stored, instead just the URI after the host:port.
	"""
	def __init__(self, session_key):
		super(MadUriMigrator, self).__init__(session_key)
		self.session_key = session_key

	def _fetch_and_migrate(self):
		status = True
		uri = '/servicesNS/nobody/SA-ITSI-MetricAD/metric_ad/contexts'
		response, raw_data = splunk.rest.simpleRequest(uri,
													   method='GET',
													   sessionKey=self.session_key,
													   raiseAllErrors=False)
		try:
			data = json.loads(raw_data)
		except Exception as e:
			logger.info('Failed to load the mad context data')
			return status

		if isinstance(data, list):
			for record in data:
				if isinstance(record, dict):
					name = record.get('name')
					postargs = {
						'metric_limit_url': '/services/event_management_interface/user_message_mad_event',
						'alert_url': '/services/event_management_interface/mad_event_action'
					}
					response, content = splunk.rest.simpleRequest(
						uri + '/' + name,
						method='POST',
						sessionKey=self.session_key,
						raiseAllErrors=False,
						postargs=postargs)
					if response.status != 200 and response.status != 201:
					#Something failed in our request, raise an error
						logger.error('failed to update the mad context')
						status = False

		return status

	def execute(self):
		"""
		Method called by migration pipeline. Just a wrapper.
		"""
		return self._fetch_and_migrate()


class EntityMigrationHandler(MigrationFunctionAbstract):
	"""
	Migration handler to fix inconsistent entities, where identifier.values would be empty or not contain all the
	alias values for the alias fields. But, the alias fields and there values would exist at top level in entity object.
	For more info, check ITSI-356.
	"""
	def __init__(self, session_key, restore):
		super(EntityMigrationHandler, self).__init__(session_key)
		self.session_key = session_key
		self.restore = restore

	@staticmethod
	def _is_identifier_or_info_field_in_inconsistent_state(entity, field_type='identifier'):
		"""
		Determing if entity is in inconsistent state or not, by looking at identifier and
		informational field in entity object. In a call, only looks at one of the kind of
		fields (identifier or informational) as per field_type parameter.

		@type entity: dict
		@param entity: entity object
		@type field_type: basestring
		@param field_type: 'identifier' or 'informational'
		@rtype: bool
		@return: if entity is inconsistent, return True. else, return False.
		"""
		field_to_verify = entity.get(field_type, {})
		if 'fields' not in field_to_verify or not isinstance(field_to_verify['fields'], list):
			return True
		if 'values' not in field_to_verify or not isinstance(field_to_verify['values'], list):
			return True
		field_names = field_to_verify.get('fields')
		for field_name in field_names:
			# In order to enable KV Store case insensitive matching we need to
			# convert identifier/info values to lower case
			field_values = entity.get(field_name)
			if not isinstance(field_values, list):
				logger.warning(
					'Found entity in inconsistent state. Either alias/info field value does not exist in entity or is '
					'not in correct format. Expected format for values of alias/info fields is list. Skipping entity '
					'update while migration. Please delete and re-create the entity. entity="%s", field_name="%s", '
					'field_format_found="%s"' % (entity.get('title'), field_name, type(field_values).__name__)
				)
				return False
			for field_value in field_values:
				if field_value.lower() not in field_to_verify.get('values'):
					return True
		return False

	def _fetch_and_migration(self):
		"""
		Re-save entity objects.
		@return: bool
		"""
		status = True
		try:
			entities_collection = []
			entities = self.get_object_iterator('entity')
			if self.restore:
				logger.info('Performing restore, update all the entities.')
				for entity in entities:
					entities_collection.append(entity)
			else:
				for entity in entities:
					# only update the entities which are in inconsistent state
					update_entity = self._is_identifier_or_info_field_in_inconsistent_state(
						entity, field_type='identifier'
					)
					if update_entity:
						entities_collection.append(entity)
						continue
					update_entity = self._is_identifier_or_info_field_in_inconsistent_state(
						entity, field_type='informational'
					)
					if update_entity:
						entities_collection.append(entity)

			if len(entities_collection) > 0:
				self.save_object('entity', entities_collection)
				logger.info('Total number of entities updated during migration: %s' % len(entities_collection))
			else:
				logger.info('No entities to update during migration.')

		except Exception, e:
			logger.exception('Failed while updating entities. Exception: %s' % e)
			status = False
		return status

	def execute(self):
		"""
		Method called by migration pipeline. Just a wrapper.
		"""
		return self._fetch_and_migration()
