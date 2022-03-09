# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import copy
import uuid
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
import ITOA.itoa_common as utils
from ITOA.itoa_object import CRUDMethodTypes
from ITOA.itoa_factory import instantiate_object
from ITOA.itoa_common import get_itoa_logger
from ITOA.itoa_exceptions import ItoaError, ItoaValidationError
from itsi.objects.changehandlers.base_service_template_update_handler import BaseServiceTemplateUpdateHandler
from itsi.objects.itsi_backup_restore import ItsiBackupRestore

logger = get_itoa_logger("itsi.link_service_template", "itsi.log")


class ServiceTemplateUtils(object):
    def __init__(self, session_key, current_user_name):
        """
        Constructor
    
        @type: string
        @param: session_key
    
        @type: string
        @param owner: "current_user_name" user invoking this call
    
        @rtype: None
        @return: None
        """
        self._session_key = session_key
        self.current_user_name = current_user_name
        self.base_service_templates = None
        self.op = instantiate_object(self._session_key, self.current_user_name, 'service', logger=logger)

    def _save_services(self, owner, services, req_source='unknown', transaction_id=None):
        """
        Update service objects with base service template objects content, when service has to be created from
        base service template.
        If, no service is linked to base service template, then, does nothing.
        @type services: list
        @param services: list of service objects
        @type owner: string
        @param owner: user who is performing this operation
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @return: a list of service ids
        """
        self.op.base_service_templates = self.base_service_templates
        self.op.skip_service_template_update = True
        saved_service_ids = self.op.save_batch(owner,
                                               services,
                                               method=CRUDMethodTypes.METHOD_UPDATE, # Services are always updated for link operation
                                               validate_names=False, # Skip validating service titles here,
                                               req_source=req_source,
                                               transaction_id=transaction_id)
        return saved_service_ids

    def get_template_id_from_service(self, owner, service_id, req_source='unknown', transaction_id=None):
        """
        Get service template id from service
        @type owner: string
        @param owner: user who is performing this operation
        @type service_id: string
        @param service_id: the key of service object
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @return: dict
        """
        services = self.op.get_bulk(owner, req_source=req_source, filter_data={'_key': service_id},
                                    fields=['_key', 'base_service_template_id'],
                                    transaction_id=transaction_id)
        if not len(services):
            error_msg = _("Service with id: {} does not exist.").format(service_id)
            logger.error(error_msg)
            raise ItoaError(error_msg, logger, status_code=404)
        return {'_key': services[0].get('base_service_template_id', '')}

    def link_template_to_service(self, owner, service_id, service_template_id, overwrite_entity_rules='append', req_source='unknown', transaction_id=None):
        """
        Perform a link operation from single service to a service template
        @type owner: string
        @param owner: user who is performing this operation
        @type service_id: string
        @param service_id: the key of service object
        @type service_template_id: string
        @param service_template_id: the key of service template object to link
        @type overwrite_entity_rules: string
        @param overwrite_entity_rules:  'append'- appends entity rules from the template with OR,
                                        'replace'- replaces entity rules with ones from the template,
                                        'ignore'- does not change the services' entity rules
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @return: dict
        """
        service_link_map = {service_template_id:[service_id]}
        services, updated_service_link_map = self._link_operation(owner, service_link_map, None, overwrite_entity_rules, req_source, transaction_id)
        if len(services):
            self._save_services(owner, services, req_source, transaction_id)
            logger.info('Successfully linked services with service template: {}'.format(updated_service_link_map))
            return {'_key': service_id}
        else:
            logger.info('Service is not updated. Service id: {}. Service template id: {}'.format(service_id, service_template_id))
            return {}

    def bulk_link_services_to_templates(self, owner, service_link_map, entity_rules=None, req_source='unknown', transaction_id=None, update_if_linked=False):
        """
        Perform a bulk link operation
        @type owner: string
        @param owner: user who is performing this operation
        @type entity_rules: dict
        @param entity_rules: dictionary {service_id: entity_rule}
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @type update_if_linked: boolean
        @param update_if_linked: Update service entity_rules if it is already linked to the given template
        @return: list of saved service ids
        """
        # when bulk linking and no entity_rules provided, default to replace operation
        services, updated_service_link_map = self._link_operation(owner, service_link_map, entity_rules, 'replace', req_source, transaction_id, update_if_linked)
        if len(services):
            saved_service_ids = self._save_services(owner, services, req_source, transaction_id)
            logger.info('Successfully linked services with service template: {}'.format(updated_service_link_map))
            return saved_service_ids
        else:
            logger.info('Service linkage is not updated, service link map: {0}'.format(service_link_map))
            return []

    def _link_operation(self, owner, service_link_map, entity_rules=None, overwrite_entity_rules='append', req_source='unknown', transaction_id=None, update_if_linked=False):
        """
        Update service objects with base service template objects content.
        Also update service template with linked services
        @type owner: string
        @param owner: user who is performing this operation
        @type service_link_map: dict
        @param service_link_map: {service_template_id: [service_id]}
        @type entity_rules: dict
        @param entity_rules: dictionary {service_id: entity_rule}. This also indicates the request comes from bulk import
        @type overwrite_entity_rules: basestring
        @param overwrite_entity_rules: 'append', 'replace', 'ignore'
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @type update_if_linked: boolean
        @param update_if_linked: Update service entity_rules if it is already linked to the given template
        @return: list of updated services and updated service link map
        """
        service_template_get_filter = {
            '$or': []
        }
        service_get_filter = {
            '$or': []
        }

        service_templates_map = {}
        service_map = {}

        # construct service template filter and service filter
        for service_template_id, services in service_link_map.items():
            service_template_get_filter['$or'].append({
                '_key':service_template_id
            })
            service_templates_map[service_template_id] = {}

            for service in services:
                service_get_filter['$or'].append({
                    '_key': service
                })
                service_map[service] = {}

        # fetch service template
        service_template_interface = instantiate_object(self._session_key, self.current_user_name,
                                                        'base_service_template', logger=logger)

        service_templates = service_template_interface.get_bulk(owner,
                                                               req_source=req_source,
                                                               filter_data=service_template_get_filter,
                                                               transaction_id=transaction_id)

        # use no_error_in_fetch to check if service_link_map is valid.
        # if not, reconstruct the map
        no_error_in_fetch = True

        # validate service template key
        if len(service_templates) < len(service_templates_map.keys()):
            no_error_in_fetch = False
            dif = [service_template for service_template in service_templates_map.keys() if service_template not in service_templates]
            logger.error('Fail to get one or more of service templates. '
                         'Please check the service template id. '
                         'Requested: {}. Received: {}. Missing: {}'.format(service_templates_map.keys(),
                                                                           [service_template['_key'] for service_template in service_templates],
                                                                           dif))

        # clean up service template map and recreate
        del service_templates_map
        service_templates_map = {}
        for service_template in service_templates:
            service_templates_map[service_template.get('_key')] = service_template

        # fetch services
        persisted_services = self.op.get_bulk(owner,
                                              filter_data=service_get_filter,
                                              transaction_id=transaction_id)

        if len(persisted_services) < len(service_map.keys()):
            no_error_in_fetch = False
            dif = [service for service in service_map.keys() if service not in persisted_services]
            logger.error('Fail to get one or more of services. '
                         'Requested: {}. Received: {}. Missing: {}'.format(service_templates_map.keys(),
                                                                           [service['_key'] for service in persisted_services],
                                                                           dif))
        # clean up service template map and recreate
        del service_map
        service_map = {}
        for service in persisted_services:
            service_map[service.get('_key')] = service

        # Generate new service link map if any errors in service fetch or service template fetch
        updated_service_link_map = {}
        if no_error_in_fetch:
            updated_service_link_map = copy.deepcopy(service_link_map)
            logger.debug('Service link map: {}'.format(updated_service_link_map))
        else:
            for service_template, services in service_link_map.items():
                if service_template in service_templates_map:
                    for service in services:
                        if service in service_map:
                            if service_template in updated_service_link_map:
                                if service not in updated_service_link_map[service_template]:
                                    updated_service_link_map[service_template].append(service)
                            else:
                                updated_service_link_map[service_template] = [service]
            logger.info("Service link map updated: {}. Original: {}".format(updated_service_link_map, service_link_map))

        updated_services = []

        del self.base_service_templates
        self.base_service_templates = []

        for service_template_id, service_ids in updated_service_link_map.items():

            service_template = service_templates_map.get(service_template_id)
            relink = False

            # store the kpis from template so we don't need to generate it every time
            kpi_title_from_template = [kpi['title'] for kpi in service_template['kpis'] if not kpi['_key'].startswith(self.op.shkpi_starts_with)]

            # tuple of tuples containing field name and it's default value, in case field is missing
            # from service template
            fields_to_copy_from_template = (('kpis', []), ('entity_rules', []), ('serviceTemplateId', ''))

            for service_id in service_ids:
                service = service_map[service_id]
                if service.get('base_service_template_id') == service_template_id:
                    logger.info('Service: {} is already linked to service template: {}. '
                                'Skip link operation'.format(service.get('title'), service_template.get('title')))
                    if not update_if_linked:
                        continue
                elif service.get('base_service_template_id'):
                    # it means it's a relink operation
                    # if entity_rules does not exist, this relink operation does not come from bulk import
                    # the code below unlink the service from original service template it's linked to
                    if not entity_rules:
                        relink = True
                        already_exist = False
                        for original_service_template_to_unlink in self.base_service_templates:
                            # if the original service template is already stored in class variable
                            # just remove the service id from linked_services field
                            if original_service_template_to_unlink.get('_key') == service.get('base_service_template_id'):
                                already_exist = True
                                if service.get('_key') in original_service_template_to_unlink.get('linked_services', []):
                                    original_service_template_to_unlink['linked_services'].remove(service['_key'])
                                logger.info('Relink service: {} from service template:{} to service template: {}. '.format(service.get('title'),
                                                                                                                           original_service_template_to_unlink.get('title'),
                                                                                                                           service_template.get('title')))

                        if not already_exist:
                            # if the original service template is not stored yet
                            # get it from kvstore and keep it in self.base_service_templates
                            original_service_template_to_unlink = service_template_interface.get(owner,
                                                                                                 service.get('base_service_template_id'),
                                                                                                 req_source=req_source,
                                                                                                 transaction_id=transaction_id)
                            if not original_service_template_to_unlink:
                                logger.error('Fail to get service template: {} in relink operation.'.format(service.get('base_service_template_id')))
                            else:
                                if service.get('_key') in original_service_template_to_unlink.get('linked_services', []):
                                    original_service_template_to_unlink['linked_services'].remove(service['_key'])
                                    self.base_service_templates.append(original_service_template_to_unlink)

                                logger.info('Relink service: {} from service template:{} to service template: {}. '.format(service.get('title'),
                                                                                                                           original_service_template_to_unlink.get('title'),
                                                                                                                           service_template.get('title')))

                    else:
                        raise ItoaValidationError(_('Re-link operation is not supported through bulk import.'), logger)

                updated_service = copy.deepcopy(service)

                updated_service['base_service_template_id'] = service_template.get('_key')

                if update_if_linked:
                    relink = True

                for field, default_value in fields_to_copy_from_template:
                    # special handler for kpis
                    if field == 'kpis':
                        if relink:
                            # remove linked kpis first if it's a relink operation
                            updated_kpis = []
                            for kpi in updated_service.get(field, []):
                                if kpi['_key'].startswith(self.op.shkpi_starts_with) or not kpi.get('base_service_template_id', ''):
                                    updated_kpis.append(kpi)
                            updated_service[field] = updated_kpis

                        for kpi in updated_service.get(field, []):
                            if kpi['_key'].startswith(self.op.shkpi_starts_with):
                                continue
                            else:
                                if kpi['title'] in kpi_title_from_template:
                                    unique_tag = '(' + service.get('identifying_name', 'dup_service') + '_' + str(uuid.uuid4())[:4] + ')'
                                    kpi['title'] = kpi['title'] + unique_tag

                        # tuple of tuples containing field name to be added to kpis as first element and
                        # field's value as second element of tuple
                        fields_to_be_added_to_kpi = (
                            # default backfill from service_template
                            # NOTE: these 2 fields are not in service template so they will be False and '-7d'
                            # might change it in the future based on how the feature evolves
                            ('backfill_enabled', service_template.get('backfill_enabled', False)),
                            ('backfill_earliest_time', service_template.get('backfill_earliest_time', '-7d')),
                        )

                        for kpi in copy.deepcopy(service_template.get(field, default_value)):
                            if kpi['_key'].startswith(self.op.shkpi_starts_with):
                                continue
                            # pop `linked_kpi_thresholds_updated` field from service kpi, if it
                            # incorrectly exists in a service template.
                            kpi.pop('linked_kpi_thresholds_updated', None)
                            self.op.add_required_fields_to_new_kpi_from_servcie_template(kpi, service_template.get('_key'))
                            for kpi_field, value in fields_to_be_added_to_kpi:
                                kpi[kpi_field] = value
                            updated_service[field].append(kpi)
                    # Append entity rules from service template
                    elif field == 'entity_rules':
                        # If operation comes from bulk import and requires replacement of entity rules.
                        # NOTE: bulk import operation is always a replace when entity_rules are provided
                        if entity_rules:
                            logger.debug('Operation comes from bulk import.')
                            if not utils.is_valid_dict(entity_rules):
                                logger.error('Invalid entity rules: {}'.format(entity_rules))
                            else:
                                if service_id in entity_rules:
                                    updated_service[field] = entity_rules.get(service_id, default_value)
                        else:
                            # If entity rules does not exist in service (which is very unlikely) or
                            # overwrite_entity_rules is 'replace'
                            # Only entity rules from service template will be used
                            if field not in updated_service or overwrite_entity_rules == 'replace':
                                updated_service[field] = service_template.get(field, default_value)
                            # append service template entity rules with services' existing entity rules
                            elif overwrite_entity_rules == 'append':
                                updated_service[field].extend(service_template.get(field, default_value))

                            # If none of the above if clauses is true, this is an 'ignore' operation for entity_rules
                            # i.e No-Op

                    else:
                        updated_service[field] = copy.deepcopy(service_template.get(field, default_value))

                logger.debug('Updated service content of `{0}` with base service template `{1}`. transaction_id '
                             '= {2}'.format(updated_service.get('_key'),
                                            updated_service.get('base_service_template_id',),
                                            transaction_id))

                updated_services.append(updated_service)

                # update service template
                if service_template.get('linked_services', None) is not None:
                    if updated_service.get('_key') not in service_template['linked_services']:
                        service_template['linked_services'].append(updated_service.get('_key'))
                else:
                    service_template['linked_services'] = [updated_service.get('_key')]
            self.base_service_templates.append(service_template)
        return updated_services, updated_service_link_map

    @staticmethod
    def unset_service_template_fields_in_services(linked_services):
        """
        Unset service template fields to unlink services from service
        templates.
        @type linked_services: list of dict
        @param linked_services: list of services linked to templates
        """
        for service in linked_services:
            service['base_service_template_id'] = ''
            for kpi in service.get('kpis', []):
                kpi['base_service_template_id'] = ''

    def service_template_sync_job_in_progress_or_sync_now(self):
        """
        Check if there is any service template sync job in progress or sync now
        Note: it's possible that this check happens before service template sync now job being picked up by refresh queue
        @type linked_services: list of dict
        @param linked_services: list of services linked to templates
        """
        service_template_interface = instantiate_object(self._session_key, self.current_user_name,
                                                'base_service_template', logger=logger)
        service_template_in_sync_filter = {"sync_status":"syncing"}
        service_template_in_sync = service_template_interface.get_bulk('nobody', filter_data=service_template_in_sync_filter, limit=1)
        # if any service template is currently syncing
        if len(service_template_in_sync):
            return True

        service_template_sync_scheduled_filter = {"sync_status":"sync scheduled"}
        service_template_sync_scheduled = service_template_interface.get_bulk('nobody', filter_data=service_template_sync_scheduled_filter)
        # if any service template is in sync now status
        for service_template in service_template_sync_scheduled:
            if not service_template.get('scheduled_time'):
                return True
        return False

    def get_objects_not_used_by_service_templates(self, object_type, objects):
        """
        Service Templates with kpi entries that contain the base search ids / threshold template ids
        associated with the objects that are being passed in
        @type object_type: string
        @param object_type: object type 
        @type objects: list
        @param objects: objects passed in through the request, each element
                        must contain a key
        """
        service_template_interface = instantiate_object(self._session_key, self.current_user_name,
                                                'base_service_template', logger=logger)
        results = []
        for object in objects:
            if object_type == 'kpi_threshold_template':
                service_template_filter = {"kpis.kpi_threshold_template_id": object.get("_key")}
            elif object_type == 'kpi_base_search':
                service_template_filter = {"kpis.base_search_id": object.get("_key")}

            # get service templates containing KPIs using this kpi base search or kpi threshold template
            existing_objects = service_template_interface.get_bulk('nobody', filter_data=service_template_filter, limit=1)

            if not existing_objects:
                results.append(object)

        return results

    def get_base_search_used_metric_not_deleted(self, objects):
        """
        Service Templates with kpi entries that contain the base search metric
        associated with the objects that are being passed in
        @type objects: list
        @param objects: objects passed in through the request, each element
                        must contain a key
        """
        service_template_interface = instantiate_object(self._session_key, self.current_user_name,
                                                'base_service_template', logger=logger)
        results = []
        for object in objects:
            metric_deleted = False
            metrics = [metric.get('_key') for metric in object.get('metrics', [])]
            service_template_filter = {"kpis.base_search_id": object.get("_key")}

            # get service templates containing KPIs using this kpi base search
            existing_objects = service_template_interface.get_bulk('nobody', filter_data=service_template_filter)

            for service_template in existing_objects:
                for kpi in service_template.get('kpis', []):
                    if kpi.get('base_search_id') == object.get('_key'):
                        if kpi.get('base_search_metric') not in metrics:
                            metric_deleted = True

            if not metric_deleted:
                results.append(object)

        return results


class ServiceTemplateUpdateJobProcesser():
    def __init__(self, session_key):
        """
        Constructor
    
        @type: string
        @param: session_key
    
        @rtype: None
        @return: None
        """
        self._session_key = session_key
        self.current_user_name = 'nobody'

    def run(self):
        """
        Performs scheduled sync from service templates to services
        """
        backup_restore_interface = ItsiBackupRestore(self._session_key, self.current_user_name)
        if backup_restore_interface.is_any_backup_restore_job_in_progress(
                'nobody', req_source='ServiceTemplateUpdateJobProcesser'
        ):
            logger.info('One or more backup/restore jobs is/are in progress. Skip scheduled '
                        'sync of services with service template. Perform sync in next run.')
            return
        # get all service templates with scheduled_time and scheduled_job
        service_template_interface = instantiate_object(self._session_key, self.current_user_name,
                                                        'base_service_template', logger=logger)

        service_templates = service_template_interface.get_bulk(self.current_user_name, fields=['_key'])
        for service_template in service_templates:
            # make sure the service template object is up-to-date since one sync job could take minutes to hours
            service_template = service_template_interface.get(self.current_user_name, service_template.get('_key'))
            if service_template.get('sync_status') == 'sync scheduled' or service_template.get('sync_status') == 'syncing' and \
                    service_template.get('scheduled_time') and service_template.get('scheduled_job'):
                if service_template.get('sync_status') == 'syncing':
                    logger.info('Found unfinished sync job from service template {}. Will redo the push now'.format(service_template['title']))
                # compare current timestamp with scheduled_time
                if service_template.get('scheduled_time') <= utils.get_current_utc_epoch():
                    # call change handler
                    success = BaseServiceTemplateUpdateHandler(logger, self._session_key).deferred(
                        change=service_template.get('scheduled_job'), scheduled_for_later=True
                    )
                    # send success or failure message
                    if success:
                        message = _('Successfully updated {} services linked to service template {}. ').format(len(service_template['linked_services']),
                                                                                                            service_template['title'])
                        utils.post_splunk_user_message(message, self._session_key)
                        logger.info(message)
                    else:
                        message = _('Error while updating {} services linked to service template {}. ' \
                                  'See service template configuration page for more details. ').format(len(len(service_template['linked_services']),
                                                                                                      service_template['title']))
                        utils.post_splunk_user_message(message, self._session_key)
                        logger.error(message)

