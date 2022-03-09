# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json
import re
import copy

import splunk
from splunk.appserver.mrsparkle.lib import i18n

import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from itsi.objects.itsi_kpi import ItsiKpi
from ITOA.itoa_factory import instantiate_object
from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_kpi_template import ItsiKpiTemplate
from itsi.objects.itsi_security_group import ItsiSecGrp
from itsi.searches.itsi_searches import ItsiKpiSearches
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG
from ITOA.saved_search_utility import SavedSearch
from ITOA.itoa_exceptions import ItoaDatamodelContextError

logger = utils.get_itoa_logger('itsi.object.service')


class ItsiService(ItoaObject):
    """
    Implements ITSI service
    """
    collection_name = 'itsi_services'
    shkpi_starts_with = 'SHKPI-'

    def __init__(self, session_key, current_user_name):
        super(ItsiService, self).__init__(session_key,
                                          current_user_name,
                                          'service',
                                          collection_name=self.collection_name,
                                          is_securable_object=True)
        self.synchronous = False
        # is used by update_services_with_base_service_templates() and post_save_setup() to store
        # fetched base service templates from kvstore. Once, service templates are fetched in
        # update_services_with_base_service_templates(), we do not need to perform extra fetch in
        # post_save_setup() to synchronously update service templates.
        self.base_service_templates = None

        # used to skip service template processing for services
        self.skip_service_template_update = False

        # force to update the savesearch, this will bypass all the savedsearch updates optimization
        self.force_update_savedsearch = False

    def templatize(self, owner, object_id, req_source='unknown', for_base_service_template=False):
        """
        Templatize given object id
        @type owner: basestring
        @param owner: context of the request `nobody` vs an actual user

        @type object_id: basestring
        @param object_id: unique identifier of an object to templatize

        @type req_source: basestring
        @param req_source: indentified source initiating the operation.

        @type for_base_service_template: bool
        @param for_base_service_template: True, if templatizing service for Base Service Temple.
                                          Else, False.
        @rtype: dict/None
        @return: requested template.
        """
        service_template = super(ItsiService, self).templatize(owner, object_id, req_source)

        if not for_base_service_template:  # normal templatizing of service
            # Null'ify service dependencies
            service_template['services_depends_on'] = []
            service_template['services_depending_on_me'] = []

            # Templatize kpis in the service.
            logger.debug('Templatizing kpis for service id `%s`', object_id)
            kpis = service_template.get('kpis', [])
            kpi_keys_to_remove = ('_key', 'search', 'search_alert', 'search_entities', 'search_aggregate',
                                  'search_time_series', 'search_time_compare',
                                  'search_time_series_entities', 'search_time_series_aggregate')
            for kpi in kpis:
                for key in kpi_keys_to_remove:
                    kpi.pop(key, None)
                if 'aggregate_thresholds' in kpi:
                    kpi['aggregate_thresholds']['search'] = ''
                if 'entity_thresholds' in kpi:
                    kpi['entity_thresholds']['search'] = ''
                if 'time_variate_thresholds_specification' in kpi and \
                   'policies' in kpi['time_variate_thresholds_specification'] and \
                   'default_policy' in kpi['time_variate_thresholds_specification']['policies']:
                        if 'aggregate_thresholds' in kpi['time_variate_thresholds_specification']['policies']['default_policy']:
                            kpi['time_variate_thresholds_specification']['policies']['default_policy']['aggregate_thresholds']['search'] = ''
                        if 'entity_thresholds' in kpi['time_variate_thresholds_specification']['policies']['default_policy']:
                            kpi['time_variate_thresholds_specification']['policies']['default_policy']['entity_thresholds']['search'] = ''

        else:
            if service_template is None:
                return None
            # specific templatizing of service to create Base Service Template object
            # from service. Used by ItsiBaseServiceTemplate object.

            service_fields_to_remove = ('services_depends_on', 'services_depending_on_me',
                                        'service_template_id', 'enabled', 'isFirstTimeSaveDone',
                                        'base_service_template_id')

            # pop service fields
            for key in service_fields_to_remove:
                service_template.pop(key, None)

            # Templatize kpis in the service.
            logger.debug('Templatizing kpis for service id `%s`', object_id)
            kpis = service_template.get('kpis', [])

            # remove service health kpi
            for i in range(len(kpis)):
                if kpis[i]['_key'].startswith(self.shkpi_starts_with):
                    del kpis[i]
                    break

            kpi_keys_to_remove = ('search', 'kpi_base_search', 'search_alert', 'search_entities',
                                  'search_aggregate', 'search_time_series', 'search_time_compare',
                                  'search_time_series_entities', 'search_time_series_aggregate',
                                  'backfill_enabled', 'backfill_earliest_time', 'service_id',
                                  'enabled', 'sec_grp', 'type', 'base_service_template_id')
            # pop kpi fields
            for kpi in kpis:
                # generate new key for kpi
                kpi['_key'] = ITOAInterfaceUtils.generate_backend_key()

                for key in kpi_keys_to_remove:
                    kpi.pop(key, None)

        logger.debug('object_id=`%s` template=`%s`', object_id, service_template)
        return service_template

    def _determine_changed_kpis_at_ad(self, service, persisted_service, state_field, track_field, settings_field=None):
        """
        Helper method to see if anomaly detection settings have changed in any KPIs for a service
        @param service: service object (current state) or `None` if service is being deleted
        @param persisted_service: previously saved state of service object or None if service is new
        @param state_field: KPI field that contains the ON/OFF state information
        @param track_field: KPI field that contains training window information (`None` if not applicable)
        @param settings_field: KPI field containing additional settings in a dict (None if not applicable)
        @returns: changed_kpis: dict keyed by kpiid with change given by `on`, `off`, `changed`
        """
        changed_kpis = {}
        if service is None:
            for kpi in persisted_service.get('kpis', []):
                if not utils.is_valid_dict(kpi):
                    # Be resilient
                    continue
                if kpi.get(state_field):
                    changed_kpis[kpi['_key']] = 'off'
        elif persisted_service is None:
            for kpi in service.get('kpis', []):
                if not utils.is_valid_dict(kpi):
                    # Be resilient
                    continue
                # Mark the kpis state to on only if the kpi is enabled.
                if kpi.get(state_field) and kpi.get('enabled') == 1:
                    changed_kpis[kpi['_key']] = 'on'
        else:
            # Check for anomaly detection being turned on or off for kpi
            # use dicts here to provide both easy conversion to sets and easy attribute access
            persisted_kpi_dict_atad_on = dict((kpi.get('_key'), kpi)
                                              for kpi in persisted_service.get('kpis', [])
                                              if kpi.get(state_field))
            kpi_dict_atad_on = dict((kpi.get('_key'), kpi)
                                    for kpi in service.get('kpis', [])
                                    if kpi.get(state_field))

            persisted_kpi_dict_atad_on_kpi_enabled = dict((kpi.get('_key'), kpi)
                                              for kpi in persisted_service.get('kpis', [])
                                              if (kpi.get(state_field) and kpi.get('enabled') == 1))
            kpi_dict_atad_on_kpi_enabled = dict((kpi.get('_key'), kpi)
                                    for kpi in service.get('kpis', [])
                                    if (kpi.get(state_field) and kpi.get('enabled') == 1))

            persisted_kpi_dict_atad_on_kpi_disabled = dict((kpi.get('_key'), kpi)
                                                    for kpi in persisted_service.get('kpis', [])
                                                    if (kpi.get(state_field) and kpi.get('enabled') == 0))

            kpi_dict_atad_on_kpi_disabled = dict((kpi.get('_key'), kpi)
                                                for kpi in service.get('kpis', [])
                                                if (kpi.get(state_field) and kpi.get('enabled') == 0))
            # (1) Check for AD being toggled on by comparing service's KPIs to persisted service's KPIs
            # NOTE: only enabled kpis are being considered here. For disabled kpis, its a NO-OP.
            _toggled_on = set(kpi_dict_atad_on_kpi_enabled.keys()) - set(persisted_kpi_dict_atad_on_kpi_enabled.keys())
            # For the case when at was already on and kpi is being toggled from disabled to enabled.
            _kpis_enabled_with_at_on = set(kpi_dict_atad_on_kpi_enabled) & set(persisted_kpi_dict_atad_on_kpi_disabled)
            _toggled_on = _toggled_on | _kpis_enabled_with_at_on
            logger.info("List of kpis toggled on: %s", _toggled_on)

            # (2) Check for AD being toggled off by comparing service's KPIs to persisted service's KPIs
            _toggled_off = set(persisted_kpi_dict_atad_on.keys()) - set(kpi_dict_atad_on.keys())
            # For the case when at is on but the kpi is toggled from enabled to disabled.
            _kpis_disabled_with_at_on = set(kpi_dict_atad_on_kpi_disabled) & set(persisted_kpi_dict_atad_on_kpi_enabled)
            _toggled_off = _toggled_off | _kpis_disabled_with_at_on
            logger.info("List of kpis toggled off: %s", _toggled_off)

            # (3) Check if any KPIs with AD turned on have had their training period changed
            # Affect the change only if the kpi is enabled
            _changed = set()
            for k in kpi_dict_atad_on:
                if k in persisted_kpi_dict_atad_on:
                    old_training_window = persisted_kpi_dict_atad_on[k].get(track_field)
                    new_training_window = kpi_dict_atad_on[k].get(track_field)
                    if new_training_window != old_training_window:
                        _changed.add(k)

            # (4) Check if any KPIs with AD turned on have had their settings changed
            # Affect the change only if the kpi is enabled
            if settings_field is not None:
                for k in kpi_dict_atad_on:
                    if k in persisted_kpi_dict_atad_on:
                        old_settings = persisted_kpi_dict_atad_on[k].get(settings_field, {})
                        new_settings = kpi_dict_atad_on[k].get(settings_field, {})
                        settings_keys = set()
                        settings_keys |= set(old_settings.keys())
                        settings_keys |= set(new_settings.keys())
                        for setting_key in settings_keys:
                            if old_settings.get(setting_key) != new_settings.get(setting_key):
                                _changed.add(k)

            changed_kpis.update(dict((k, 'on') for k in _toggled_on))
            changed_kpis.update(dict((k, 'off') for k in _toggled_off))
            changed_kpis.update(dict((k, 'changed') for k in _changed))
        return changed_kpis

    def _determine_generate_changed_search_param(self, service, persisted_service):
        """
        Helper method to see if any search related parameters are updated in any KPI for a service.
        @type service: dict
        @param service: service object
        @type persisted_service: dict
        @param persisted_service: service object from kvstore
        @rtype changed_kpis: dict
        @param changed_kpis: kpis with savedsearch info
        """
        changed_kpis = {}
        need_update_search = False
        if not utils.is_valid_dict(service) or service is None:
            return changed_kpis
        if 'need_update_search' in service:
            need_update_search = service.get('need_update_search', False)
            service.pop('need_update_search')
        if not utils.is_valid_dict(persisted_service) or persisted_service is None:
            persisted_kpi_list = {}
        else:
            persisted_kpi_list = dict((kpi.get('_key'), kpi)
                                      for kpi in persisted_service.get('kpis', []) if kpi.get('_key'))
            if persisted_service.get('entity_rules') != service.get('entity_rules'):
                need_update_search = True
        new_kpi_list = dict((kpi.get('_key'), kpi)
                                  for kpi in service.get('kpis', []) if kpi.get('_key'))

        for kpi_id, kpi_content in new_kpi_list.iteritems():
            # Add temporary keys
            kpi_content['service_id'] = service.get('_key')
            kpi_content['service_title'] = service.get('title', '')

            if kpi_content['_key'].startswith(self.shkpi_starts_with) or kpi_content.get('search_type') == 'shared_base':
                # No saved searches need to be updated for ServiceHealth.
                # Saved searches for Shared Base Searches are updated async by
                # the itsi_refresher Modular Input.
                continue

            # if entity filtering is disabled, no need to update the savedsearch
            is_service_entity_filter = kpi_content.get('is_service_entity_filter', False)
            if not is_service_entity_filter:
                need_update_search = False

            # take care of all the newly created KPIs.
            if kpi_id not in persisted_kpi_list:
                saved_search_settings = ItsiKpi(self.session_key,
                    'nobody').generate_saved_search_settings(kpi_content,
                                                             service.get('entity_rules'),
                                                             service.get('sec_grp'))
                changed_kpis.update({kpi_id:saved_search_settings})
            else:
                if need_update_search or self.force_update_savedsearch:
                    # regardless of the search string content, the search need to be regenerated
                    # this is coming from the entity update.
                    saved_search_settings = ItsiKpi(self.session_key,
                    'nobody').generate_saved_search_settings(kpi_content,
                                                             service.get('entity_rules'),
                                                             service.get('sec_grp'),
                                                             acl_update=False)
                    changed_kpis.update({kpi_id:saved_search_settings})
                else:
                    # kpi/search already exist, compare the search setting
                    saved_search_settings = ItsiKpi(self.session_key,
                    'nobody').generate_saved_search_settings(kpi_content,
                                                             service.get('entity_rules'),
                                                             service.get('sec_grp'),
                                                             acl_update=False)
                    persisted_kpi_content = persisted_kpi_list.get(kpi_id)
                    # if it was a shared base search before, now a non-shared bases search
                    # we still want to generate the search string for it.
                    if persisted_kpi_content.get('search_type') == 'shared_base' and kpi_content.get('search_type') != 'shared_base':
                        saved_search_settings['acl_update'] = True
                        changed_kpis.update({kpi_id:saved_search_settings})
                    else:
                        persisted_kpi_content['service_id'] = service.get('_key')
                        persisted_kpi_content['service_title'] = service.get('title', '')

                        # With PBL-5603, changes to allow a user to split KPI by a different entity field from
                        # entity filtering field were added. As a part of this change, new field
                        # 'entity_breakdown_id_fields' was added to kpi object. Code chunk below is added to
                        # handle case of migration, when persisted KPI content in kvstore will not have
                        # 'entity_breakdown_id_fields' while performing migration of service objects.
                        if persisted_kpi_content.get('is_entity_breakdown', False):
                            entity_breakdown_id_fields = persisted_kpi_content.get('entity_breakdown_id_fields', None)
                            if entity_breakdown_id_fields is None or len(entity_breakdown_id_fields) == 0:
                                persisted_kpi_content['entity_breakdown_id_fields'] = persisted_kpi_content.get('entity_id_fields', '')
                                logger.debug('entity_breakdown_id_fields missing from kpi object = {}. '
                                             'Setting it to entity_id_fields.'
                                             .format(persisted_kpi_content.get('_key')))

                        persisted_saved_search_settings = ItsiKpi(self.session_key,
                            'nobody').generate_saved_search_settings(persisted_kpi_content,
                                                                     service.get('entity_rules'),
                                                                     service.get('sec_grp'),
                                                                     acl_update=False)

                        # pop out the crontab, we don't compare the crontab
                        cron_schedule = saved_search_settings.get('cron_schedule')
                        saved_search_settings.pop('cron_schedule', None)
                        persisted_saved_search_settings.pop('cron_schedule', None)
                        if saved_search_settings != persisted_saved_search_settings:
                            saved_search_settings['cron_schedule'] = cron_schedule
                            changed_kpis.update({kpi_id:saved_search_settings})

            # cleanup temporary keys added.
            kpi_content.pop('service_id', None)
            kpi_content.pop('service_title', None)

        return changed_kpis

    def _determine_changed_alert_period(self, service, persisted_service):
        """
        Helper method to see if alert period value have changed in any KPIs for a service
        @param service: service object (current state) or `None` if service is being deleted
        @param persisted_service: previously saved state of service object or None if service is new
        @returns: changed_kpis: dict keyed by kpiid and new alert period value
        """
        changed_kpis = {}

        if not utils.is_valid_dict(service) or service is None or \
                not utils.is_valid_dict(persisted_service) or persisted_service is None:
            return changed_kpis

        persisted_alert_period_list = dict((kpi.get('_key'), kpi)
                                           for kpi in persisted_service.get('kpis', []) if kpi.get('alert_period'))
        alert_period_list = dict((kpi.get('_key'), kpi)
                                 for kpi in service.get('kpis', []) if kpi.get('alert_period'))
        for k in alert_period_list:
            if k in persisted_alert_period_list:
                old_alert_period = persisted_alert_period_list[k].get('alert_period')
                new_alert_period = alert_period_list[k].get('alert_period')
                if old_alert_period != new_alert_period:
                    changed_kpis.update({k: new_alert_period})

        return changed_kpis

    def get_shared_search_type(self, service):
        """
        Get shared search kpis
        @type service: dict
        @param service: service object
        @return: dict which hold kpis which are shared search
        """
        if not isinstance(service, dict):
            # return empty dict
            return {}
        return dict((kpi.get('_key'), kpi) for kpi in service.get('kpis', []) if kpi.get('search_type') ==
                    'shared_base' and kpi.get("base_search_id") is not None)

    def get_un_shared_search_type(self, service):
        """
        Get ad-hoc or datamodel search kpis
        @type service: dict
        @param service: service object
        @return: dict which hold kpis which are shared search
        """
        if not isinstance(service, dict):
            # return empty dict
            return {}
        return dict((kpi.get('_key'), kpi) for kpi in service.get('kpis', [])
                    if kpi.get('search_type') != 'shared_base')

    def _determine_changed_search_type(self, service, persisted_service):
        """
        Determine if search type changed from adhoc/data model to shared_base search
        @type service: dict
        @param service: service
        @type persisted_service: dict
        @param persisted_service: persisted service
        @return: list of kpis which is changed from ad-hoc/datamodel to shared base search
        """
        if service is None or persisted_service is None:
            return []
        if not isinstance(service, dict) or not isinstance(persisted_service, dict):
            return []
        old_un_shared_kpi = self.get_un_shared_search_type(persisted_service)

        new_kpi_shared_search = self.get_shared_search_type(service)

        # get search which has changed from ad-hoc/datamodel to shared
        kpi_changed_to_shared = list(set(old_un_shared_kpi.keys()).intersection(set(new_kpi_shared_search.keys())))

        # Lets pass id which is changed
        logger.info("length=%s, ids=%s changed from ad-hoc/datamodel to shared_based", len(kpi_changed_to_shared),
                    kpi_changed_to_shared)

        return kpi_changed_to_shared

    def _determine_changed_service_dependencies(self, service, persisted_service):
        """
        Will check if any dependencies were added or removed to the service
        @param service: service object (current state) or `None` if service is being deleted
        @param persisted_service: previously saved state of service object or None if service is new
        @return: dict of service key to added and removed dependences
        """
        update_set = {}
        service_depends_on = service.get('services_depends_on')
        added_dependencies = []
        removed_dependencies = []
        # This is a new service, so we can assume all dependencies are newly added as well
        if not persisted_service:
            if service_depends_on is None or len(service_depends_on) == 0:
                return update_set # nothing to do
            # all dependencies are new
            for service_dependency in service_depends_on:
                added_dependencies.append({
                    'target_service': service_dependency.get('serviceid'),
                    'depending_kpis': service_dependency.get('kpis_depending_on')
                })
        # This is an update to an existing service, so we must go through the structure
        else:
            existing_depends_on = persisted_service.get('services_depends_on')
            # no dependency info on either existing or new, so nothing required
            if (service_depends_on is None or len(service_depends_on)) == 0 and (existing_depends_on is None or len(existing_depends_on)) == 0:
                return update_set # nothing to do

            existing_service_ids = set([])
            new_service_ids = set([])
            if existing_depends_on is not None:
                existing_service_ids = set({record.get('serviceid') for record in existing_depends_on})
            if service_depends_on is not None:
                new_service_ids = set({record.get('serviceid') for record in service_depends_on})

            # Find which services were completely removed as dependencies
            removed_services = existing_service_ids - new_service_ids
            # Find which services are new dependencies
            added_services = new_service_ids - existing_service_ids

            logger.debug('removed services detected: %s', str(removed_services))
            # For all removed services, we can remove all depending on kpis from the target service
            for removed_service in removed_services:
                existing_dependency = next((x for x in existing_depends_on if x.get('serviceid') == removed_service), None)
                removed_dependencies.append({
                    'target_service': removed_service,
                    'depending_kpis': existing_dependency.get('kpis_depending_on')
                })
            # For all added services we can add all kpis as dependencies
            for added_service in added_services:
                new_dependency = next((x for x in service_depends_on if x.get('serviceid') == added_service), None)
                added_dependencies.append({
                    'target_service': added_service,
                    'depending_kpis': new_dependency.get('kpis_depending_on')
                })

            # Now the complicated part, if service was already a dependency
            # we need to see if list of KPI dependencies changed
            for service_id in existing_service_ids.intersection(new_service_ids):
                new_dependency = next((x for x in service_depends_on if x.get('serviceid') == service_id), None)
                existing_dependency = next((x for x in existing_depends_on if x.get('serviceid') == service_id), None)

                # New KPI dependencies
                new_kpis = list(set(new_dependency.get('kpis_depending_on')) -
                                set(existing_dependency.get('kpis_depending_on')))

                # Removed KPI dependencies
                removed_kpis = list(set(existing_dependency.get('kpis_depending_on')) -
                                    set(new_dependency.get('kpis_depending_on')))

                if len(new_kpis) > 0:
                    added_dependencies.append({
                        'target_service': service_id,
                        'depending_kpis': new_kpis
                    })

                if len(removed_kpis) > 0:
                    removed_dependencies.append({
                        'target_service': service_id,
                        'depending_kpis': removed_kpis
                    })

        logger.debug('added_dependencies: %s, removed_dependencies: %s', str(added_dependencies), str(removed_dependencies))
        # if any dependencies were added or removed, then we have a service we need to update
        if len(added_dependencies) > 0 or len(removed_dependencies) > 0:
            update_set[service.get('_key')] = {
                'added_dependencies': added_dependencies,
                'removed_dependencies': removed_dependencies
            }
        return update_set

    def get_shared_base_search_update_jobs(self, services, old_services, transaction_id):
        """
        Iterate through the services to determine what kpi base searches we need to update on a service change
        @param services: A list of new services that we have not yet saved to the database. Could be dicts, could be strings
        @param old_services: A dict of old services that we're comparing against, needs to be a subset of services
        @returns: A list of requests issued to update different base searches
        """
        #When do we want to update a base search? From the work on ticket ITOA-6362, I think that there are 4 rules that we want to abide by
        #Anything outside of these rules should not have an update issued for it
        # 1 Issue an update to all associated base searches if the entity filter changes
        # 2 Issue an update to the base search when an entirely new service is being created that uses base searches
        # 3 Issue an update when a service has deleted a kpi and there are no more kpis in that service which reference a particular base search
        # 4 Issue an update when a service has added a kpi that references a previously unreferenced base search
        base_searches_to_update = set()
        existing_ids = []
        logger.debug('Updating shared base searches tid=%s', transaction_id)
        for service in services:
            current_base_searches = set()
            current_enabled_base_searches = set()
            kpis = service.get("kpis",[])
            for kpi in kpis:
                if (kpi['search_type'] == 'shared_base' and
                        kpi.get('base_search_id') is not None):
                    #Get the set of currently referenced base searches
                    current_base_searches.add(kpi['base_search_id'])
                    #We want a special case for changing the enabled/disabled status
                    #Because it adds an additional dimension
                    if kpi.get('enabled') == 1:
                        current_enabled_base_searches.add(kpi['base_search_id'])

            if isinstance(service, dict): #Sometimes this may be a full service, othertimes a string
                #Keep in mind that old_service can be None
                old_service = old_services.get(service.get('_key'))
            elif isinstance(service, basestring):
                old_service = old_services.get(service)
            else:
                raise Exception(_('Invalid service in service list %s') % service)
            if not old_service:
                #We're dealing with an entirely new service, add all of the base searches
                #referencing that service
                for kpi in kpis:
                    if (kpi['search_type'] == 'shared_base' and
                            kpi.get('base_search_id') is not None):
                        base_searches_to_update.add(kpi['base_search_id'])
                continue

            #If the entity rules are different, then everything needs to be updated
            if old_service.get('entity_rules') != service.get('entity_rules'):
                for s in [service, old_service]:
                    kpis = s.get('kpis',[])
                    for kpi in kpis:
                        if (kpi['search_type'] == 'shared_base' and
                                kpi.get('base_search_id') is not None):
                            base_searches_to_update.add(kpi['base_search_id'])
                continue

            #Get all of the previously referenced KPIs
            prior_base_searches = set()
            prior_enabled_base_searches = set()
            old_kpis = old_service.get('kpis', [])
            for kpi in old_kpis:
                if (kpi.get('search_type') == 'shared_base' and
                        kpi.get('base_search_id') is not None):
                    prior_base_searches.add(kpi['base_search_id'])
                    existing_ids.append(kpi['base_search_id'])
                    #If the kpi was enabled previously, then we want to add it
                    if kpi.get('enabled') == 1:
                        prior_enabled_base_searches.add(kpi['base_search_id'])

            #Now we should have two sets that tell us what the current base searches are and what the
            #prior base searches were, we want things that fall outside of the intersection of the two
            base_searches_to_update.update(prior_base_searches.symmetric_difference(current_base_searches))

            #Now we add the base searches where the dimensionality changed.
            #If it goes from enabled -> disabled or disabled -> enabled, then it should show up in only one of
            #the sets, therefore we want to ony add whats in the symmetric differences
            base_searches_to_update.update(prior_enabled_base_searches.symmetric_difference(current_enabled_base_searches))

        #We now should have a set of all base searches that need an update
        refresh_jobs = []
        logger.debug('Shared base update issued tid=%s searches=%s', transaction_id, base_searches_to_update)
        for base_search in base_searches_to_update:
            refresh_jobs.append(
                self.get_refresh_job_meta_data(
                    'update_shared_base_search',
                    [base_search],
                    'kpi_base_search',
                    change_detail = {'existing_ids': existing_ids},
                    transaction_id=transaction_id
                ))
        return refresh_jobs

    def identify_dependencies(self, owner, objects, method, req_source='unknown', transaction_id=None):
        """
        Assess refresh job data based upon changes
        @param {string} owner: user which is performing this operation
        @param {list} objects: list of object
        @param {string} method: method name
        @param {string} req_source: request source
        @return: a tuple
            {boolean} set to true/false if dependency update is required
            {list} list - list of refresh job, each element has the following
                change_type: <identifier of the change used to pick change handler>,
                changed_object_key: <Array of changed objects' keys>,
                changed_object_type: <string of the type of object>
        """
        refresh_jobs = []
        is_refresh_required = False
        if not utils.is_valid_list(objects):
            logger.error("%s resource did not passed valid object list:%s", req_source, objects)
            return is_refresh_required, refresh_jobs

        fields_filter = None
        # If delete, then fetch only whats needed to determine change which is a much smaller set than for other ops
        if method == CRUDMethodTypes.METHOD_DELETE:
            fields_filter = ['_key', 'object_type', 'kpis._key', 'kpis.adaptive_thresholds_is_enabled',
                             'kpis.adaptive_thresholding_training_window', 'kpis.search_type', 'kpis.base_search_id',
                             'kpis.enabled']
        persisted_services = self.get_persisted_objects_by_id(
            owner,
            object_ids=[service.get('_key') for service in objects],
            req_source=req_source,
            fields=fields_filter
        )

        persisted_services_dict = dict((x['_key'], x) for x in persisted_services)

        refresh_jobs.extend(self.get_shared_base_search_update_jobs(objects, persisted_services_dict, transaction_id))

        updated_entities_service_keys = []
        entity_updates_needed_detail = {'method': method, 'service_info': {}}
        if method == "DELETE":
            deleted_kpis = []
            atad_changed_kpis = {}
            kpi_dict = {}
            kpi_svc_dict = {}  # kpi to service mapping
            for service in persisted_services:
                for kpi in service.get("kpis", []):
                    if not utils.is_valid_dict(kpi):
                        # Be resilient
                        continue
                    kpi_dict[kpi.get("_key")] = kpi
                    kpi_svc_dict[kpi.get("_key")] = service.get("_key")

                atad_changed_kpis.update(self._determine_changed_kpis_at_ad(None, service,
                                                                            "adaptive_thresholds_is_enabled",
                                                                            "adaptive_thresholding_training_window"))
                for kpi in service.get("kpis", []):
                    if not utils.is_valid_dict(kpi):
                        # Be resilient
                        continue
                    if utils.is_valid_dict(kpi):
                        kpi_id = kpi.get('_key', '')
                        deleted_kpis.append(kpi_id)

                # Service delete implies, any entity associated with the service via inclusion rules must be updated
                entity_updates_needed_detail['service_info'][service["_key"]] = {
                    'title': service.get('title')
                }
                updated_entities_service_keys.append(service["_key"])

            self._enqueue_atad_refresh_jobs(refresh_jobs, kpi_dict, kpi_svc_dict, 'service_kpi_at', atad_changed_kpis, transaction_id)

            refresh_jobs.append(
                self.get_refresh_job_meta_data(
                    "delete_service",
                    [service.get('_key') for service in objects],
                    self.object_type,
                    change_detail={"deleted_kpis": deleted_kpis},
                    transaction_id=transaction_id
                )
            )

            if len(entity_updates_needed_detail['service_info']) > 0:
                refresh_jobs.append(
                    self.get_refresh_job_meta_data(
                        "service_entities_update",
                        updated_entities_service_keys,
                        self.object_type,
                        entity_updates_needed_detail,
                        transaction_id=transaction_id
                    )
                )
        else:
            # Get service bulk
            # add key if does not exists
            for service in objects:
                if service.get("_key") is None:
                    service["_key"] = ITOAInterfaceUtils.generate_backend_key()

            saved_search_changed_kpis = {}
            updated_entities_service_keys = []  # contain list of array of services _key which has entities list updated
            updated_entities_service_detail = {}  # dict of service key to added and removed entities for that service
            deleted_kpi_ids = []
            deleted_kpi_detail = {}
            backfill_enabled_service_keys = []  # list of array of services _key which has KPIs with backfill enabled
            backfill_enabled_service_detail = {}  # dict of service key to list of KPIs with backfill enabled
            kpi_dict = {}  # kpiid -> KPI
            kpi_svc_dict = {}  # kpiid -> serviceid
            at_changed_kpis = {}  # kpiid -> change summary (e.g. 'on', 'off', 'changed')
            ad_changed_kpis = {}  # kpiid -> change summary (e.g. 'on', 'off', 'changed')
            cad_changed_kpis = {} # kpiid -> change summary (e.g. 'on', 'off', 'changed')
            alert_period_changed_kpis = {}
            updated_service_dependencies = {}
            service_kpis_changed_to_shared_search = {} # kpis which are changed from adhoc/datamodel to shared based

            objects, remove_depending_on_me = self._validate_service_dependencies(objects, method)

            # add refresh queue job for updating 'services_depends_on' based on 'services_depending_on_me'
            if remove_depending_on_me:
                 updated_service_dependencies['services_depending_on_me'] = remove_depending_on_me

            for service in objects:
                service_title = service.get('title', '')
                persisted_service = persisted_services_dict.get(service['_key'])

                # Get list of kpis which is changed from ad-hoc/datamodel to shared search, can possible only for
                # upgrade
                if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:
                    list_kpis_changed_to_shared_search = self._determine_changed_search_type(service, persisted_service)
                    service_key = service.get('_key')
                    if len(list_kpis_changed_to_shared_search) > 0 and\
                                    service_key in service_kpis_changed_to_shared_search:
                        service_kpis_changed_to_shared_search[service_key].extend(list_kpis_changed_to_shared_search)
                    elif len(list_kpis_changed_to_shared_search) > 0:
                        service_kpis_changed_to_shared_search[service_key] = list_kpis_changed_to_shared_search

                if persisted_service is not None:
                    for kpi in persisted_service.get("kpis", []):  # kpi_dict must include info from persisted services
                        if not utils.is_valid_dict(kpi):
                            # Be resilient
                            continue
                        kpi_dict[kpi.get("_key")] = kpi            # to handle KPI deletions gracefully
                        kpi_svc_dict[kpi.get("_key")] = persisted_service.get("_key")
                for kpi in service.get("kpis", []):  # append/overwrite kpi_dict entries with info for the current service
                    if not utils.is_valid_dict(kpi):
                        # Be resilient
                        continue
                    kpi_dict[kpi.get("_key")] = kpi
                    kpi_svc_dict[kpi.get("_key")] = service.get("_key")

                ad_changed_kpis.update(self._determine_changed_kpis_at_ad(service, persisted_service,
                                                                          "anomaly_detection_is_enabled", None,
                                                                          settings_field='trending_ad'))

                at_changed_kpis.update(self._determine_changed_kpis_at_ad(service, persisted_service,
                                                                          "adaptive_thresholds_is_enabled",
                                                                          "adaptive_thresholding_training_window"))

                cad_changed_kpis.update(self._determine_changed_kpis_at_ad(service, persisted_service,
                                                                          "cohesive_anomaly_detection_is_enabled", None,
                                                                           settings_field='cohesive_ad'))

                alert_period_changed_kpis.update(self._determine_changed_alert_period(service, persisted_service))

                if  not updated_service_dependencies.get('services_depends_on'):
                    updated_service_dependencies['services_depends_on'] = {}

                updated_service_dependencies['services_depends_on'].update(self._determine_changed_service_dependencies(service,
                                                                                                 persisted_service))

                if persisted_service is not None:
                    # Save away entity rules to handle entity membership in refresh job
                    entity_updates_needed_detail['service_info'][service["_key"]] = {
                        'entity_rules': service.get('entity_rules', []),
                        'title': service.get('title')
                    }
                    updated_entities_service_keys.append(service["_key"])

                    # Check of KPI deletion
                    persisted_kpi_ids = [persisted_kpi.get("_key") for persisted_kpi in persisted_service.get("kpis", [])]
                    kpi_ids = [kpi.get("_key") for kpi in service.get("kpis", [])]
                    service_deleted_kpis = list(set(persisted_kpi_ids)-set(kpi_ids))
                    if len(service_deleted_kpis) > 0:
                        deleted_kpi_detail[service.get('_key')] = service_deleted_kpis
                        deleted_kpi_ids.extend(service_deleted_kpis)

                    # Check for backfill being enabled
                    persisted_kpi_backfill_on = dict((kpi.get("_key"), kpi)
                                                    for kpi in persisted_service.get("kpis", [])
                                                    if kpi.get("backfill_enabled"))
                    kpi_backfill_on = dict((kpi.get("_key"), kpi)
                                                    for kpi in service.get("kpis", [])
                                                    if kpi.get("backfill_enabled"))
                    enabled_backfill_kpis = list(set(kpi_backfill_on)-set(persisted_kpi_backfill_on))
                    if len(enabled_backfill_kpis) > 0:
                        logger.debug('found backfill kpis on update service')
                        backfill_enabled_service_detail[service.get("_key")] = {"kpis": enabled_backfill_kpis}
                        backfill_enabled_service_keys.append(service.get("_key"))
                else:
                    # Service create implies, any entity associated with the service via inclusion rules must be updated
                    # Save away entity rules to handle entity membership in refresh job
                    entity_updates_needed_detail['service_info'][service["_key"]] = {
                        'entity_rules': service.get('entity_rules', []),
                        'title': service.get('title')
                    }
                    updated_entities_service_keys.append(service["_key"])
                    # it would be new service is does not exists in KV store
                    if len(service.get("entities", [])) > 0:
                        logger.debug('found backfill kpis on new service')
                        updated_entities_service_detail[service.get("_key")] = {"added_entities": service.get("entities", []), "removed_entities": []}
                        updated_entities_service_keys.append(service.get("_key"))

                    # get the set of KPIs with backfill enabled
                    kpi_backfill_on = dict((kpi.get("_key"), kpi) for kpi in service.get("kpis", []) if kpi.get("backfill_enabled"))
                    if len(kpi_backfill_on) > 0:
                        backfill_enabled_service_detail[service.get("_key")] = {"kpis": kpi_backfill_on.keys()}
                        backfill_enabled_service_keys.append(service.get("_key"))

                # Handling all the savedsearch generations
                saved_search_changed_kpis.update(self._determine_generate_changed_search_param(service,
                                                                                               persisted_service))

            self.update_savedsearches(service.get('_key'), saved_search_changed_kpis)

            # update information to job queue
            if len(entity_updates_needed_detail['service_info']) > 0:
                refresh_jobs.append(
                    self.get_refresh_job_meta_data(
                        "service_entities_update",
                        updated_entities_service_keys,
                        self.object_type,
                        change_detail=entity_updates_needed_detail,
                        transaction_id=transaction_id
                    )
                )
            if len(deleted_kpi_ids) > 0:
                refresh_jobs.append(
                    self.get_refresh_job_meta_data("service_kpi_deletion", deleted_kpi_ids, "kpi",
                        change_detail={'service_kpi_mapping': deleted_kpi_detail}, transaction_id=transaction_id))
            if len(backfill_enabled_service_keys) > 0:
                refresh_jobs.append(
                    self.get_refresh_job_meta_data("service_kpi_backfill_enabled", backfill_enabled_service_keys, self.object_type,
                        change_detail=backfill_enabled_service_detail, transaction_id=transaction_id)
                )

            if len(updated_service_dependencies) > 0:

                updated_service_dependencies_keys = []

                if updated_service_dependencies.get('services_depends_on'):
                    updated_service_dependencies_keys.extend(updated_service_dependencies['services_depends_on'].keys())
                if updated_service_dependencies.get('services_depending_on_me'):
                    updated_service_dependencies_keys.extend(updated_service_dependencies['services_depending_on_me'].keys())

                if updated_service_dependencies_keys:

                    refresh_jobs.append(
                        self.get_refresh_job_meta_data("service_dependency_changed", updated_service_dependencies_keys, self.object_type,
                            change_detail=updated_service_dependencies, transaction_id=transaction_id)
                    )

            # Create job to delete KPI saved search because it is changed from Ad/hoc to shared
            if len(service_kpis_changed_to_shared_search) > 0:
                refresh_jobs.append(self.get_refresh_job_meta_data('modify_kpi_search_type',
                                                                   service_kpis_changed_to_shared_search.keys(),
                                                                   'service_kpi',
                                                                   change_detail=service_kpis_changed_to_shared_search,
                                                                   transaction_id=transaction_id))

            # Ignore the kpis in the deleted list
            for i in deleted_kpi_ids:
                if i in ad_changed_kpis:
                    ad_changed_kpis.pop(i)
                if i in cad_changed_kpis:
                    cad_changed_kpis.pop(i)

            logger.debug("Changed KPIs for AD %s", ad_changed_kpis)
            self._enqueue_atad_refresh_jobs(refresh_jobs, kpi_dict, kpi_svc_dict, 'service_kpi_ad', ad_changed_kpis, transaction_id)

            logger.debug("Changed KPIs for Cohesive AD %s", cad_changed_kpis)
            self._enqueue_atad_refresh_jobs(refresh_jobs, kpi_dict, kpi_svc_dict, 'service_kpi_cad', cad_changed_kpis, transaction_id)

            logger.debug("Changed KPIs for AT %s", at_changed_kpis)
            self._enqueue_atad_refresh_jobs(refresh_jobs, kpi_dict, kpi_svc_dict, 'service_kpi_at', at_changed_kpis, transaction_id)

            logger.debug("Changed KPIs for alert period %s", alert_period_changed_kpis)

            if len(alert_period_changed_kpis) > 0:
                kpis_keys = list(alert_period_changed_kpis.keys())
                refresh_jobs.append(
                    self.get_refresh_job_meta_data('service_kpi_update_alert_period', kpis_keys, 'kpi',
                        change_detail=alert_period_changed_kpis,
                        transaction_id=transaction_id))

        is_refresh_required = len(refresh_jobs) > 0
        return is_refresh_required, refresh_jobs

    def _enqueue_atad_refresh_jobs(self, refresh_jobs, kpi_dict, kpi_svc_dict, change_type, changed_kpis, transaction_id):
        """
        Change jobs for anomaly detection or adaptive thresholding get created
        whenever we detect that the on/off flag has changed state, or when key
        parameters (e.g. training window, or thresholding method) have changed.

        A job will be created per training window track; the job will contain a list of
        KPIs with AD or AT turned on. The change handler will create an appropriate search.
        If an empty list is passed for the changed_object_key's, the handler will
        delete the saved search for that track

        @param refresh_jobs: refresh jobs list
        @param kpi_dict: full dict of all KPI objects for all services (keyed by KPI ID)
        @param kpi_svc_dict: kpiid -> serviceid mapping
        @param changed_kpis: full dict of changed KPI objects for all services;
          keyed by KPI ID, values are one of ('on', 'off', 'changed'),
          depending on whether anomaly detection / adaptive thresholding
            - was newly switched on
            - was newly switched off
            - had parameters changed
        """
        if change_type == 'service_kpi_ad':
            STATE_FIELD = 'anomaly_detection_is_enabled'
            TRACK_FIELD = ''
            KPI_DATA_FIELDS = ['trending_ad']

        elif change_type == 'service_kpi_at':
            STATE_FIELD = 'adaptive_thresholds_is_enabled'
            TRACK_FIELD = 'adaptive_thresholding_training_window'
            KPI_DATA_FIELDS = []

        elif change_type == 'service_kpi_cad':
            STATE_FIELD = 'cohesive_anomaly_detection_is_enabled'
            TRACK_FIELD = ''
            KPI_DATA_FIELDS = ['cohesive_ad']

        else:
            raise ValueError(_("Invalid `change_type` argument: %s") % change_type)

        if len(changed_kpis) == 0:
            logger.debug("No change detected in AT/AD settings")
            return # no-op if the set of affected KPIs is empty

        def _get_kpi_data_dict(kpi):
            data_dict = dict((x, kpi.get(x)) for x in KPI_DATA_FIELDS)
            data_dict['anomaly_detection_is_enabled'] = kpi.get(STATE_FIELD)
            data_dict['training_window'] = kpi.get(TRACK_FIELD)
            data_dict['service_id'] = kpi_svc_dict.get(kpi['_key'])
            data_dict['change_summary'] = changed_kpis.get(kpi['_key']) or 'unchanged'
            data_dict['alert_period'] = str(kpi.get('alert_period')) + 'm'
            return data_dict

        _kpi_data = {}  # abridged KPI dict
        _kpi_ids = []
        for kpi_id in changed_kpis:
            _kpi_data[kpi_id] = _get_kpi_data_dict(kpi_dict[kpi_id])
            _kpi_ids.append(kpi_id)

        refresh_jobs.append(
            self.get_refresh_job_meta_data(change_type, _kpi_ids, 'kpi', change_detail={'kpi_data': _kpi_data}, transaction_id=transaction_id))

    def get_entities(self, owner, service_ids, req_source="static services link", transaction_id=None):
        """
        Get entities which contains of one of given service id
        @param {string} owner: owner
        @param {list} service_ids: list of service id
        @param {string} req_source:
        @return: {list} - list of service ids
        """
        filter_data = {
            '$or': [{'services': service_id} for service_id in service_ids]
        }

        entity_object = ItsiEntity(self.session_key, self.current_user_name)
        entities = entity_object.get_bulk(owner, filter_data=filter_data, req_source=req_source, transaction_id=transaction_id)
        return entities

    def delete_kpi_saved_searches(self, kpi_saved_search_names):
        """
        Delete kpi alert saved searches
        Note this is a primitive and performs no clean up of service objects
        @param {list} kpi_saved_search_names: list of search names to delete
        @return: True or False based upon operation success or failure
        :exception exception if things do not go well
        """
        status_ok = True
        # Delete saved search for kpi
        for saved_search_name in kpi_saved_search_names:
            #TODO: delete_kpi_saved_searches is DEFINITELY broken and needs an update
            #This is not the kind of heuristic I should be going with to determine if we can delete the search
            #We're basically checking to make sure that the indicator search does not contain the search prefix we expect
            if ItsiSharedAdhocSearch.search_prefix in saved_search_name:
                continue
            ret = True
            try:
                ret = SavedSearch.delete_search(self.session_key, saved_search_name)
            except splunk.ResourceNotFound:
                logger.exception('Saved search "%s" was not found, ignoring delete', saved_search_name)
            except Exception as e:
                logger.exception('Caught exception trying to delete saved search "%s"', saved_search_name)
                ret = False

            if not ret:
                logger.error('Failed to delete saved search="%s"', saved_search_name)
                status_ok = False
            else:
                logger.info('Successfully deleted saved search="%s"', saved_search_name)
        return status_ok

    def _update_savedsearches(self, saved_searches):
        """
        Update given saved searches synchronously.

        @type saved_searches: dict
        @param saved_searches: dictionary. key'ed by kpi title. value being saved search settings

        @rtype: None
        @returns nothing.
        """
        for ss in saved_searches:
            title = ss.pop('kpi_title', None)
            acl_update = ss.pop('acl_update', True)
            ret = SavedSearch.update_search(self.session_key, ss.get('name'), 'itsi', 'nobody', **ss)
            if ret:
                logger.debug("Successfully created/update saved search=%s for kpi=%s", ss.get('name'), title)
                if acl_update:
                    ret = SavedSearch.update_acl(self.session_key, ss.get('name'),
                            'nobody' #All searches get saved under the nobody context
                            )
                    if not ret:
                        msg = _('Failed to update ACL settings for savedsearch: "{}"; KPI: "{}". Please do this manually.').format(
                            ss.get('name'), title)
                        logger.error(msg)
                        # At this stage we could either:
                        # i) raise an exception, delete KPI and bail out or
                        # ii) continue with KPI creation and let Admin manually change
                        #       ACL settings for this KPI Saved Search via GUI.
                        # We will execute ii)
            else:
                message = _("Failed to create saved search={0} for kpi={1}" .format(ss.get('name'), title))
                logger.error(message)
                raise Exception(message)
        return

    def post_save_setup(self, owner, ids, services, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Performs additional synchronous operations on other objects after writing services to kvstore.
        @type owner: string
        @param owner: user who is performing this operation
        @type ids: List of dict identifiers in format {"_key": <key>} returned by kvstore, pairity with objects passed in
        @param ids: list of dict
        @type services: list of dictionary
        @param objects: list of objects being written
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @return: none, throws exceptions on errors
        """
        # NOTE: Here, we update base service templates synchronously after service creation/update is done.
        # Considering, number of service template objects would not be as high as other itoa objects like
        # services and entities, we're performing synchronous update of service template in bulk here. If,
        # we hit performance issues with synchronous update of service templates, then we can move it to
        # async refresh queue job, using change handler.

        if self.base_service_templates is not None and len(self.base_service_templates) > 0:
            service_template_interface = instantiate_object(self.session_key, 'nobody',
                                                            'base_service_template', logger=logger)
            service_template_interface.skip_service_template_update = True
            service_template_interface.save_batch(owner, self.base_service_templates,
                                                  validate_names=True,
                                                  req_source=req_source,
                                                  ignore_refresh_impacted_objects=True,
                                                  method=CRUDMethodTypes.METHOD_UPDATE,
                                                  transaction_id=transaction_id)
            service_template_interface.skip_service_template_update = False
            logger.info('Total `{0}` base service templates updated after update/creation '
                        'of `{1}` linked services. transaction_id = {2}'.format(len(self.base_service_templates),
                                                                                ids, transaction_id))
            # cleanup service templates
            del self.base_service_templates

    def update_savedsearches(self, service_key, saved_search_changed_kpis, transaction_id=None):
        """
        Update and generate the savedsearches
        @type service_key:  basestring
        @param service_key: service _key
        @type saved_search_changed_kpis: dict
        @param saved_search_changed_kpis: list of kpis that need to be updated
        @type transaction_id: basestring
        @param transaction_id: transcation id for debugging purpose
        @rtype: None
        @returns nothing
        """
        refresh_jobs = []
        refresh_jobs_change_details = {}
        savedsearch_list = []

        for kpi_id, savedsearch in saved_search_changed_kpis.iteritems():
            savedsearch_list.append(savedsearch)
            refresh_jobs_change_details[kpi_id] = {'search_data': json.dumps(savedsearch),
                                                   'kpi_title': savedsearch.get('title')}
        size = len(savedsearch_list)
        if size == 0:
            return
        if 0 < size < 10:
            self._update_savedsearches(savedsearch_list)
        else:
            refresh_jobs.append(self.get_refresh_job_meta_data(
                'create_or_update_kpi_saved_search',
                service_key, self.object_type,
                change_detail=refresh_jobs_change_details,
                transaction_id=transaction_id
            ))
            logger.info('Creating create_or_update_kpi_saved_search refresh jobs for service=%s', service_key)
            self.create_refresh_jobs(refresh_jobs, synchronous=self.synchronous)

    @staticmethod
    def add_required_fields_to_new_kpi_from_servcie_template(new_kpi, service_template_id):
        """
        Add required fields to a new kpi, while adding it to a service from a service template.

        @type new_kpi: dict
        @param new_kpi: new kpi to be added in service.
        @type service_template_id: basestring
        @param service_template_id: key of service template to which service is linked
        @return: None
        """
        fields_to_be_added_to_kpi = (
            ('_key', ITOAInterfaceUtils.generate_backend_key()),
            ('type', 'kpis_primary'),
            ('base_service_template_id', service_template_id)
        )

        for field, value in fields_to_be_added_to_kpi:
            new_kpi[field] = value

    def update_services_with_base_service_templates(self, services, persisted_services, owner, req_source='unknown',
                                                    method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Update service objects with base service template objects content, when service has to be created from
        base service template.
        If, no service is linked to base service template, then, does nothing.
        @type services: list
        @param services: list of service objects
        @type persisted_services: list
        @param persisted_services: list of persisted services in kvstore
        @type owner: string
        @param owner: user who is performing this operation
        @type req_source: string
        @param req_source: string identifying source of this request
        @type method: basestring
        @param method: operation type. Defaults to upsert.
        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        @return: none, throws exceptions on errors
        """
        # used to get service templated id from service id
        service_to_service_template_map = {}
        service_template_get_filter = {
            '$or': []
        }

        for service in services:
            if not isinstance(service, dict):
                self.raise_error_bad_validation(
                    logger, 'Invalid type for service. Expected json dict, received {}.'.format(type(service).__name__)
                )

            if service.get('_key', ''):
                service_to_service_template_map[service.get('_key')] = service.get('base_service_template_id', '')
            else:
                # if service doesn't have a key, then assume it is a new service to be created
                if service.get('base_service_template_id'):
                    service_template_get_filter['$or'].append({'_key': service.get('base_service_template_id')})

        services_unlink_map = {}
        persisted_services_kpis_map = {}
        process_services = False
        # validation of update request for services linked to service templates. always validate
        # base_service_template_id in service by comparing it with persisted service in kvstore. We do not allow
        # re-linking of service to another service template, through update/bulk-update endpoint for service.
        if method != CRUDMethodTypes.METHOD_CREATE:
            for persisted_service in persisted_services:
                # update request for service
                if persisted_service.get('_key') in service_to_service_template_map:
                    # Unlink operation
                    if persisted_service.get('base_service_template_id', '') \
                            and not service_to_service_template_map.get(persisted_service.get('_key'), ''):
                        # Get related service template
                        service_template_get_filter['$or'].append({
                                    '_key': persisted_service.get('base_service_template_id')
                        })
                        services_unlink_map[persisted_service['_key']] = persisted_service.get('base_service_template_id')
                        # pop the service ids from map which are not create service request from service template
                        service_to_service_template_map.pop(persisted_service.get('_key'), None)

                    # if base service template id for a service in request is not same as for the
                    # service in kvstore, then raise bad validation error
                    elif persisted_service.get('base_service_template_id', '') != service_to_service_template_map.get(
                            persisted_service.get('_key', ''), ''):
                        self.raise_error_bad_validation(logger,
                                                        'Invalid service template id provided while updating '
                                                        'service `{0}`. Cannot re-link service to another service template '
                                                        'through this endpoint, check ITSI API docs to find API for '
                                                        're-linking of service to another service template. Expected '
                                                        'service template id `{1}`, found `{2}`'
                                                        .format(persisted_service.get('_key', None),
                                                                persisted_service.get('base_service_template_id', None),
                                                                service_to_service_template_map.get(
                                                                    persisted_service.get('_key', ''), None))
                                                        )
                    # check for update in KPI thresholds and validate update requested, for
                    # services linked to service template
                    elif persisted_service.get('base_service_template_id', '') and \
                            service_to_service_template_map.get(persisted_service.get('_key'), ''):
                        for kpi in persisted_service.get('kpis', []):
                            if kpi['_key'].startswith(self.shkpi_starts_with) or not kpi.get('base_service_template_id', ''):
                                continue
                            if persisted_service['_key'] not in persisted_services_kpis_map:
                                persisted_services_kpis_map[persisted_service['_key']] = {
                                    kpi['_key']: kpi
                                }
                            else:
                                persisted_services_kpis_map[persisted_service['_key']][kpi['_key']] = kpi
                        if persisted_services_kpis_map:
                            process_services = True
                        # pop the service ids from map which are not create service request from service template
                        service_to_service_template_map.pop(persisted_service.get('_key'), None)

        # add service templates to filter to be fetched
        for service_id in service_to_service_template_map:
            # only fetch service templates with valid key
            if service_to_service_template_map.get(service_id):
                service_template_get_filter['$or'].append({'_key': service_to_service_template_map[service_id]})

        service_templates_map = {}
        # fetch service templates for creating services or for unlinking services
        if len(service_template_get_filter.get('$or')) > 0:
            logger.info('Some of the service objects in create/update request are requested to be'
                        ' created or unlinked from service template. transaction_id="%s"' % transaction_id)
            service_template_interface = instantiate_object(self.session_key, 'nobody',
                                                            'base_service_template', logger=logger)

            # cleanup class variable before using it
            del self.base_service_templates
            # fetch service template objects from kvstore in bulk
            self.base_service_templates = service_template_interface.get_bulk(owner,
                                                                              req_source=req_source,
                                                                              filter_data=service_template_get_filter,
                                                                              transaction_id=transaction_id)
            if len(self.base_service_templates) == 0:
                self.raise_error_bad_validation(logger,
                                                'Could not find service template object(s) with id(s) `{}`. '
                                                'Cannot create service(s) from non-existent service template(s).'
                                                .format(service_template_get_filter.get('$or'))
                                                )

            # construct service template key to object map. used by service object to
            # quickly get service template content by id
            for service_template in self.base_service_templates:
                service_templates_map[service_template.get('_key')] = service_template
            process_services = True

        if process_services:
            for service in services:
                # handle new service to be created from base service template. service without
                # a key means a new service to be created
                if service.get('base_service_template_id') and \
                        (not service.get('_key') or service.get('_key') in service_to_service_template_map):
                    service_template = service_templates_map.get(service.get('base_service_template_id'), {})

                    if not utils.is_valid_str(service.get('_key')):
                        service['_key'] = ITOAInterfaceUtils.generate_backend_key()

                    # generate service health kpi
                    service['kpis'] = [ITOAInterfaceUtils.generate_shkpi_dict(service['_key'])]

                    # tuple of tuples containing field name and it's default value, in case field is missing
                    # from service template
                    fields_to_copy_from_template = (('kpis', []), ('entity_rules', []), ('serviceTemplateId', ''))
                    for field, default_value in fields_to_copy_from_template:
                        if field == 'kpis':
                            service[field].extend(copy.deepcopy(service_template.get(field, default_value)))
                            continue
                        service[field] = copy.deepcopy(service_template.get(field, default_value))

                    # tuple of tuples containing field name to be added to kpis as first element and
                    # field's value as second element of tuple
                    fields_to_be_added_to_kpi = (
                        # considering backfill fields are sent in service payload, while creating
                        # service from service template
                        ('backfill_enabled', service.get('backfill_enabled', False)),
                        ('backfill_earliest_time', service.get('backfill_earliest_time', '-7d'))
                    )
                    # add fields to service kpis not present in service template kpis
                    for kpi in service.get('kpis', []):
                        if kpi['_key'].startswith(self.shkpi_starts_with):
                            continue
                        self.add_required_fields_to_new_kpi_from_servcie_template(kpi, service.
                                                                                  get('base_service_template_id'))
                        for field, value in fields_to_be_added_to_kpi:
                            kpi[field] = value

                        # pop below field, if it is passed while creation of service from service
                        # template. as it can cause repercussions while updating unchanged linked
                        # kpis with service template in BaseServiceTemplateUpdateHandler
                        kpi.pop('linked_kpi_thresholds_updated', None)

                    # pop redundant fields.
                    service.pop('backfill_enabled', None)
                    service.pop('backfill_earliest_time', None)

                    logger.debug('Updated service content of `{0}` with base service template `{1}`. transaction_id '
                                 '= {2}'.format(service.get('_key'),
                                                service.get('base_service_template_id'),
                                                transaction_id))

                    #####
                    # Make updates to service template object to reflect link with new service. Since, the newly linked
                    # service is a new service, therefore, we don't need to validate, if service key already exists in
                    # linked services list or not. Actual update of service templates in kvstore occurs in
                    # post_save_setup(), after service objects get saved in kvstore.
                    #####
                    if service_template.get('linked_services', None) is not None:
                        if service.get('_key') not in service_template['linked_services']:
                            service_template['linked_services'].append(service.get('_key'))
                    else:
                        service_template['linked_services'] = [service.get('_key')]

                elif services_unlink_map and service.get('_key') in services_unlink_map:
                    # Unlink service from service template
                    # Please note: since the payload contains all the necessary changes on service
                    # Only service template unlink is needed
                    service_template = service_templates_map.get(services_unlink_map[service.get('_key')], {})
                    if service.get('_key') in service_template['linked_services']:
                        service_template['linked_services'].remove(service.get('_key'))

                # Validate KPI content and check for KPI thresholds update, for services linked to template
                elif service.get('_key') in persisted_services_kpis_map:
                    for kpi in service.get('kpis', []):
                        if kpi['_key'].startswith(self.shkpi_starts_with):
                            continue
                        if kpi['_key'] in persisted_services_kpis_map[service['_key']]:
                            persisted_service_kpi = persisted_services_kpis_map[service['_key']][kpi['_key']]
                            if not kpi.get('base_service_template_id', ''):
                                self.raise_error_bad_validation(
                                    logger, 'The base_service_template_id must be provided. A KPI cannot be unlinked '
                                            'from a service template, only a service can be unlinked from a service '
                                            'template. service_id="%s", kpi_id="%s"' %
                                            (service.get('_key', None), kpi.get('_key', None))
                                )
                            elif kpi.get('base_service_template_id', '') != persisted_service_kpi.get('base_service_template_id', ''):
                                self.raise_error_bad_validation(
                                    logger, 'Invalid base_service_template_id provided for KPI. A service can be linked'
                                            ' to only one service template. service_id="%s", kpi_id="%s", '
                                            'service_base_template_id="%s", kpi_base_template_id="%s"' %
                                            (
                                                service.get('_key', None),
                                                kpi.get('_key', None),
                                                service.get('base_service_template_id', None),
                                                kpi.get('base_service_template_id', None)
                                             )
                                )
                            # make sure that none of the service template linked KPI search attribute
                            # is changed, in update request
                            for attr in ItsiKpi.get_kpi_search_attributes():
                                if kpi.get(attr, '') != persisted_service_kpi.get(attr, ''):
                                    self.raise_error_bad_validation(
                                        logger, 'Invalid update request. Cannot update search attributes for KPI '
                                                'linked to service template. To update KPI search attributes, '
                                                'update the corresponding KPI in service template and then '
                                                'push out changes to linked services. service_id="%s", kpi_id="%s", '
                                                'service_template_id="%s", attribute_update_requested="%s"' % (
                                                    service.get('_key'), kpi.get('_key'),
                                                    kpi.get('base_service_template_id'), attr
                                                 )
                                    )

                            # if 'linked_kpi_thresholds_updated' is already true in persisted kpi, don't reset it
                            if not persisted_service_kpi.get('linked_kpi_thresholds_updated', False):
                                for field in ItsiKpi.get_kpi_threshold_fields():
                                    if kpi.get(field, '') != persisted_service_kpi.get(field, ''):
                                        kpi['linked_kpi_thresholds_updated'] = True
                                        break
                            else:
                                kpi['linked_kpi_thresholds_updated'] = persisted_service_kpi.get(
                                   'linked_kpi_thresholds_updated'
                                )
                        # raise error, if new kpi is found in service, which is linked to service template.
                        # addition of new kpi to service which is linked to service template, could only be
                        # done by adding that kpi to service template and then pushing out changes to linked
                        # services.
                        elif kpi.get('base_service_template_id', ''):
                            self.raise_error_bad_validation(
                                logger, 'Invalid update request. Cannot add a new KPI with a link to service '
                                        'template, through service update request. To add a new KPI with a link to '
                                        'service template, add the KPI to the service template, then push out the '
                                        'changes to linked services. service_id="%s", kpi_id="%s"' %
                                        (service.get('_key', None), kpi.get('_key', None))
                            )

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Any additional setup that is required to be done.

        @type owner: basestring
        @param owner: request owner. "nobody" or some username.

        @type objects: list
        @param objects: List of service type objects

        @type req_source: basestring
        @param req_source: Source requesting this operation.

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.
        
        @rtype: None
        @return: Nothing
        """
        def _normalize_enabled_flag_to_binary(input_):
            false_things = [0, '0', 'false']
            if input_ in false_things:
                return 0
            else:
                return 1

        if not utils.is_valid_list(objects):
            self.raise_error_bad_validation(
                logger, 'Invalid type for service(s). Expected list, received {}'.format(type(objects).__name__))

        # fetch all persisted services to be used for service template processing and validation of kpis
        fields_to_fetch = ['_key', 'kpis._key']
        if method != CRUDMethodTypes.METHOD_CREATE:
            fields_to_fetch.extend(
                ['base_service_template_id', 'kpis.base_service_template_id'] +
                ItsiKpi.get_kpi_threshold_fields(for_kvstore_fetch=True) +
                ItsiKpi.get_kpi_search_attributes(for_kvstore_fetch=True)
            )
        persisted_services = self.get_bulk(
            owner, req_source=req_source, fields=fields_to_fetch, transaction_id=transaction_id
        )

        # update service with service template content, if service has to be created from service template.
        # if the request comes from link service template endpoint, skip this step
        if not self.skip_service_template_update:
            self.update_services_with_base_service_templates(objects, persisted_services, owner, req_source=req_source,
                                                             transaction_id=transaction_id)

        self.validate_kpis(owner, objects, persisted_services, method=method, transaction_id=transaction_id)
        self.cleanup_kpis(objects, method)

        for svc in objects:
            if not utils.is_valid_str(svc.get('_key')):
                svc['_key'] = ITOAInterfaceUtils.generate_backend_key()

            # If the flag is not passed in, enable the service
            svc['enabled'] = _normalize_enabled_flag_to_binary(svc.get('enabled', 1))

            kpis = svc.get('kpis', [])

            # Assume no shkpi exists for given service. We'll generate one down below
            shkpi_found = False

            # Generate KPI searches afresh
            for kpi in kpis:
                if kpi['_key'].startswith(self.shkpi_starts_with):
                    shkpi_found = True
                    kpi.update(ITOAInterfaceUtils.generate_shkpi_dict(svc['_key'])) # Always rewrite shkpi
                    continue # Do not populate searches for shkpi

                # validate time policies prior to filling searches
                ItsiKpiTemplate(self.session_key, self.current_user_name).validate_kpi_time_policies(kpi)

                # Populate regular kpi object with search strings.
                ItsiKpi(self.session_key, 'nobody').populate(
                        kpi, svc.get('entity_rules', []),
                        svc.get('_key'), svc.get('title'),
                        svc.get('enabled'), svc.get('sec_grp')
                )
            # End for loop...

            # Create a SHKPI if none is present.
            if not shkpi_found:
                kpis.append(ITOAInterfaceUtils.generate_shkpi_dict(svc['_key']))

            svc['kpis'] = kpis # ... in case, svc object had no kpis initially.

            # Clean up entity rules
            self._cleanup_entity_rules(svc)

        # Service payloads can bloat up significantly after generating searches.
        # If the resultant payload size exceeds allowable document size in KV store,
        # save operation on the service will fail causing stray saved searches
        # and saved search refresh jobs if those operations occur before the save.
        # As a precaution, perform a size limit
        # check after size bloat and before saved searches and refresh jobs are created

        self.storage_interface.check_payload_size(self.session_key, objects)

        return

    @staticmethod
    def _cleanup_entity_rules(service):
        """
        Clean up the all the things from entity rules which are not needed.

        Specifically, clean up the id attribute from entity rule terms. If present, it causes
        backbone destroy call to fail, while deleting an entity rule from UI. As, it assumes
        EntityRuleModel has a persistent store associated to it, when id is present.
        For more info, see ITOA-11342.

        @type service: dict
        @param service: service object
        @return:
        """
        if not isinstance(service.get('entity_rules'), list):
            service['entity_rules'] = []
        entity_rules = service.get('entity_rules')
        # Remove the 'id' attribute from the entity_rules in the service object if present
        for or_rule_term in entity_rules:
            if not isinstance(or_rule_term, dict):
                self.raise_error_bad_validation(
                    logger,
                    _('Invalid type of OR entity rule term specified for service %s. Expected json dict, received %s.')
                    % (service.get('title'), type(or_rule_term).__name__)
                )
            or_rule_term.pop('id', None)

            for and_rule_term in or_rule_term.get('rule_items', []):
                if not isinstance(and_rule_term, dict):
                    self.raise_error_bad_validation(
                        logger,
                        _('Invalid type of AND entity rule term specified for service %s. '
                          'Expected json dict, received %s.') % (service.get('title'), type(and_rule_term).__name__)
                    )
                and_rule_term.pop('id', None)

    def cleanup_kpis(self, services, method=CRUDMethodTypes.METHOD_UPSERT):
        """
        Given a list of services, cleanup the KPIs of all things that are not
        needed.
        Primarily, search strings in time_variate_thresholds_specification &
            aggregate_thresholds

        @type services: list
        @param services: List of service type objects

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @rtype: None
        @return: Nothing
        """
        if method not in (CRUDMethodTypes.METHOD_UPSERT, CRUDMethodTypes.METHOD_CREATE, CRUDMethodTypes.METHOD_UPDATE):
            return

        # Assume that services is a valid list and so are kpis.
        # Assume that each kpi is a valid dictionary.
        # We will also trust that a developer has the sanity to validate data prior to calling us.
        for service in services:
            kpis = service.get('kpis', [])
            for kpi in kpis:
                if kpi.get('search_type', '') != 'shared_base':
                    # cleanup KPIs if they have base search specfic keys for adhoc/datamodel type
                    keys = ('base_search_metric', 'base_search_id')
                    for k in keys:
                        kpi.pop(k, None)

                keys = ('aggregate_thresholds', 'entity_thresholds')
                for k in keys:
                    blob = kpi.get(k, {})
                    if 'search' in blob:
                        blob['search'] = ''

                # clear search strings from policies defined as part of time variate thresholds
                threshold_policies = kpi.get('time_variate_thresholds_specification', {}).get('policies',{})
                for value in threshold_policies.itervalues():
                    for k in keys:
                        blob = value.get(k, {})
                        if 'search' in blob:
                            blob['search'] = ''

                # cleanup service template specific attributes, if service or kpi is not linked to template
                if not service.get('base_service_template_id'):
                    service_template_keys = ('base_service_template_id', 'linked_kpi_thresholds_updated')
                    for key in service_template_keys:
                        kpi.pop(key, None)
                elif not kpi.get('base_service_template_id'):
                    kpi.pop('linked_kpi_thresholds_updated', None)

    def validate_kpis(self, owner, services, persisted_services, method=CRUDMethodTypes.METHOD_UPSERT,
                      transaction_id=None, for_base_service_template=False):
        """
        Validates KPIs for passed in services. Attempts to perform basic validations to prevent KPI
        from breaking the searches. Extensive checks for each field could be added as the need is found
        in favor of saving on performance of service saves.

        @type owner: string
        @param owner: owner context for KV store operations

        @type services: list of dict
        @param services: Services JSON list containing KPIs to validate

        @type persisted_services: list of dict
        @param persisted_services: list of persisted services in kvstore

        @type method: basestring
        @param method: CRUD method type

        @type transaction_id: basestring
        @param transaction_id: transaction_id for end-end tracing

        @type for_base_service_template: bool
        @param for_base_service_template: True, if validating kpis for Base Service Template.
                                          Else, False.

        @return: None, raises exceptions on invalid KPIs
        """
        if for_base_service_template:
            object_type = 'base service template'
        else:
            object_type = 'service'

        # Accumulate map of service to KPI keys for existing services to validate KPI
        # key uniqueness below
        kpi_keys_map = {}
        kpi_keys_dict = {} # Used to quickly detect KPI key duplication within passed in services
        kpi_title_list = []

        itsi_kpi = ItsiKpi(self.session_key, self.current_user_name)

        for service in services:
            if not isinstance(service, dict):
                self.raise_error_bad_validation(
                    logger, 'Invalid type for {0}. Expected json dict, received {1}.'.format(object_type, type(service).__name__))

            kpis = service.get('kpis', [])
            if not isinstance(kpis, list):
                self.raise_error_bad_validation(
                    logger, 'Invalid type for KPIs. Expected list, received %s' % type(kpis).__name__)

            # Per KPI validations
            count_shkpi = 0
            for kpi in kpis:
                if not isinstance(kpi, dict):
                    self.raise_error_bad_validation(
                        logger, 'Invalid type for KPI. Expected json dict, received %s' % type(kpi).__name__)

                kpi_key = kpi.get('_key')
                if not utils.is_valid_str(kpi_key):
                    self.raise_error_bad_validation(logger, 'Missing key. KPI must have a "_key" populated.')

                if kpi_key.startswith(self.shkpi_starts_with):
                    count_shkpi += 1
                    continue # Skip remaining validations for SH-KPI

                service_key = service.get('_key', '') # Accumulate KPIs in new service with key
                if utils.is_valid_str(service_key):
                    if service_key not in kpi_keys_map:
                        kpi_keys_map[service_key] = []

                    if for_base_service_template and kpi_key in kpi_keys_map[service_key]:
                        self.raise_error_bad_validation(logger, 'KPI keys are not unique within the same'
                                                                ' {0}. KPIs must have unique keys.'
                                                                ' Duplicate _key = {1}'.format(object_type, kpi_key))
                    kpi_keys_map[service_key].append(kpi_key)

                if kpi.get('search_type') not in ['adhoc', 'datamodel', 'shared_base']:
                    isadhoc = kpi.get('isadhoc', True) #Assume an adhoc search
                    if isadhoc:
                        kpi['search_type'] = 'adhoc'
                    else:
                        kpi['search_type'] = 'datamodel'

                # For Base Service Template object, do not need to validate kpi key uniqueness across templates and
                # validate characters in key, as base service templates kpis don't generate any searches.
                if not for_base_service_template:
                    if kpi_key in kpi_keys_dict:
                        self.raise_error_bad_validation(
                            logger, 'KPI keys are not unique. KPIs must have unique keys. Eg. _key: ' + kpi_key)
                    else:
                        kpi_keys_dict[kpi_key] = kpi.get('_kpi_method', CRUDMethodTypes.METHOD_UPSERT)

                    # Guard against usage of problematic characters in KPI key primarily for usage in search:
                    #       Dots
                    #       Commas
                    #       Whitespaces
                    #       Pipes
                    #       Paranthesis
                    #       Square brackets
                    #       Single and double quotes
                    #       Equal sign
                    #       Backslash
                    # Prevent use of special terms like service_aggregate and N/A
                    regex_invalid_key_characters = re.compile('service_aggregate|N\\\\A|[=.,"\'()\\[\\]\\s\\|\\\\]+')

                    if re.search(regex_invalid_key_characters, kpi_key):
                        self.raise_error_bad_validation(
                            logger,
                            'Invalid key specified for KPI, Eg. ' + kpi_key + '. ' \
                                'Key cannot contain special characters not supported by SPL. ' \
                                'Key could also not be reserved words like service_aggregate or N/A.'
                        )

                # Perform basic validation and value setting for all the KPIs
                itsi_kpi.validate_kpi_basic_structure(kpi, for_base_service_template)

                # Title has already been validated.
                # Check for duplicated kpi titles within the same service
                kpi_title = kpi.get('title').strip().lower()
                if kpi_title in kpi_title_list:
                    self.raise_error_bad_validation(logger, 'Duplicated KPI title within the same {}.'.format(object_type))
                kpi_title_list.append(kpi_title)

                is_service_entity_filter = kpi.get('is_service_entity_filter', False)

                if kpi.get('search_type') == 'datamodel':
                    try:
                        datamodel_spec = kpi.get('datamodel', {})
                        ItsiKpiSearches.get_datamodel_context(self.session_key,
                            'nobody',
                            datamodel_spec.get('field'),
                            datamodel_spec.get('datamodel'),
                            datamodel_object_name=datamodel_spec.get('object'))
                    except ItoaDatamodelContextError as e:
                        self.raise_error_bad_validation(logger,
                            'Invalid datamodel specification in {0} "{1}" for kpi "{2}". Datamodel info: {3}'.format(
                                object_type,
                                service.get('title', ''),
                                kpi_title,
                                json.dumps(datamodel_spec))
                        )

                service_entity_rules = service.get('entity_rules', [])
                if ((service_entity_rules is None) or (len(service_entity_rules) == 0)) and is_service_entity_filter:
                    self.raise_error_bad_validation(logger,
                        'Cannot filter on entities in {0} "{1}" for kpi "{2}" if there are no entities in the'\
                        ' {3}.'.format(object_type, service.get('title', ''), kpi_title, object_type)
                    )

                if is_service_entity_filter and not utils.is_valid_str(kpi.get('entity_id_fields')):
                    self.raise_error_bad_validation(
                        logger,
                        'Requires a valid entity alias mapping to be set to generate searches when filtering on ' \
                        'entities in {}.'.format(object_type)
                    )

                if kpi.get('is_entity_breakdown', False):
                    entity_breakdown_id_fields = kpi.get('entity_breakdown_id_fields', None)
                    if entity_breakdown_id_fields is not None and len(entity_breakdown_id_fields) > 0 \
                            and not utils.is_valid_str(entity_breakdown_id_fields):
                        self.raise_error_bad_validation(
                            logger,
                            'Requires a valid entity breakdown id field in order to split KPI by entities.'
                        )

                # Validate anomaly detection settings
                def validate_ad_settings(madAlgorithmType):
                    enable_attribute = 'anomaly_detection_is_enabled' if madAlgorithmType == 'trending'\
                        else 'cohesive_anomaly_detection_is_enabled'
                    settings_attribute = 'trending_ad' if madAlgorithmType == 'trending' else 'cohesive_ad'

                    if kpi.get(enable_attribute) == True:
                        ad_settings = kpi.get(settings_attribute, {})
                        if not isinstance(ad_settings, dict):
                            self.raise_error_bad_validation(
                                logger,
                                'Invalid %s anomaly detection settings specified.' % madAlgorithmType
                            )
                        kpi[settings_attribute] = ad_settings

                        sensitivity = ad_settings.get('sensitivity')
                        if sensitivity is None:
                            # Set default if not set
                            sensitivity = 8 # default in MAD for unspecified sensitivity
                            kpi[settings_attribute] = {'sensitivity': sensitivity}
                        elif not isinstance(sensitivity, int):
                            self.raise_error_bad_validation(
                                logger,
                                'Invalid %s anomaly detection sensitivity specified, MUST be integer.' % madAlgorithmType
                            )

                validate_ad_settings('trending')
                validate_ad_settings('cohesive')

            kpi_title_list[:] = []

            # Validate that there is only one service health KPI
            if count_shkpi > 1:
                self.raise_error_bad_validation(
                    logger, 'Invalid Service Health KPI count. Expecting 1. Found {0}.'.format(count_shkpi))

        # validation in below section is not needed for base service templates, since service templates don't have
        # health KPIs associated with them.
        if not for_base_service_template:
            # Validate if kpi keys are unique across services.
            # This check is expensive but this check is important when introducing new KPIs
            # into the system. Without a guarantee for KPI key uniqueness, health calculations in the
            # ITSI KPI searches would be incorrect.
            # Batching check for all KPIs for optimization
            # Note that duplication in KPI keys within passed in services is already done above

            # KV store does not support lookup on fields starting with _ in a reliable way in nested objects
            # Owing to this, we will load all KPI ids and do a manual compare here
            # Query existing services for duplication of KPI keys

            # Also if in create only mode make sure KPI key being created
            # does not already exist

            for service_key in kpi_keys_map:
                for kpi_key in kpi_keys_map[service_key]:
                    kpi_found = False
                    for persisted_service in persisted_services:
                        for persisted_kpi in persisted_service.get('kpis', []):
                            if persisted_kpi['_key'] == kpi_key:
                                # On create, any existing KPI with same key is a duplicate
                                duplicate_found = kpi_keys_dict[kpi_key] == CRUDMethodTypes.METHOD_CREATE

                                # On update/upsert, KPIs with same key in other services are duplicates
                                if kpi_keys_dict[kpi_key] != CRUDMethodTypes.METHOD_CREATE:
                                    if persisted_service['_key'] == service_key:
                                        kpi_found = True
                                    else:
                                        duplicate_found = True

                                if duplicate_found:
                                    self.raise_error_bad_validation(logger,
                                        'KPI keys are not unique. KPIs must have unique keys. ' \
                                            'Eg: existing service duplicating key for KPIs ' \
                                            'that you are trying to save are: ' + persisted_service.get('_key', '')
                                    )
                    # On update, if specified KPI does not exist in current service,
                    # that is also an error condition
                    if (kpi_keys_dict[kpi_key] == CRUDMethodTypes.METHOD_UPDATE) and (not kpi_found):
                        self.raise_error(logger, 'KPI keys specified for update do not exist. Example: ' + kpi_key, 404)

            # Remove the book keeping fields added to KPIs. List of such keys:
            #   _kpi_method
            for service in services:
                for kpi in service.get('kpis', []):
                    if '_kpi_method' in kpi:
                        del kpi['_kpi_method']

    def _validate_service_dependencies(self, services, method):
        """
        Method to validate service dependencies for a bunch of services
        1. They must exist.
        2. a) They must exist in the same security group of the service, or
           b) They must belong to a security group thats a parent of the security group of the service if this service
                depends on the other

        @type services: JSON list of dict
        @param services: the service objects for which dependency config is being checked
        
        @type method: basestring
        @param method: operation type
        
        @rtype: list of dicts
        @return: list of service objects
        """
        def _extract_service_ids(dependency_list):
            if not isinstance(dependency_list, list):
                return []

            dependency_service_ids = []
            for service_dependency in dependency_list:
                if not isinstance(service_dependency, dict):
                    continue

                dependency_service_id = service_dependency.get('serviceid')
                if dependency_service_id is None:
                    # Ignore
                    continue
                dependency_service_ids.append(dependency_service_id)

            return dependency_service_ids

        all_service_ids = []
        all_sec_grp_ids = []
        service_dependencies_map = {}
        remove_depending_on_me = {}

        # Assume services json is valid
        # First collect all service and security groups info needed across all input services
        # to prevent multiple kv store lookups
        for i, service in enumerate(services):
            services_depending_on_ids = _extract_service_ids(service.get('services_depends_on'))
            services_depending_on_me_ids = _extract_service_ids(service.get('services_depending_on_me'))

            all_service_ids.extend(services_depending_on_ids + services_depending_on_me_ids)
            all_sec_grp_ids.append(service.get('sec_grp'))

            service_dependencies_map[service.get('_key')] = {
                'services_depending_on_ids': services_depending_on_ids,
                'services_depending_on_me_ids': services_depending_on_me_ids
            }

        if len(all_service_ids) < 1:
            # No dependencies, done here!
            return services, {}

        # Lookup all services once across the list of services for dependent service info
        # Does not support defining dependencies within active set to prevent potential complex issues from misconfiguration
        service_ids_filter = self.get_filter_data_for_keys(object_ids=all_service_ids)
        dependency_services = self.storage_interface.get_all(self.session_key, 'nobody', self.object_type,
                                                        filter_data=service_ids_filter, fields=['_key', 'sec_grp', 'title'])

        if not isinstance(dependency_services, list):
            if isinstance(dependency_services, dict):
                dependency_services = [dependency_services]
            else:
                # Cant fail here since stale info is ok in services_depending_on_me
                # Vaidate this below
                dependency_services = []

        # Lookup all security groups across list of services for sec grp info
        sec_grp_instance = ItsiSecGrp(self.session_key, self.current_user_name)
        service_sec_grps_map = sec_grp_instance.get_inheritance_info(all_sec_grp_ids)
        if not (isinstance(service_sec_grps_map, dict) and len(service_sec_grps_map) > 0):
                self.raise_error(logger, 'Some or all services are being configured with invalid teams.')

        # create a map for updated services
        all_updated_services = {}
        for service in services:
            all_updated_services[service.get('_key')] = service

        for i, service in enumerate(services):
            # Go through the list of updated services and check if dependency violates security group membership rules
            # Note: If the dependency service itself is in the update list, the new sec_grp field is used
            # instead of the original one in kvstore
            services_depending_on_map = {}
            services_depending_on_me_map = {}

            services_depending_on_ids = service_dependencies_map[service.get('_key')]['services_depending_on_ids']
            services_depending_on_me_ids = service_dependencies_map[service.get('_key')]['services_depending_on_me_ids']

            original_service = self.storage_interface.get(self.session_key,
                                                          'nobody',
                                                          self.object_type,
                                                          service.get('_key'))

            for dependency_service in dependency_services:
                if dependency_service.get('_key') in services_depending_on_ids:
                    services_depending_on_map[dependency_service['_key']] = dependency_service
                    # replace the security group from kvstore with security group from update
                    if dependency_service.get('_key') in all_updated_services:
                        if 'sec_grp' in all_updated_services[dependency_service['_key']] :
                            services_depending_on_map[dependency_service['_key']]['sec_grp'] = \
                                all_updated_services[dependency_service['_key']]['sec_grp']

                if dependency_service.get('_key') in services_depending_on_me_ids:
                    services_depending_on_me_map[dependency_service['_key']] = dependency_service
                    # replace the security group from kvstore with security group from update
                    if dependency_service.get('_key') in all_updated_services:
                        if 'sec_grp' in all_updated_services[dependency_service['_key']]:
                            services_depending_on_me_map[dependency_service['_key']]['sec_grp'] = \
                                all_updated_services[dependency_service['_key']]['sec_grp']

            # All needed info is collected at this point, start validations

            if len(services_depending_on_map) != len(services_depending_on_ids):
                #self.raise_error(logger, 'Some or all dependencies being configured could not be found.')
                logger.warning('Some or all dependencies being configured could not be found.')

            service_sec_grp = service_sec_grps_map.get(service.get('sec_grp'))
            if not isinstance(service_sec_grp, dict):
                self.raise_error(
                    logger,
                    'Team is incorrectly configured for the service.')

            # First process services that this service depends on
            for dependency_service_id, dependency_service in services_depending_on_map.iteritems():
                if service.get('sec_grp') == dependency_service.get('sec_grp', GLOBAL_SECURITY_GROUP_CONFIG.get('key')):
                    continue

                sec_grp_violation_error_msg = _('Dependency being configured violates team membership rules. '\
                    'Services could only depend on services from other teams if '\
                    'the depending service is in the parent hierarchy of the service\'s team. Violating '\
                    'dependent service is %s, for the service %s.') % (
                        dependency_service.get('title', dependency_service_id), service.get('title'))

                break_dependency_msg = _('Service dependency was broken by this action. Service %s ' \
                                       'no longer depends on service %s') % (
                                            service.get('title'), dependency_service.get('title', dependency_service_id))

                if not service_sec_grp['has_parents'] or \
                        not any(str(parent['_key']) == str(dependency_service.get('sec_grp'))
                           for parent in service_sec_grp['parents']):

                    # handle the case that sec_grp gets updated
                    if method == CRUDMethodTypes.METHOD_UPDATE and service.get('sec_grp') != original_service.get('sec_grp'):

                            logger.warning(break_dependency_msg)

                            temp_service_depends_on = []
                            for service_dependency in service['services_depends_on']:
                                if not isinstance(service_dependency, dict) or \
                                        service_dependency.get('serviceid') != dependency_service_id:
                                    temp_service_depends_on.append(service_dependency)

                            services[i]['services_depends_on']  = temp_service_depends_on

                    else:
                        self.raise_error(logger, sec_grp_violation_error_msg)

            # Now process services that depend on this service, for the sake of REST API
            for dependency_service_id, dependency_service in services_depending_on_me_map.iteritems():
                if service.get('sec_grp') == dependency_service.get('sec_grp', GLOBAL_SECURITY_GROUP_CONFIG.get('key')):
                    continue

                sec_grp_violation_error_msg = _('Dependency being configured violates team membership rules. '\
                    'Services could only depend on services from other teams if '\
                    'the depending service is in the parent hierarchy of the service\'s team. Violating '\
                    'dependent service is %s, for the service %s.') % (
                        service.get('title'), dependency_service.get('title', dependency_service_id))

                break_dependency_msg = _('Service dependency was broken by this action. Service %s ' \
                                       'no longer depends on service %s') % (
                                            dependency_service.get('title', dependency_service_id), service.get('title'))

                if not service_sec_grp['has_children'] \
                        or not any(str(child['_key']) == str(dependency_service.get('sec_grp'))
                           for child in service_sec_grp['children']):

                    # handle the case that sec_grp gets updated
                    if method == CRUDMethodTypes.METHOD_UPDATE and service.get('sec_grp') != original_service.get('sec_grp'):

                        logger.warning(break_dependency_msg)

                        temp_service_depending_on_me = []
                        for service_dependency in service['services_depending_on_me']:
                            if not isinstance(service_dependency, dict) or \
                                    service_dependency.get('serviceid') != dependency_service_id:
                                temp_service_depending_on_me.append(service_dependency)

                        services[i]['services_depending_on_me']  = temp_service_depending_on_me

                        if service.get('_key') not in remove_depending_on_me:
                            remove_depending_on_me[service.get('_key')] = [dependency_service_id]
                        else:
                            remove_depending_on_me[service.get('_key')].append(dependency_service_id)

                    else:
                        self.raise_error(logger, sec_grp_violation_error_msg)

        return services, remove_depending_on_me

    def bulk_get_kpis(self, owner, service_kpis_raw, transaction_id=None):
        """
        Used by KPI CRUD APIs to get KPIs from existing services

        @type owner: string
        @param owner: owner context for KV store collection

        @type service_kpis_raw: list of dicts
        @param service_kpis_raw: list of dictionary specifying which KPIs to get from which services
            Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]

        @rtype: list of dictionaries
        @return: list of dictionary items with service key and KPIs requested for that service
        """
        service_kpis = self.extract_json_data(service_kpis_raw)

        if (service_kpis is not None) and (not utils.is_valid_list(service_kpis)):
            self.raise_error_bad_validation(
                logger,
                'To get KPIs, pass in a list of service keys with their KPI keys. ' \
                    'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                    'Invalid input received.'
            )

        services_filter = {} # By default get all services and their KPIs
        service_kpis_map = {}
        if len(service_kpis) > 0:
            services_filter = {'$or': []}
            for service in service_kpis:
                service_key = service.get('_key')
                kpi_keys = [
                    kpi['_key'] for kpi in service.get('kpis',[]) if utils.is_valid_str(kpi.get('_key'))
                    ]
                if service_key in service_kpis_map:
                    self.raise_error_bad_validation(
                        logger,
                        'To get KPIs, pass in a list of service keys with their KPI keys. ' \
                            'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                            'Duplicate service key entries received.'
                    )
                service_kpis_map[service_key] = kpi_keys
                if not (utils.is_valid_str(service_key) and utils.is_valid_list(kpi_keys)):
                    self.raise_error_bad_validation(
                        logger,
                        'To get KPIs, pass in a list of service keys with their KPI keys. ' \
                            'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                            'Invalid input received.'
                    )

                service_filter = {'_key': service_key}
                if len(kpi_keys) > 0:
                    # Get the subset of KPIs requested
                    service_filter = {
                        '$and': [
                            service_filter,
                            {
                                "$or": [{"kpis._key": kpi_key} for kpi_key in kpi_keys]
                            }
                        ]
                    }
                # else get all KPIs for the service
                services_filter['$or'].append(service_filter)

        services = self.get_bulk(owner, filter_data=services_filter, fields=['_key', 'title', 'kpis'], transaction_id=transaction_id)
        for service in services:
            # As a guard if KV store returned the KPIs not requested owing to _key being an internal field,
            # remove them here
            # Also remove service health KPI since this API is meant for CRUD on KPIs directly and
            # we should not allow users to modify service health KPI
            requested_kpis = service_kpis_map.get(service['_key'], [])
            service['kpis'] = [
                kpi for kpi in service.get('kpis', [])
                if (not kpi['_key'].startswith(self.shkpi_starts_with)) and
                    ((len(requested_kpis) < 1) or (kpi['_key'] in requested_kpis))
            ]

        return services

    def bulk_change_kpis(self, owner, service_kpis_raw, is_create = False, transaction_id=None):
        """
        Used by KPI CRUD APIs to directly create new/update existing KPIs on services

        @type owner: string
        @param owner: owner context for KV store collection

        @type service_kpis_raw: list of dicts
        @param service_kpis_raw: list of dictionary specifying which KPIs to update for what services
            Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]

        @type is_create: bool
        @param is_create: indicate if KPIs are being created or updated

        @rtype: list of strings
        @return: list of service keys for services that got updated
        """
        service_kpis = self.extract_json_data(service_kpis_raw)

        if (not utils.is_valid_list(service_kpis)) or (len(service_kpis) < 1):
            self.raise_error_bad_validation(
                logger,
                'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                    'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                    'Invalid input received.' + str(service_kpis)
            )

        # First get the existing service configuration
        service_keys = []
        service_kpis_map = {}
        services_filter = {'$or': []}
        for service in service_kpis:
            service_key = service.get('_key')
            if not utils.is_valid_str(service_key):
                self.raise_error_bad_validation(
                    logger,
                    'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                        'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                        'Invalid service keys received.'
                )
            service_keys.append(service_key)
            services_filter['$or'].append({'_key': service_key})
            if service_key in service_kpis_map:
                self.raise_error_bad_validation(
                    logger,
                    'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                        'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                        'Duplicate service entries (keys) received. Check services specified.'
                )
            service_kpis_map[service_key] = service.get('kpis', [])
            for kpi in service_kpis_map[service_key]:
                # Add a temporary key in each KPI to track if KPI is being created new.
                # Helps perform validations that need to differentiate the newly configured KPIs
                # from the existing KPIs in existing services
                # This key will be cleared before saving the service in
                # validate_kpis
                kpi['_kpi_method'] = CRUDMethodTypes.METHOD_CREATE if is_create else CRUDMethodTypes.METHOD_UPDATE

        if len(service_keys) < 1:
            self.raise_error_bad_validation(
                logger,
                'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                    'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                    'No service keys received.'
            )

        services = self.get_bulk(owner, filter_data=services_filter, transaction_id=transaction_id)
        if not (utils.is_valid_list(services) and (len(services) == len(service_keys))):
            self.raise_error(
                logger,
                'A service key specified does not exist. Cannot change KPIs for non-existing services.',
                404
            )

        # Merge the KPIs to update with the existing KPIs in the services
        # Add as new if not found
        for service in services:
            kpis_to_update = service_kpis_map[service['_key']]
            if not (utils.is_valid_list(kpis_to_update) and (len(kpis_to_update) > 0)):
                self.raise_error_bad_validation(
                    logger,
                    'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                        'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                        'No KPIs received for some services. Check the KPIs.'
                )

            merged_kpis = []

            # First add all KPIs passed in for this service
            # New ones and updated ones
            for kpi_to_update in kpis_to_update:
                kpi_key = kpi_to_update.get('_key')

                if is_create and (not utils.is_valid_str(kpi_key)):
                    kpi_to_update['_key'] = ITOAInterfaceUtils.generate_backend_key()
                    kpi_key = kpi_to_update['_key']

                if not utils.is_valid_str(kpi_key):
                    self.raise_error_bad_validation(
                        logger,
                        'To change KPIs, pass in a non-empty list of service keys with their KPIs list. ' \
                            'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>, <rest of KPI structure>}]]. ' \
                            'Some KPIs are specified with invalid key.'
                    )

                if kpi_key.startswith(self.shkpi_starts_with):
                    self.raise_error_bad_validation(
                        logger,
                        'Cannot change service health type KPIs. Please remove service health KPIs and retry.'
                    )

                merged_kpis.append(kpi_to_update)

            # Now go over all existing KPIs in the service that have not been merged and add them
            for existing_kpi in service.get('kpis', []):
                existing_kpi_already_updated = False
                for kpi_to_update in kpis_to_update:
                    if existing_kpi['_key'] == kpi_to_update['_key']:
                        existing_kpi_already_updated = True
                        break
                if not existing_kpi_already_updated:
                    merged_kpis.append(existing_kpi)

            service['kpis'] = merged_kpis

        # Now save the updated services
        # Note that the KPIs get validated in save_batch, so skip validations here
        return self.save_batch(
            owner,
            services,
            method=CRUDMethodTypes.METHOD_UPDATE, # Services are always updated for KPI changes
            validate_names=False, # Skip validating service titles here,
            transaction_id=transaction_id
        )

    def bulk_delete_kpis(self, owner, service_kpis_raw, transaction_id=None):
        """
        Used by KPI CRUD APIs to delete KPIs from existing services

        @type owner: string
        @param owner: owner context for KV store collection

        @type service_kpis_raw: list of dicts
        @param service_kpis_raw: list of dictionary specifying which KPIs to get from which services
            Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]

        @rtype: list of strings
        @return: list of services from which KPIs were deleted
        """
        service_kpis = self.extract_json_data(service_kpis_raw)

        if not (utils.is_valid_list(service_kpis) and (len(service_kpis) > 0)):
            self.raise_error_bad_validation(
                logger,
                'To delete KPIs, pass in a list of service keys with the keys for the KPIs to delete. ' \
                    'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                    'Invalid input received.'
            )

        services_filter = {'$or': []}
        service_delete_kpis_map = {}
        for service in service_kpis:
            service_key = service.get('_key')
            kpi_keys = [kpi['_key'] for kpi in service.get('kpis',[])]

            # We dont want users to accidentally delete all KPIs from a service
            # Hence limit deletes to only specified KPI keys
            if not (utils.is_valid_str(service_key) and utils.is_valid_list(kpi_keys) and (len(kpi_keys) > 0)):
                self.raise_error_bad_validation(
                    logger,
                    'To delete KPIs, pass in a list of service keys with the keys for the KPIs to delete. ' \
                        'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                        'Specify atleast one KPI per service.'
                )

            if service_key in service_delete_kpis_map:
                self.raise_error_bad_validation(
                    logger,
                    'To delete KPIs, pass in a list of service keys with the keys for the KPIs to delete. ' \
                        'Expected format: [{_key: <service key>, kpis: [{_key: <KPI key>}]]. ' \
                        'Duplicate service key received. Please specify all KPIs for a service in one entry.'
                )

            service_delete_kpis_map[service_key] = kpi_keys
            service_filter = {'_key': service_key}
            services_filter['$or'].append(service_filter)

        services = self.get_bulk(owner, filter_data=services_filter, transaction_id=transaction_id)
        for service in services:
            # Remove any KPIs requested to be deleted from the service if found
            # Always retain service health KPIs
            service['kpis'] = [
                kpi for kpi in service.get('kpis', [])
                if ((kpi['_key'] not in service_delete_kpis_map[service['_key']]) or
                    (kpi['_key'].startswith(self.shkpi_starts_with)))
            ]

        return self.save_batch(owner, services, validate_names=False, transaction_id=transaction_id) # Skip validating service titles here

    def update(self, owner, service_id, data, is_partial_data=False, dupname_tag=None, transaction_id=None):
        """
        Wrapper to itoa_object interface's update method, to set class variable to skip service template
        update or not, then call itoa_object interface's update method and then unset the variable.
        @type owner: string
        @param owner: user who is performing this operation
        @type service_id: string
        @param service_id: id of object to update
        @type data: string
        @param data: object to update
        @type is_partial_data: bool
        @param is_partial_data: indicates if payload passed into data is a subset of object structure
            when True, payload passed into data is a subset of object structure
            when False, payload passed into data is the entire object structure
            Note that KV store API does not support partial updates
        @rtype: string
        @return: id of object updated on success, throws exceptions on errors
        """
        results = super(ItsiService, self).update(owner, service_id, data, is_partial_data=is_partial_data,
                                                  dupname_tag=dupname_tag, transaction_id=transaction_id)
        self.skip_service_template_update = False

        return results

    def save_batch(self, owner, data_list, validate_names, dupname_tag=None, req_source='unknown',
                   ignore_refresh_impacted_objects=False, method=CRUDMethodTypes.METHOD_UPSERT,
                   is_partial_data=False, transaction_id=None):
        """
        Wrapper to itoa_object interface's save_batch method, to set class variable to skip service template
        update or not, then call itoa_object interface's save_batch method and then unset the variable.
        @type owner: string
        @param owner: user who is performing this operation
        @type data_list: list
        @param data_list: list of objects to upsert
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
        result_ids = super(ItsiService, self).save_batch(owner, data_list, validate_names, dupname_tag=dupname_tag,
                                                         req_source=req_source,
                                                         ignore_refresh_impacted_objects=ignore_refresh_impacted_objects,
                                                         method=method,
                                                         is_partial_data=is_partial_data, transaction_id=transaction_id)
        self.skip_service_template_update = False

        return result_ids
