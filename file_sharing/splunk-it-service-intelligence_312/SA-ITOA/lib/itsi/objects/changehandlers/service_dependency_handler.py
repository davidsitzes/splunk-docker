# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from . import itoa_change_handler
from itsi.objects.itsi_service import ItsiService


class ServiceDependencyHandler(itoa_change_handler.ItoaChangeHandler):
    """
    Change handler that will update dependent services information with services_depends_on_me field
    """

    def deferred(self, change, transaction_id=None):
        """
        @param change: Must have changed_object_type == service and change_type == 'service_dependency_changed'
        @return: Boolean as to whether or not the operation was successful or unsuccessful
        """

        if change.get('changed_object_type') != 'service':
            raise Exception(_('Expected changed_object_type to be "service"'))

        if change.get('change_type') != 'service_dependency_changed':
            raise Exception(_('Expected change_type to be "service_dependency_changed"'))

        service_interface = ItsiService(self.session_key, 'nobody')

        updated_services = {}

        change_detail = change.get("change_detail", {})
        owner = 'nobody'

        services_depends_on_update = change_detail.get('services_depends_on', {})
        services_depending_on_me_update = change_detail.get('services_depending_on_me', {})

        if len(services_depends_on_update) != 0:

            #Bulk request all of the services
            service_keys = []
            for cd in services_depends_on_update.itervalues():
                for ad in cd['added_dependencies']:
                    service_keys.append(ad['target_service'])
                for rd in cd['removed_dependencies']:
                    service_keys.append(rd['target_service'])

            if not service_keys:
                return True

            filter_data = {
                '$or': [{'_key': service_key} for service_key in service_keys]
                }
            services = service_interface.get_bulk(owner,
                                                  filter_data=filter_data,
                                                  req_source="ServiceDependencyHandler",
                                                  transaction_id=transaction_id)

            # Translate to dict at first
            target_services = {s["_key"]:s for s in services}
            for service_key, detail in services_depends_on_update.iteritems():
                added_dependencies = detail['added_dependencies']
                removed_dependencies = detail['removed_dependencies']

                for added_dependency in added_dependencies:
                    target_service_key = added_dependency['target_service']
                    # service could have been updated previously, fetch it from updated_services if available
                    if target_service_key in updated_services:
                        target_service = updated_services.get(target_service_key)
                    # otherwise fetch from kvstore
                    else:
                        target_service = target_services.get(target_service_key)
                        if target_service is None:
                            self.logger.warning("Attempted to update missing service=%s", target_service_key)
                            continue
                    new_depending_kpis = added_dependency['depending_kpis']
                    existing_dependencies =\
                        target_service.get('services_depending_on_me') if target_service is not None else None

                    matched_dependencies = []
                    if existing_dependencies is not None:
                        matched_dependencies = [d for d in existing_dependencies if d.get('serviceid') == service_key]
                    if len(matched_dependencies) > 0:
                        # should only be 1
                        if len(matched_dependencies) > 1:
                            self.logger('Service "' + service_key + '" is referenced twice, should never happen')
                        matched_dependencies[0].get('kpis_depending_on', []).extend(new_depending_kpis)
                        matched_dependencies[0]['kpis_depending_on'] = list(set(
                            matched_dependencies[0]['kpis_depending_on']
                        ))
                    else:
                        if existing_dependencies is None:
                            existing_dependencies = []
                        existing_dependencies.append({
                            'serviceid': service_key,
                            'kpis_depending_on': list(set(new_depending_kpis))
                        })
                        #Patching the call, kept on getting a crash in this part of the code
                        if target_service is not None:
                            target_service['services_depending_on_me'] = existing_dependencies
                    updated_services[target_service_key] = target_service

                self.logger.debug('removed dependencies: ' + str(removed_dependencies))
                for removed_dependency in removed_dependencies:
                    target_service_key = removed_dependency['target_service']
                    self.logger.debug('removed dependency key: ' + target_service_key)
                    if target_service_key in updated_services:
                        target_service = updated_services.get(target_service_key)
                    else:
                        target_service = target_services.get(target_service_key)
                    depending_kpis_to_remove = removed_dependency['depending_kpis']
                    existing_dependencies = target_service.get('services_depending_on_me') if target_service is not None else None

                    matched_dependencies = []
                    if existing_dependencies is not None:
                        matched_dependencies = [d for d in existing_dependencies if d.get('serviceid') == service_key]
                    if len(matched_dependencies) > 0:
                        existing_kpis = matched_dependencies[0].get('kpis_depending_on')
                        existing_kpis = [x for x in existing_kpis if x not in depending_kpis_to_remove]
                        # if no KPI dependencies remaining for this service, remove this service as a dependency
                        if len(existing_kpis) == 0:
                            existing_dependencies = [d for d in existing_dependencies if d.get('serviceid') != service_key]
                            target_service['services_depending_on_me'] = existing_dependencies
                        # otherwise just remove this KPI
                        else:
                            self.logger.debug('existing kpis: ' + str(existing_kpis))
                            matched_dependencies[0]['kpis_depending_on'] = existing_kpis
                        updated_services[target_service_key] = target_service
                    else:
                        self.logger.error('Could not find service "' + service_key + '" in target service dependency')


        # update services for the case of moving service between sec_groups and need to break
        # services_depends_on based on services_depending_on_me change
        if len(services_depending_on_me_update) != 0:

            #Bulk request all of the services
            service_keys = []
            for cd in services_depending_on_me_update.itervalues():
                service_keys.extend(cd)

            if not service_keys:
                return True

            filter_data = {
                '$or': [{'_key': service_key} for service_key in service_keys]
                }
            services = service_interface.get_bulk(owner,
                                                  filter_data=filter_data,
                                                  req_source="ServiceDependencyHandler",
                                                  transaction_id=transaction_id)

            # Translate to dict at first
            target_services = {s["_key"]:s for s in services}
            for service_key, removed_dependencies in services_depending_on_me_update.iteritems():

                self.logger.debug('removed dependencies: ' + str(removed_dependencies))
                for target_service_key in removed_dependencies:
                    self.logger.debug('removed dependency key: ' + target_service_key)
                    if target_service_key in updated_services:
                        target_service = updated_services.get(target_service_key)
                    else:
                        target_service = target_services.get(target_service_key)

                    existing_dependencies = target_service.get('services_depends_on') if target_service is not None else None

                    matched_dependencies = []
                    if existing_dependencies is not None:
                        matched_dependencies = [d for d in existing_dependencies if d.get('serviceid') == service_key]
                    if len(matched_dependencies) > 0:
                        existing_dependencies = [d for d in existing_dependencies if d.get('serviceid') != service_key]
                        target_service['services_depends_on'] = existing_dependencies
                        updated_services[target_service_key] = target_service
                    else:
                        self.logger.error('Could not find service "' + service_key + '" in target service dependency')


        if len(updated_services) == 0:
            return True  # Noop

        try:
            service_interface.batch_save_backend('nobody', updated_services.values(), transaction_id=transaction_id)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False
