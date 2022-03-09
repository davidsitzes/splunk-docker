# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
The itsi base search object (and association) definition.
Used in what may be called "kpi templates"
It allows the users to abstract base searches away and make kpi creation easier
See:
https://confluence.splunk.com/pages/viewpage.action?title=ITSI+KPI+Search+Performance+Enhancements&spaceKey=PROD
"""
from splunk.appserver.mrsparkle.lib import i18n
import ITOA.itoa_common as utils
from ITOA.itoa_object import ItoaObject, CRUDMethodTypes
from .itsi_service import ItsiService
from ITOA.itoa_factory import instantiate_object
from .itsi_kpi import BASE_SEARCH_KPI_ATTRIBUTES, BASE_SEARCH_METRIC_KPI_ATTRIBUTES, DEFAULT_VALUE_KPI_ATTRIBUTES_DICT
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch
from itsi.service_template.service_template_utils import ServiceTemplateUtils

from ITOA.setup_logging import setup_logging
logger = setup_logging('itsi.log', 'itsi.object.kpi_base_search')


class ItsiKPIBaseSearch(ItoaObject):
    """
    Implements ITSI base search ItoaObject methods
    Updates on the base search
    - If base search and other fields have been modified, then update the associated services
    - If the base search title has been modified, then update the base search association table
    - If the base search has been deleted, then delete the entries in the base search association table and
      update the associated services from "shared_base_search" to "adhoc"
    """

    log_prefix = '[ITSI Base Search] '

    def __init__(self, session_key, current_user_name):
        """
        @param session_key:  The active splunkd session key
        @param current_user_name: The user initializing the objects
        """
        super(ItsiKPIBaseSearch, self).__init__(session_key,
                                                current_user_name,
                                                'kpi_base_search',
                                                collection_name='itsi_services',
                                                is_securable_object=True)

    def templatize(self, owner, object_id, req_source='unknown'):
        """
        Templatize given object id
        @type owner: basestring
        @param owner: context of the request `nobody` vs an actual user
        @type object_id: basestring
        @param object_id: unique identifier of an object to templatize
        @type req_source: basestring
        @param req_source: indentified source initiating the operation.
        """
        logger.debug('Templatize request received for `%s`', object_id)

        kpi_template = super(ItsiKPIBaseSearch, self).templatize(owner, object_id, req_source)
        logger.debug('Base class templatize returned=`%s`.', kpi_template)

        logger.debug('Templatizing metrics for `%s`', object_id)
        metrics = kpi_template.get('metrics', [])
        for metric in metrics:
            metric.pop('_key', None)
        kpi_template['metrics'] = metrics

        return kpi_template

    @staticmethod
    def kpi_attributes_compare(old_kpi, new_kbs):
        """
        Determine if the base search attributes are identical to KPIs
        If they are - return true, else return false
        @param: old_kpi - The old kpi base search referencing KPI from a service
        @param: new_kbs - The new kpi base search
        """
        # NOTE: Is it worth it to do this checking?  Should I compress and loop through this part
        for attribute in BASE_SEARCH_KPI_ATTRIBUTES:
            if new_kbs.get(attribute) != old_kpi.get(attribute):
                return False
        return True

    @staticmethod
    def metric_attribute_compare(new_metric, old_metric):
        """
        Determine if two metrics are identical to KPIs
        If they are - return true, else return False
        """
        for attribute in BASE_SEARCH_METRIC_KPI_ATTRIBUTES:
            if new_metric.get(attribute) != old_metric.get(attribute):
                return False
        return True

    def _get_impacted_objects(self, owner, fetch_filter, impacted_object_type):
        """
        Impacted objects (Services or Base Service Templates) with kpi entries that contain the
        base search ids associated with the objects that are being passed in.

        NOTE: Users of this method should keep in mind that the whole service and service template
        will be passed in. So one or more KPIS may match and the consumer has the responsibility
        of figuring out which one is which

        @type owner: basestring
        @param owner: The owner of the objects (typically 'nobody')
        @type fetch_filter: list of dict
        @param fetch_filter: list of base search id maps that will be used as a filter to fetch impacted objects
            from kvstore. example: [{'kpis.base_search_id': <id1>}, {'kpis.base_search_id': <id2>}]
        @type impacted_object_type: basestring
        @param impacted_object_type: impact object type as defined in objects manifest
        @rtype: list of dict
        @return: list of impacted objects (services or service templates)
        """
        # All the items here are fresh - keyless.  No matching services possible
        if len(fetch_filter) == 0:
            return []

        object_interface = instantiate_object(
            self.session_key, self.current_user_name, impacted_object_type, logger=logger
        )
        # get services containing KPIs of type shared_base & who have base
        # search ids that match us
        existing_objects = object_interface.get_bulk(
            owner,
            filter_data={
                "$and": [
                    {'kpis.search_type': 'shared_base'},
                    {'$or': fetch_filter}
                ]
            }
        )
        return existing_objects

    def _update_impacted_objects(self, updated_base_search, affected_objects, affected_object_dict):
        """
        Update impacted objects with kpi base search updates.
        Impacted objects could be KPIs in services and service templates,
        using base search.

        @type updated_base_search: dict
        @param updated_base_search: updated kpi base search object
        @type affected_objects: list of dict
        @param affected_objects: list of impacted services / service template objects
        @type affected_object_dict: dict
        @param affected_object_dict: map of impacted object id to object
        @rtype: list of dict
        @return: list of updated impacted objects
        """
        if affected_objects is None:
            return []
        new_metrics = updated_base_search.get('metrics', [])
        updated_objects = []
        updated_objects_ids = []
        for object_id, affected_kpis in affected_objects.iteritems():
            updated = False
            object = affected_object_dict[object_id]

            # used for logging purposes
            object_type_log_string = 'Service'
            if object.get('object_type') == 'base_service_template':
                object_type_log_string = 'Base Service Tempalte'

            kpis = object.get('kpis')
            for kpi in kpis:
                if kpi.get('_key') not in affected_kpis:
                    continue
                base_search_id = kpi.get('base_search_id')
                if base_search_id is None:
                    continue #Dafuq
                if kpi.get('search_type') != 'shared_base':
                    logger.warning('%s %s has kpi %s referencing a shared base search, but has the wrong search type' %
                                   (object_type_log_string, object_id, kpi.get('_key')))
                    continue

                # Apply the changes that dont have to do with base search metrics
                non_metric_changes = not self.kpi_attributes_compare(kpi, updated_base_search)
                if non_metric_changes:
                    updated = True
                    for attribute in BASE_SEARCH_KPI_ATTRIBUTES:
                        # Some fields in old shared base search are missing, populate defaults
                        if attribute in updated_base_search:
                            kpi[attribute] = updated_base_search.get(attribute)
                        else:
                            kpi[attribute] = DEFAULT_VALUE_KPI_ATTRIBUTES_DICT.get(attribute)

                # Now update metric fields
                metric_id = kpi.get("base_search_metric")
                if metric_id is None:
                    logger.error('%s %s has kpi %s has no base search metric - Aborting update' %
                                 (object_type_log_string, object_id, kpi.get('_key')))
                    continue

                metric_found = False
                for new_metric in new_metrics:
                    if new_metric['_key'].lower() != metric_id.lower():  # normalize metric key to lower case
                        continue
                    metric_found = True
                    if not self.metric_attribute_compare(new_metric, kpi):
                        updated = True
                        for metric_attribute in BASE_SEARCH_METRIC_KPI_ATTRIBUTES:
                            kpi[metric_attribute] = new_metric[metric_attribute]
                        break
                # we should not hit this scenario for a service template. If a service template KPI is using a base
                # search metric, then we should not allow deletion of that metric.
                if not metric_found and object.get('object_type') != 'base_service_template':
                    # Metric is deleted from shared base search, convert KPI to adhoc
                    updated = True
                    if kpi.get('search_type') == 'shared_base':
                        kpi['search_type'] = 'adhoc'
                        del kpi['base_search_id']
                        del kpi['base_search_metric']

            # No updates to the base search, everything that was changed here
            # can be passed directly to the statestore
            if updated and object_id not in updated_objects_ids:
                updated_objects_ids.append(object_id)
                updated_objects.append(object)
        return updated_objects

    @staticmethod
    def _get_base_search_to_impacted_objects_map(impacted_objects):
        """
        Generates a base search id to impacted object id to kpis list map.
        @type impacted_objects: list of dict
        @param impacted_objects: list of impacted services or service templates
        @rtype: tuple
        @return: tuple of base search id to impacted object id to kpis list map and
        impacted object id to object map
        """
        # A dictionary of base search ids to to a dict of kpi id lists, see sample
        # {'bsid1':{'svc1':['kpi1','kpi2']}}
        bs_to_object_kpi_dict = {}
        object_dict = {}
        # I tried to do this all in one line, but it was a wee bit unreadable
        for obj in impacted_objects:
            object_dict[obj.get('_key')] = obj
            kpis = obj.get('kpis')
            for kpi in kpis:
                base_search = kpi.get('base_search_id')
                if base_search is not None:
                    # Add to the dict
                    if base_search not in bs_to_object_kpi_dict:
                        bs_to_object_kpi_dict[base_search] = {obj.get('_key'): [kpi.get("_key")]}
                    else:
                        object_map = bs_to_object_kpi_dict[base_search]
                        if obj.get('_key') not in object_map:
                            bs_to_object_kpi_dict[base_search][obj.get("_key")] = [kpi.get("_key")]
                        else:
                            bs_to_object_kpi_dict[base_search][obj.get("_key")].append(kpi.get("_key"))

        return bs_to_object_kpi_dict, object_dict

    def update_kpi_base_search(self, owner, objects, transaction_id=None):
        """
        The base searches have been updated; upsert OR update
        Perform the appropriate action within this context
        @type owner: basestring
        @param owner: A string representing the user making the change
        @type objects: list of dict
        @param objects: The base searches that we're changing
        @type transaction_id: basestring
        @param transaction_id: for transaction tracing
        """
        # Unfortunately, we need to determine the nature of the change for the objects
        id_array = []
        impacted_objects_fetch_filter = []
        base_searches = {}
        for obj in objects:
            if '_key' in obj:
                id_array.append({'_key': obj.get('_key')})
                impacted_objects_fetch_filter.append({'kpis.base_search_id': obj.get('_key')})
                base_searches[obj.get('_key')] = obj

        if len(id_array) == 0:
            return  # No existing associations, its all new stuff

        services = self._get_impacted_objects(owner, impacted_objects_fetch_filter, 'service')
        service_templates = self._get_impacted_objects(owner, impacted_objects_fetch_filter, 'base_service_template')
        if len(services) == 0 and len(service_templates) == 0:
            return  # No services / service templates / kpis are affected

        bs_to_service_kpi_dict, service_dict = self._get_base_search_to_impacted_objects_map(services)
        bs_to_service_template_kpi_dict, service_templates_dict = self._get_base_search_to_impacted_objects_map(
            service_templates
        )

        updated_services = []
        updated_service_templates = []
        # The meat of the method
        for nbs_key, nbs in base_searches.iteritems():
            affected_services = bs_to_service_kpi_dict.get(nbs['_key'], {})
            affected_service_templates = bs_to_service_template_kpi_dict.get(nbs['_key'], {})

            updated_services.extend(self._update_impacted_objects(nbs, affected_services, service_dict))
            updated_service_templates.extend(
                self._update_impacted_objects(nbs, affected_service_templates, service_templates_dict)
            )

        if updated_services:
            # OKAY!  After all of that if we have a non-empty list of the services
            # That we need to update
            # These service updates need to go through the official channels, so that all the necessary
            # Cruft gets applied
            service_object = ItsiService(self.session_key, self.current_user_name)
            service_object.skip_service_template_update = True
            service_object.save_batch(owner, updated_services, False)

        if updated_service_templates:
            service_template_interface = instantiate_object(
                self.session_key, self.current_user_name, 'base_service_template', logger=logger
            )
            # we do not really need to perform any dependencies update for service templates.
            # therefore, directly call backend batch save to update service templates
            service_template_interface.batch_save_backend(
                owner, updated_service_templates, transaction_id=transaction_id
            )

    def delete_kpi_base_search(self, owner, objects, req_source='unknown'):
        """
        The base searches listed have been deleted.
        Remove any service associations and save
        @param owner: The service/kpi owner
        @param objects: The base search objects that we'll be matching on
        """
        # For convenience, store the ids of the array
        id_array = []
        fetch_filter = []
        for obj in objects:
            if '_key' in obj:
                id_array.append(obj.get('_key'))
                fetch_filter.append({'kpis.base_search_id': obj.get('_key')})

        services = self._get_impacted_objects(owner, fetch_filter, 'service')

        if len(services) == 0:
            logger.debug('Zero services affected from deletion of base searches "%s".', objects)
            return

        for svc in services:
            for kpi in svc.get('kpis', []):
                if kpi.get('search_type') == 'shared_base' and kpi.get('base_search_id') in id_array:
                    # We have a match for the kpi that we need to edit.  Change the method to adhoc
                    # And remove the base search id reference
                    kpi['search_type'] = 'adhoc'
                    del kpi['base_search_id']
                    del kpi['base_search_metric']

        # Update affected services & KPIs. They will need savedsearch entries
        # and such. Plus we should not have any need for title validations or
        # creating refresh jobs for these services.
        op = ItsiService(self.session_key, self.current_user_name)
        op.skip_service_template_update = True
        results = op.save_batch(owner, services, False, req_source=req_source,ignore_refresh_impacted_objects=True)

        if len(results) != len(services):
            service_ids = [s['_key'] for s in services]
            logger.error('There was an error saving the services to the backend. Length of results=%s. Length of services=%s',
                len(results), len(services))
            logger.debug('Incomplete Results=%s', results)
            logger.debug('Service_IDs=%s', service_ids)
            # Probably better here to keep the shared searches rather than delete them
            return
        
        for bs_id in id_array:
            # Kind of a hack here, but I dont need or want to get the services or base search
            # So should delete_splunk_search should work it out
            ItsiSharedAdhocSearch(self.session_key, bs_id, base_search={}, services=[]).delete_splunk_search()
        return

##################################################################
# ItoaObject specific methods
#################################################################
    def identify_dependencies(self, owner, objects, method=CRUDMethodTypes.METHOD_UPSERT, req_source='unknown', transaction_id=None):
        """
        Extended as a part of the contract for ItoaObject subclasses, this one makes sure that services depending
        on the KPIBaseSearch have updates issued for them

        See the ERD for information on what needs to be done here
        https://confluence.splunk.com/pages/viewpage.action?title=ITSI+KPI+Search+Performance+Enhancements&spaceKey=PROD
        """
        if method == CRUDMethodTypes.METHOD_DELETE:
            self.delete_kpi_base_search(owner, objects, req_source)
        # Dont really need change handlers here since post save will take care of most updates
        return False, []

    def post_save_setup(self, owner, ids, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Extended as a part of the contract for ItoaObject subclasses, this one performs the optional step of
        creating/updating the saved searches that apply to them
        @param owner: The owner
        @type owner: string
        @param ids: An array of dicts in the form of {"_key":<key>"}
        @type ids: list
        @param objects: The objects used in the create call
        @type objects: List of dicts
        @param req_source: Required source
        @type req_source: string
        @param methpd: The method string used to generate the data
        @type method: CRUDMethodType constant
        """
        if len(ids) != len(objects):
            raise Exception(_("Error getting the appropriate id array for object array"))

        if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:
            # We're doing an upsert or update, for both of these we have more complicated adjustments to make
            self.update_kpi_base_search(owner, objects, transaction_id=transaction_id)

        for idx, base_search in enumerate(objects):
            bs_id = ids[idx]
            if isinstance(bs_id, dict):
                bs_id = bs_id['_key']
            search = ItsiSharedAdhocSearch(self.session_key, bs_id, base_search)
            search.create_splunk_search()

    def do_additional_setup(self, owner, objects, req_source='unknown', method=CRUDMethodTypes.METHOD_UPSERT, transaction_id=None):
        """
        Any additional setup required before saving base search 
        should be done here.
        
        @type owner: basestring
        @param owner: request owner. "nobody" or some username.

        @type objects: list
        @param objects: List of base search type objects

        @type req_source: basestring
        @param req_source: Source requesting this operation.

        @type method: basestring
        @param method: operation type. Defaults to upsert.

        @type transaction_id: basestring
        @param transaction_id: transaction id for end-end tracing.

        @rtype: None
        @return: Nothing 
        """
        # PBL-5603: changes made in this story, allow user to split KPI by a different entity field from
        # entity filtering field. As a part of this change, new field 'entity_breakdown_id_fields'
        # was added to KPI object. To guard against migration issues and cases where
        # 'entity_breakdown_id_fields' would be missing in kpi object, added following check. We fall back
        # to 'entity_id_fields', in cases when 'entity_breakdown_id_fields' is missing.
        for base_search in objects:
            if base_search.get('is_entity_breakdown', False):
                entity_breakdown_id_fields = base_search.get('entity_breakdown_id_fields', None)
                if entity_breakdown_id_fields is None or len(entity_breakdown_id_fields) == 0:
                    base_search['entity_breakdown_id_fields'] = base_search.get('entity_id_fields', '')
                    logger.debug('entity_breakdown_id_fields missing from base search object = {}. '
                                 'Setting it to entity_id_fields.'.format(base_search.get('_key')))
        # Do not allow delete of kpi base search metric if it's used by service templates
        if method == CRUDMethodTypes.METHOD_UPDATE or method == CRUDMethodTypes.METHOD_UPSERT:
            # check if the metric is used by service template
            results = ServiceTemplateUtils(self.session_key, self.current_user_name).get_base_search_used_metric_not_deleted(objects)
            if not results:
                self.raise_error_bad_validation(logger, 'KPI base search metric cannot be deleted because it is being used by one or more service templates.')

    def can_be_deleted(self, owner, objects, raise_error=False, transaction_id=None):
        # Do not allow delete of kpi base search if it's used by service templates
        results = ServiceTemplateUtils(self.session_key, self.current_user_name).get_objects_not_used_by_service_templates(self.object_type,
                                                                                                                           objects)
        if raise_error and not results:
            self.raise_error_bad_validation(logger, 'KPI base search cannot be deleted because it is being used by one or more service templates.')

        return results