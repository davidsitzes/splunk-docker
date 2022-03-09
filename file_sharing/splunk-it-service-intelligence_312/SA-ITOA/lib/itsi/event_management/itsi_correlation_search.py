#Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
This module is being used to do CURD operation for ITSI correlation searches.
"""

import json
import sys
from uuid import uuid1

from splunk.util import fieldListToString, stringToFieldList, normalizeBoolean

from ITOA.event_management.correlation_search import CorrelationSearch, CorrelationSearchException
from itsi.event_management.correlation_search_generation import SearchGeneration

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

from SA_ITOA_app_common.solnlib.splunk_rest_client import SplunkRestClient


class ItsiCorrelationSearch(CorrelationSearch):
    """
    Main class to create/update/delete correlation search

    Schema for correlation search
        Refer itsi app - app-common/CorrelationSearchModel.js

    """

    def __init__(self, session_key, current_user_name=None, user='nobody',
                 app='itsi', logger=None, is_validate_service_ids=False):
        """
        Initialize objects

        @type session_key: basestring
        @param session_key: session_key

        @type collection: basestring
        @param collection: collection name

        @type user: basestring
        @param user: user name

        @type object_type: basestring
        @param object_type: object type

        @type logger: logger object
        @param logger: logger name

        @type is_validate_service_ids: bool
        @param is_validate_service_ids: set to false if service ids validation is not required. Normally it is required
                for migration from old search because some of correlation searches may not contain service ids
        @rtype: object
        @return: instance of the class
        """
        super(ItsiCorrelationSearch, self).__init__(session_key, current_user_name, user, app, logger)
        self.search_type_key = 'action.itsi_event_generator.param.search_type'
        self.basic_type = 'basic'
        self.service_ids_key = 'action.itsi_event_generator.param.service_ids'
        self.composite_kpi_score_type = 'composite_kpi_score_type'
        self.composite_kpi_percentage_type = 'composite_kpi_percentage_type'
        self.latest_key = 'dispatch.latest_time'
        self.earliest_key = 'dispatch.earliest_time'
        self.type_meta_data_key = 'action.itsi_event_generator.param.meta_data'
        self.is_ticket_key = 'action.itsi_event_generator.param.is_ticket'
        # Key called counttype in savedsearches.conf, alert_type in entity API
        self.counttype_key = 'alert_type'
        # Key called relation in savedsearches.conf, alert_comparator in entity API
        self.relation_key = 'alert_comparator'
        # Key called quantity in savedsearches.conf, alert_threshold in entity API
        self.quantity_key = 'alert_threshold'
        self.alert_condition_key = 'alert_condition'

        # Keys which is mainly used inside meta_data data
        self.score_based_kpis_key = 'score_based_kpis'
        self.percentage_based_kpis_key = 'percentage_based_kpis'
        self.is_validate_service_ids = is_validate_service_ids

    def extra_validation(self, search_schema_list, method):
        """
        This function is being used to validate and generate search for multi kpi alert
        based searches

        @type search_schema_list: list
        @param search_schema_list: List of saved search schema

        @type method: basestring
        @param method: method name

        @return: None
        """
        if not isinstance(search_schema_list, list):
            raise TypeError(_('Could not validate searches because provide data is not a valid list'))

        for data in search_schema_list:
            if not data:
                raise TypeError(_('Invalid data, type {0}').format(type(data)))
            search_type = data.get(self.search_type_key)

            # Dont need to trigger alerts when search finds no events
            # Also do not update if user has overridden default alert triggers
            if data.get(self.alert_condition_key) is None:
                if data.get(self.counttype_key) is None:
                    data[self.counttype_key] = 'number of events'
                if data.get(self.relation_key) is None:
                    data[self.relation_key] = 'greater than'
                if data.get(self.quantity_key) is None:
                    data[self.quantity_key] = '0'

            if search_type == self.composite_kpi_score_type:
                meta_data = data.get(self.type_meta_data_key)
                if not meta_data:
                    message = _('Could not find meta data to generate search')
                    self.logger.info(message)
                    raise TypeError(message)

                if isinstance(meta_data, basestring):
                    try:
                        meta_data = json.loads(meta_data)
                    except Exception as e:
                        self.logger.exception(e)
                        raise TypeError(_('Could not load meta data into json format'))

                search_gen = SearchGeneration(data.get('name'), meta_data,
                                              self.composite_kpi_score_type)
                latest, earliest = search_gen.get_search_earliest_latest(data.get(self.latest_key),
                                                                         data.get(self.earliest_key))
                self.logger.info('Updated earliest=%s and latest=%s time for search_name="%s"', earliest, latest,
                                 data.get(self.name_key))
                data[self.earliest_key] = earliest
                data[self.latest_key] = latest
            if search_type == self.composite_kpi_percentage_type:
                meta_data = data.get(self.type_meta_data_key)
                if not meta_data:
                    message = _('Could not find meta data to generate search')
                    self.logger.info(message)
                    raise TypeError(message)
                search_gen = SearchGeneration(data.get(self.id_key), meta_data,
                                              self.composite_kpi_percentage_type)

            if search_type == self.composite_kpi_percentage_type or search_type == self.composite_kpi_score_type:
                # Generate search
                data[self.search_key] = search_gen.get_search()
                self.logger.info('Generated search="%s" for search_name="%s"', data.get(self.search_key),
                                 data.get(self.name_key))
                # Set service ids
                data[self.service_ids_key] = search_gen.get_service_ids()
                self.logger.info('Generated service ids=%s for search_name="%s"', data.get(self.service_ids_key),
                                 data.get(self.name_key))
                # Dump the meta data only if it is a basestring and loadable object
                load_meta_data = data.get(self.type_meta_data_key)
                if isinstance(load_meta_data, basestring):
                    self.logger.debug('meta data is a string, make sure it is loadable')
                    try:
                        # Make sure the string is loadable
                        json.loads(load_meta_data)
                    except Exception as e:
                        self.logger.exception(e)
                        raise
                else:
                    # do json dumps on meta data so it would be easier to load on model
                    self.logger.debug('meta data is already in json format, dump it')
                    data[self.type_meta_data_key] = json.dumps(load_meta_data)

        # Now validate service ids, we have a
        if self.is_validate_service_ids and not self._validate_key(data, self.service_ids_key):
            msg = _('Service ids are not set, service_ids="{0}".').format(data.get(self.service_ids_key))
            self.logger.error(msg)
            raise ValueError(msg)
        return True

    def get_search_string(self, search_filter=None):
        """
        Get search string to filter

        @rtype: basestring
        @return: search string
        """
        search = 'action.itsi_event_generator=1'

        if search_filter:
            if isinstance(search_filter, (str, unicode)):
                search_filter = json.loads(search_filter)

            conditional = search_filter.keys()[0]
            search_keys = []
            for pair in search_filter.get(conditional):
                search_keys += ['{}="{}"'.format(key, value)
                                for key, value in pair.iteritems()]
            conditional = ' {} '.format(conditional)
            search += ' AND ({})'.format(conditional.join(search_keys))

        return search

    def get_associated_search_with_service_or_kpi(self, service_ids=None, kpi_ids=None):
        """
        Get correlation search which is associated with given service id and kpi id

        @type service_ids: basestring
        @param service_ids: service ids

        @type kpi_ids: basestring
        @param kpi_ids: kpi_ids

        @rtype: base string
        @return: correlation search name
        """
        if not service_ids and not kpi_ids:
            message = _('Service id or kpi id are not provided')
            self.logger.error(message)
            raise ValueError(message)
        if service_ids and not isinstance(service_ids, list):
            message = _('Service id is not valid')
            self.logger.error(message)
            raise TypeError(message)
        if kpi_ids and not isinstance(kpi_ids, list):
            message = _('Kpi id is not list')
            self.logger.error(message)
            raise TypeError(message)

        searches = self.get_bulk(None)
        ids_hash = {}
        if service_ids:
            for sid in service_ids:
                ids_hash[sid] = False
        if kpi_ids:
            for kid in kpi_ids:
                ids_hash[kid] = False

        # Just verify if kpi or service id exists
        final_search_list = []
        for search in searches:
            if service_ids:
                for sid in stringToFieldList(search.get(self.service_ids_key)):
                    # Check
                    if sid in ids_hash:
                        final_search_list.append(search)
                        break
            if kpi_ids and search.get(self.type_meta_data_key):
                try:
                    meta_data = json.loads(search.get(self.type_meta_data_key))
                except Exception as e:
                    self.logger.error('Failed to read meta data of search, skipping this search=%s', search.get('name'))
                    self.logger.exception(e)
                    continue
                search_type = search.get(self.search_type_key)

                if search_type == self.composite_kpi_percentage_type:
                    for info in meta_data.get(self.percentage_based_kpis_key):
                        if info.get('kpiid') in ids_hash and search not in final_search_list:
                            final_search_list.append(search)
                            break
                if search_type == self.composite_kpi_score_type:
                    for info in meta_data.get(self.score_based_kpis_key):
                        if info.get('kpiid') in ids_hash and search not in final_search_list:
                            final_search_list.append(search)
                            break

        return final_search_list

    def _remove_id_from_meta_data(self, meta_data, removable_id, id_key):
        """
        Remove given id from given meta data. It does inplace changes in the given meta data.
        @type meta_data: dict
        @param meta_data: dict which hold meta data information for composite KPIs

        @type removable_id: basestring
        @param removable_id: id to remove

        @param id_key: basestring
        @param id_key: key in dict which old that value

        @rtype: dict
        @return: updated dict
        """
        # Note this supporting function, assumption that all validation has done upfront
        if meta_data and meta_data.get(self.score_based_kpis_key):
            new_score_based_kpis = []
            for data in meta_data.get(self.score_based_kpis_key):
                if data.get(id_key) != removable_id:
                    new_score_based_kpis.append(data)
            meta_data[self.score_based_kpis_key] = new_score_based_kpis
        if meta_data and meta_data.get(self.percentage_based_kpis_key):
            new_per_base_kpis = []
            for data in meta_data.get(self.percentage_based_kpis_key):
                if data.get(id_key) != removable_id:
                    new_per_base_kpis.append(data)
            meta_data[self.percentage_based_kpis_key] = new_per_base_kpis
        return meta_data

    def delete_and_post_message(self, name):
        """
        Delete correlation search and post message to user

        @type name: basestring
        @param name: search name

        @return: None
        """
        self.logger.debug('Deleting search=%s', name)
        self.delete(name)
        self.logger.info('Deleted search=%s', name)
        if self.post_message('Correlation Search {0} has been deleted because all corresponding Service or'
                             ' Kpis has been deleted from system'.format(name)):
            self.logger.info('Successfully post message to user')
        else:
            self.logger.error('Failed to post message to user')

    def post_message(self, message):
        """
        Post message to the end user

        @type message: basestring
        @param message: message

        @rtype: bool
        @return: True|False
        """
        if message:
            message = message if len(message) <= 500 else message[0:499] + '...'
            try:
                msg = SplunkRestClient(
                        session_key=self.session_key,
                        owner=self.owner,
                        app=self.app).messages
                return msg.post(name=str(uuid1()), value=message, severity='info')
            except Exception as e:
                self.logger.exception(e)

    def update_service_or_kpi_in_correlation_search(self, id_key, ids,
                                                    is_disable=True, searches=None):
        """
        Update service id or KPI id in meta data or service_ids property of given search, based upon its type
        It also disable them along with updating their meta data

        @type id_key: basestring
        @param id_key: key (possible values are kpiid and serviceid)

        @type ids: list
        @param ids: list of ids to remove

        @type is_disable: bool
        @param is_disable: flag to disable those search where we are updating meta or service ids

        @type searches: list
        @param searches: passes searches if already fetch
        @return:None
        """
        # Validation is done in get function so no need to do it here
        if not searches:
            if id_key == 'serviceid':
                searches = self.get_associated_search_with_service_or_kpi(service_ids=ids)
            if id_key == 'kpiid':
                searches = self.get_associated_search_with_service_or_kpi(kpi_ids=ids)

        if not searches:
            self.logger.info('Could not find any correlation search which was depends on ids=%s, id_key=%s',
                             ids, id_key)
            return

        for search in searches:
            # Update meta_data first
            search_type = search.get(self.search_type_key)
            if search_type == self.composite_kpi_percentage_type or search_type == self.composite_kpi_score_type:
                if not search.get(self.type_meta_data_key):
                    self.logger.warning('No meta data for search=%s', search.get('name'))
                    continue
                json_meta_data = json.loads(search.get(self.type_meta_data_key))
                for eid in ids:
                    self._remove_id_from_meta_data(json_meta_data, eid, id_key)

                if (search_type == self.composite_kpi_percentage_type and
                        not json_meta_data.get(self.percentage_based_kpis_key)) or \
                        (search_type == self.composite_kpi_score_type and
                            not json_meta_data.get(self.score_based_kpis_key)):
                    self.delete_and_post_message(search.get('name'))
                else:
                    search[self.type_meta_data_key] = json_meta_data
                    # service ids keys update automatically
                    if is_disable:
                        search['disabled'] = '1'
                    name = search.get('name')
                    self.logger.info('Associated kpi or service id is deleted,'
                                     ' so updating search=%s data and disabling it', name)
                    if not self.update(name, search, enforce_rbac=False):
                        msg = _('Failed to update correlation search={0}, with data="{1}".').format(name,
                                                                                                search)
                        self.logger.error(msg)
                        raise CorrelationSearchException(msg)
                    else:
                        if not is_disable:
                            continue
                        # post message to user only when search was disabled
                        if self.post_message('Correlation Search {0} has been disabled because some corresponding'
                                             ' Service(s) or Kpi(s) has been deleted from system'.format(name)):
                            self.logger.info('Successfully posted disable correlation search message to user')
                        else:
                            self.logger.error('Failed to post disabled correlation search message to user')
            else:
                service_ids =\
                        list(set(stringToFieldList(search.get(self.service_ids_key))).difference(ids))
                self.logger.info('Updated service ids=%s', service_ids)
                if not service_ids:
                    # Need to delete correlation search and post message
                    self.delete_and_post_message(search.get('name'))
                else:
                    self.logger.info('Disabling search because correlation search has impacted with service deletion,'
                                     ' search=%s', search.get('name'))
                    search[self.service_ids_key] = fieldListToString(service_ids)
                    if is_disable:
                        search['disabled'] = '1'
                    if not self.update(search.get('name'), search, enforce_rbac=False):
                        msg = _('Failed to update correlation search={0}, with data="{1}".').format(search.get('name'),
                                                                                                search)
                        self.logger.error(msg)
                        raise CorrelationSearchException(msg)
