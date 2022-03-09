# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
CUD the AT AD saved searches based on the service setting
'''
from . import itoa_change_handler
from string import Template
from itsi.event_management.itsi_correlation_search import ItsiCorrelationSearch
from itsi.searches.itsi_at_search import ItsiAtSearch
from splunk.appserver.mrsparkle.lib import i18n
from splunk import ResourceNotFound


class KpiAtAdUpdateHandler(itoa_change_handler.ItoaChangeHandler):
    """
    Create or delete the anomaly detection saved search based on
    anomaly detection being turned on or off

    Every distinct training period corresponds to a saved search that
    filters KPI summary index according to a set of KPI IDs and feeds
    the data into the itsiad command.  This change handler creates,
    updates, or deletes those searches.
    """

    def deferred(self, change,transaction_id=None):
        """
        For every impacted KPI this method will return a saved search name and
        a string-valued flag <"add"|"remove"> indicating whether this KPI is
        being added to or removed from the saved search. Note that the saved
        search with the given name may not exist yet.

        After that it will enable/disable anomaly detection searches

        @param change:
               change.changed_object_type: must equal `kpi`
               change.changed_object_key: list of KPI IDs with AD turned on
               change.change_type: must equal `service_kpi_ad` or `service_kpi_at`
               change.change_detail: dict with at least the following fields:
                                 - kpi_data: dict keyed by KPI ids containing relevant KPI attributes
                                   - kpi_data.training_window
                                   - kpi_data.service_id
                                   - kpi_data.change_summary: one of `on`, `changed`, `unchanged`, `off`
                                   /for AT jobs/
                                     <no special attributes currently required>
                                   /for AD jobs/
                                   - kpi_data.alert_period: alert period for that KPI (in minutes)
                                   - kpi_data.anomaly_detection_alerting_enabled: boolean flag for the alert enabled/disabled state

        NOTE: both change.changed_object_key and change.change_kpi_data must contain all the
        KPIs with AD turned on, regardless of whether they were just turned on or have been on since forever.

        @returns: Boolean indicating success
        """
        if change.get('changed_object_type') != 'kpi':
            raise Exception(_('Expected changed_object_type to be "kpi"'))

        change_type = change.get('change_type', '')
        if not change_type.startswith('service_kpi_at'):
            raise Exception(_('Expected change_type to be "service_kpi_at"'))

        self.owner = 'nobody'
        # The impacted objects are the saved AT searches that need to be created or deleted.
        # For AD we have N saved searches where N is the number of distinct training windows
        # in use. In this method, we get the names of all searches needing creates/deletes/updates.

        impacted_objects = {}

        self.saved_search_interface = ItsiAtSearch(self.session_key)
        impacted_objects['saved_searches'] = self._get_saved_search_params(change)
        self.logger.debug("impacted_objects: %s", impacted_objects)

        if impacted_objects is None or len(impacted_objects) == 0:
            return True  # Noop

        retval = []

        if 'saved_searches' in impacted_objects:
            retval.append(self._update_saved_searches(impacted_objects['saved_searches']))

        return all(retval)

    def _get_saved_search_params(self, change):
        """
        Saved search parameters returned as a dict keyed by the saved search name
        @param change: change dict
        @returns {<search name>: {
                         'et': <search earliest time>,
                         'training_days': <integer number of training days (used in AD searches)>,
                         'operation': <one of `create`, `update`, `delete`>,
                         'kpi_list': <set of kpis that are on in this search>
                  }}
        Important note: a <search name> key is present in the returned dict if and only if
        a corresponding saved search has at least one KPI associated with it.  Thus, if there
        exist saved searches that do not correspond to keys in this dict, they can be safely removed.
        """

        def get_search_et(kpi_record):
            """Get earliest time for a single KPI"""
            training_window = kpi_record['training_window']
            return self.saved_search_interface.compute_earliest_time(training_window)

        def get_num_training_days(kpi_record):
            """Get the number of days to apply training window"""
            training_window = kpi_record['training_window']
            default = 1
            try:
                ndays = self.saved_search_interface.to_days(training_window)
                if ndays < 1:
                    return default
                else:
                    return ndays
            except Exception as e:
                self.logger.warning("Failing to convert training window parameter %s, falling back on default of 1: %s", training_window, e)
                return default

        # FIXME: ITOA-7612
        # pull in existing searches to compute the updates that need to be performed to each search's KPI set
        existing_searches = self.saved_search_interface.get_all_searches()

        search_records = {}  # existing searches keyed by search name; contain `kpi_list`, `et`
        kpi_searches = {}            # (existing KPIs -> existing search name) mapping
        for existing_search_name, existing_search in existing_searches.iteritems():
            _kpis = [x.strip() for x in existing_search['content'].get('action.summary_index._kpi_id_list', '').split(',')]
            for k in _kpis:
                kpi_searches[k] = existing_search_name
            try:
                _et = existing_search['content']['action.summary_index._et']
                # we store earliest time in a separate field so that we know its exact format
            except KeyError:
                _et = existing_search['content'].get('dispatch.earliest_time')
            search_records[existing_search_name] = {
                'kpi_list': set(_kpis),
                'et': _et,
                'operation': 'noop'
            }
        self.logger.debug("existing_searches: %s", existing_searches.keys())
        self.logger.debug("kpi_searches mapping: %s", kpi_searches)

        # the following helper methods operate on the `search_records` and `kpi_searches` structures
        def remove(kpi_id):
            self.logger.debug("Removing KPI %s from search %s", kpi_id, kpi_searches[kpi_id])
            search_records[kpi_searches[kpi_id]]['kpi_list'].remove(kpi_id)
            if len(search_records[kpi_searches[kpi_id]]['kpi_list']) == 0:
                operation = 'delete'
            else:
                operation = 'update'
            search_records[kpi_searches[kpi_id]]['operation'] = operation
            del kpi_searches[kpi_id]

        def add(kpi_id, search_name, kpi_attrs):
            self.logger.debug("Adding KPI %s", kpi_id)
            kpi_searches[kpi_id] = search_name
            if search_name not in search_records:
                self.logger.debug("Creating new search %s", search_name)
                search_records[search_name] = {
                    'kpi_list': set([kpi_id]),
                    'et': get_search_et(kpi_attrs),
                    'training_days': get_num_training_days(kpi_attrs),
                    'operation': 'create'
                }
            else:
                self.logger.debug("Appending to search %s", search_name)
                cur_record = search_records[kpi_searches[kpi_id]]
                cur_et = cur_record['et']
                cur_record['kpi_list'].add(kpi_id)
                cur_record['operation'] = 'update'
                cur_record['training_days'] = get_num_training_days(kpi_attrs)
                cur_record['et'] = min(cur_et, get_search_et(kpi_attrs), key=lambda x: int(x.strip('m')))

        def transfer(kpi_id, new_search_name, kpi_attrs):
            self.logger.debug("Transfering a KPI")
            remove(kpi_id)
            add(kpi_id, new_search_name, kpi_attrs)


        # compute the updates by parsing the change spec
        change_spec = change['change_detail']['kpi_data']  # kpi to kpi attr mapping
        self.logger.debug("kpi data: %s", change_spec)
        for kpi_id, kpi_attrs in change_spec.iteritems():
            search_name = self.saved_search_interface.make_search_name(kpi_attrs['training_window'])
            state = kpi_attrs['change_summary']
            if state not in ('on', 'off', 'changed'):
                continue
            if state in ('off', 'changed') and kpi_id not in kpi_searches:
                self.logger.warning("KPI %s change state is %s indicating it has been saved previously, "
                                    "yet we failed to find its associated search", kpi_id, state)
                if state == 'changed':  # add this anyway -- more robust this way
                    state = 'on'
                else:
                    continue
            if state == 'on':
                add(kpi_id, search_name, kpi_attrs)
            elif state == 'off':
                remove(kpi_id)
            else: # transfer
                transfer(kpi_id, search_name, kpi_attrs)

        return search_records

    def _update_saved_searches(self, impacted_searches):
        retval = []
        for search_name, params in impacted_searches.iteritems():
            kpi_list = params.get('kpi_list', [])
            training_days = params.get('training_days', 1)
            kpi_filter_string = " OR ".join("itsi_kpi_id=" + x for x in kpi_list)
            if params['operation'] == 'create':
                self.logger.debug("Name %s not in existing searches, calling create", search_name)
                if not kpi_filter_string:  # this should normally not occur
                    self.logger.warning("Aborting call to create since no valid filter string was found")
                    success = True
                else:
                    search_string = self.saved_search_interface.make_search(kpi_filter_string=kpi_filter_string, training_days=training_days)
                    success = self.saved_search_interface.create_saved_search(search_name, search_string, params['et'], kpi_list)
                retval.append(success)
            elif params['operation'] == 'update':
                self.logger.debug("Name %s is in existing searches, calling update or delete", search_name)
                self.logger.debug("Updating saved search %s", search_name)
                search_string = self.saved_search_interface.make_search(kpi_filter_string=kpi_filter_string, training_days=training_days)
                success = self.saved_search_interface.update_saved_search(search_name, search_string, params['et'], kpi_list)
                retval.append(success)
            elif params['operation'] == 'delete':
                self.logger.debug("Deleting saved search %s", search_name)
                success = self.saved_search_interface.delete_saved_search(search_name)
                retval.append(success)

        return all(retval)

