# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from itsi_atad_search_base import ItsiAtAdSearchBase
from ITOA import itoa_common as utils
from string import Template

logger = utils.get_itoa_logger('itsi.object.at_search')

AT_SEARCH_TEMPLATE = Template("  `get_itsi_summary_index` ($kpi_filter_string) "
                              "  `service_level_kpi_only` alert_value!=\"N/A\" alert_level!=-2"
                              "| eval itsi_service_id=mvdedup(itsi_service_id) | eval itsi_kpi_id=mvdedup(itsi_kpi_id) "
                              "| itsiat ")


class ItsiAtSearch(ItsiAtAdSearchBase):
    """
    Implements ITSI AT Search
    Contains CRUD operations and utility functions pertaining to AT searches
    """

    log_prefix = '[ITSI AT Search] '
    collection_name = 'itsi_service'

    def __init__(self, session_key):
        super(ItsiAtSearch, self).__init__(session_key, logger=logger)

    def make_search_name(self, training_window_id):
        """
        Generate name for AT search stanza
        @param training_window_id: training window string
        @returns: name for AT search stanza
        """
        return 'itsi_at_' + self._make_search_name_suffix(training_window_id)

    def get_all_searches(self):
        """
        @returns: dict of saved searches keyed by stanza name
        """
        return self._get_all_searches(lambda x: x.startswith('itsi_at_search'))

    def make_search(self, **params):
        """
        Generate AT search string
        @param **params: keyword args needed for search generation;
                         required args: `kpi_filter_string`
        @returns: AT search string
        """
        if 'kpi_filter_string' not in params:
            logger.error("Missing parameters to search template, got %s", params)
            raise Exception(_("Missing parameters to search template"))
        return AT_SEARCH_TEMPLATE.substitute(**params)

    def compute_earliest_time(self, training_window):
        """
        Compute earliest time (in relative minutes) for AT search
        @param training_window: AT training window, as a relative time spec in days, minutes, or hours ('-Xd' or '-Xm')
        @returns: relative time string for search earliest time in minutes, e.g. '-1940m'
        """
        return '-%sm' % (self.to_minutes(training_window))

    def make_saved_search_params(self, name, search, et, kpi_list):
        """
        @param name: search stanza name
        @param search: search string
        @param et: earliest time (relative timespec)
        @param kpi_list: list of KPI IDs
        @returns: dict of key/value pairs for the saved search stanza
        """
        return {
            'name': name,
            'disabled': False,
            'enableSched': 1,
            'cron_schedule': '0 0 * * *',
            'dispatch.earliest_time': et,
            'dispatch.latest_time': 'now',
            'action.summary_index._kpi_id_list': ','.join(kpi_list),
            'action.summary_index._et': et, # save earliest time to persist it in format user can't override
            'search': search
        }
