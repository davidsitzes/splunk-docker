# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import logging

from ITOA.setup_logging import setup_logging
from itsi.objects.itsi_service import ItsiService

class KPISearchRetriever(object):
    '''
        A class which retrieves the search string for a KPI.
    '''

    def __init__(self, read_results, settings, args, is_debug=False):
        '''
        Initialize the class
        :param read_results: results provided by splunk search
        :param settings: settings provide by search
        :param args: arguments to search command (serviceId, kpiId, search_alert, [is_debug])
        :param is_debug: flag to set debug level for logs
        :return:
        '''
        if is_debug:
            level = logging.DEBUG
        else:
            level = logging.WARN

        self.logger = setup_logging("itsi_searches.log", "itsi.object.kpi.search",
                                    is_console_header=True,
                                    level=level)

        self.settings = settings
        self.args = args

    def _get_kpi_search(self):
        '''
        Get kpi search information for kpi
        :return: [] of {search}
        '''
        owner = "nobody"
        toReturn = []

        # Validate args before trying to perform get
        if 'serviceId' not in self.args['kvargs']:
            message = _("'serviceId' attribute does not exist in args")
            self.logger.debug(message)
            raise Exception(message)
        if len(self.args['kvargs']['serviceId']) == 0:
            self.logger.debug("'serviceId' attribute is empty")
            return toReturn
        serviceId = self.args['kvargs']['serviceId'][0]  # fields are arrays, so grab first value

        if 'searchField' not in self.args['kvargs']:
            message = _("'searchField' attribute does not exist in args")
            self.logger.debug(message)
            raise Exception(message)
        if len(self.args['kvargs']['searchField']) == 0:
            self.logger.debug("'searchField' attribute is empty")
            return toReturn
        searchField = self.args['kvargs']['searchField'][0]  # fields are arrays, so grab first value

        kpiFieldStr = "kpis." + searchField;
        service_object = ItsiService(self.settings['sessionKey'], 'nobody')
        fetched_all_services_object = service_object.get_bulk(owner, fields=["_key", "kpis._key", "kpis.title",
                                                                             "kpis.base_search", kpiFieldStr],
                                                              filter_data={"_key": serviceId})

        if fetched_all_services_object is None:
            self.logger.debug(
                "unable to fetch service objects with owner: {0}, searchField: {1}".format(owner, searchField))
            return toReturn
        if len(fetched_all_services_object) == 0:
            self.logger.debug(
                "unable to fetch service objects with owner: {0}, searchField: {1}".format(owner, searchField))
            return toReturn

        for service in fetched_all_services_object:
            if 'kpis' in service:
                # go through KPIs and get required attributes
                for kpi in service['kpis']:
                    kpiId = kpi.get('_key')
                    kpiTitle = kpi.get('title')
                    kpiSearchString = kpi.get(searchField)
                    toReturn.append({
                    "kpiId": kpiId,
                    "title": kpiTitle,
                    "search": kpiSearchString
                    });
        return toReturn


    def execute(self):
        '''
            Function which calculates all type of scores
            Splunk search should provide fields
                serviceId, kpiId, search_alert, [is_debug]

            Output results should have following fields
                search
        '''
        searchObjArr = self._get_kpi_search()
        if searchObjArr is not None:
            return searchObjArr
        else:  # unable to fetch search string for KPI
            return [{}]  # return no results found - should this be an empty array? array with empty object? None?



