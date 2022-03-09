# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import time

from splunk.appserver.mrsparkle.lib import i18n
from migration.migration import MigrationFunctionAbstract
from ITOA.setup_logging import setup_logging
from itsi.itsi_utils import ITOAInterfaceUtils
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch

logger = setup_logging("itsi_migration.log", "itsi.migration")

class GlassTableMigrator(MigrationFunctionAbstract):
    """
    Migration handler to update the drilldown settings for widgets on existing glass tables / glass tables created in
    previous versions of ITSI. Before 3.1.x, glass table widgets that had a 'Custom Drilldown' as OFF still 'drilled down'
    by the default Drilldown. In 3.1.x onwards, if a drilldown is set to OFF, it will not drilldown. Existing widgets
    in glass tables will be set to 'ON' and 'Default' if widgets were set to OFF
    """

    def __init__(self, session_key):
        super(GlassTableMigrator, self).__init__(session_key)
        self.session_key = session_key

    @staticmethod
    def set_off_custom_drilldowns_on(glass_table):
        """
        Utility method to set custom drilldown for old glasstables to On if OFF previously
        @type glass_table: dict
        @param glass_table: a glass table that may need to get updated
        @return: None
        """
        for widget in glass_table.get('content', []):
            logger.info("Widget is: ")
            logger.info(widget)
            if not isinstance(widget.get('drilldownModel'), dict):
                logger.warn('drilldownModel for widget looks invalid, skipping glass table adjustment')
                continue
            model = widget.get('drilldownModel')
            if model.get('useCustomDrilldown') == False:
                # If useCustomDrilldown is False, set it True (ON)
                model['useCustomDrilldown'] = True
                # and set it to Default
                model['drilldownSettingsModel'] = {
                    'objectType': 'default',
                    'objPage': 'search',
                    'objOwner': 'nobody',
                    'objId': '',
                    'customUrl': '',
                    'params': {}
                }

    @staticmethod
    def change_small_widgets_to_toolbar_widgets(glass_table):
        """
        Utility method to change the small widgets on the glass table to toolbar widgets
        @type glass_table: dict
        @param glass_table: a glass table that may need to get updated
        @return: None
        """
        for widget in glass_table.get('content', []):
            if widget.get('name', None) == 'CircularWidget' or widget.get('name', None) == 'SquareWidget':
                if widget.get('name', None) == 'CircularWidget':
                    widget['name'] = 'Ellipse'
                elif widget.get('name', None) == 'SquareWidget':
                    widget['name'] = 'Rectangle'
                widget['vizType'] = 'toolbar_widget'
                widget['stroke'] = 1
                widget['colorCalc'] = 'kpi'
                widget['bgColor'] = '#FFFFFF'
                widget['color'] = '#333333'

    def _fetch_and_migrate(self):
        """
        Fetch and migrate all glass tables that already exist.
        """
        status = None
        try:
            # get all aggregation policies
            gt_itr = self.get_object_iterator('glass_table')
            all_glass_tables = []

            for table in gt_itr:
                # Go through glass tables and update
                GlassTableMigrator.set_off_custom_drilldowns_on(table)
                GlassTableMigrator.change_small_widgets_to_toolbar_widgets(table)
                all_glass_tables.append(table)

            status = self.save_object('glass_table', all_glass_tables)
        except Exception, e:
            logger.exception('Failed to migrate glass tables')
            message = _('Failed to update Glass Tables set any default drilldowns that were OFF to ON - Default')
            ITOAInterfaceUtils.create_message(self.session_key, message)
            status = False
        logger.info('No exceptions when saving. Save status=%s', status)
        return status

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._fetch_and_migrate()

class UpdateSearchAndService(MigrationFunctionAbstract):
    """
    Migration handler to update all searches in the savedsearch.conf and service collection
    With the setserverityfield cmd optimization, some of the search clause in search
    needs to be updated.
    """
    def __init__(self, session_key):
        super(UpdateSearchAndService, self).__init__(session_key)
        self.session_key = session_key

    def _fetch_and_migrate(self):
        """
        Fetch all the shared base search
        """
        base_searches_to_update = []
        status = True
        try:
            object_collection = []
            services = self.get_object_iterator('service')
            for service in services:
                kpis = service.get('kpis', [])
                for kpi in kpis:
                    if kpi['search_type'] == 'shared_base' and \
                       kpi.get('base_search_id') is not None and \
                       kpi.get('base_search_id') not in base_searches_to_update:
                        base_searches_to_update.append(kpi['base_search_id'])
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
            logger.exception('Fail to update searches')
            status = False
        return status

    def execute(self):
        """
        Method called by migration pipeline. Just a wrapper.
        """
        return self._fetch_and_migrate()