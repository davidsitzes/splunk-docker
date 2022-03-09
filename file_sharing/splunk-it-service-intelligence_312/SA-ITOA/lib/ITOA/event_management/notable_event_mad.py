# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import datetime
import time
import re

from splunk.appserver.mrsparkle.lib import i18n
import splunk.rest as splunk_rest
import splunk.search as splunk_search
from splunk.util import safeURLQuote
from ITOA.setup_logging import setup_logging
from itsi.event_management.itsi_notable_event import ItsiNotableEvent
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity

class NotableEventMadException(Exception):
    pass

class NotableEventMad(object):

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None,
                 audit_token_name='Auto Generated ITSI Notable Index Audit Token', **kwargs):
        """
        Notable event MAD special process

        @type session_key: basestring
        @param session_key: session key

        @type app: basestring or str
        @param app: app name

        @type owner: basestring or str
        @param owner: owner name

        @type logger: object
        @param logger: logger

        @type audit_token_name: basestring
        @param audit_token_name: audit token name

        @type kwargs: dict
        @param kwargs: extra params

        @rtype: instance of class
        @return: object
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.default_status = '1'
        self.default_owner = 'unassigned'
        self.default_severity = '4'

        if logger is None:
            self.logger = setup_logging('itsi_event_management.log',
                    'itsi.notable_event.mad')
        else:
            self.logger = logger

    def transform_raw_mad_events(self, data):
        if isinstance(data, basestring):
            try:
                json_content = json.loads(data)
            except Exception:
                message = _('Failure parsing string data into json')
                self.logger.exception(message)
                raise NotableEventMadException(message)
        else:
            json_content = data

        if not isinstance(json_content, dict):
            raise TypeError(_('Data is not a valid dictonary, data type is %s.'), type(json_content))

        self.logger.debug('Received raw mad event: %s', json_content)

        event_data = self.transform_event_management_data(json_content)
        if event_data:
            try:
                self.create_notable_event(event_data)
            except Exception:
                message = _('Notable event creation failed')
                self.logger.exception(message)
                raise NotableEventMadException(message)
        else:
            self.logger.debug('Notable event not generated!')

    def _get_entity_title(self, entity_key):
        """
        Get entity title given entity key
        :param entity_key: Identifier of the entity
        :return: Entity title
        """
        entity_object = ItsiEntity(self.session_key, self.owner)
        impacted_entity = entity_object.get(self.owner, entity_key)
        if not impacted_entity:
            self.logger.warn('No corresponding entity was found for the entity key: %s', entity_key)
            return "N/A"
        return impacted_entity.get("title", "N/A")

    def _get_entity_info(self, entity_ident):
        """
        Parse entity_ident and interpret valid values for entity_key and entity_title
        :param entity_ident: Specifying type and id of the entity separated by ':'
        :return: Tuple representing entity_key and entity_title
        """
        entity_ident_split = entity_ident.split(":")
        try:
            (entity_type, entity_id) = (entity_ident_split[0], entity_ident_split[1])
            if entity_type == "defined":
                entity_key = entity_id
                entity_title = self._get_entity_title(entity_key)
            elif entity_type == "pseudo":
                entity_key = "N/A"
                entity_title = entity_id
            return (entity_key, entity_title)
        except Exception:
            return ("N/A", "N/A")


    def transform_event_management_data(self, data):
        """
        Map the incoming MAD alert event into event management data structure.
        @type data: dict
        @param data: incoming MAD alert event
        @return: Transformed event management data
        """

        kpi_id = data.get('itsi_kpi_id', 'UNKNOWN NAME')
        threshold = data.get('threshold', '')
        score = data.get('score', '')
        alert_value = data.get('alert_value', '')
        time_stamp = data.get('_time', 0.0)
        drilldown_search_latest_offset = '302400'
        drilldown_search_earliest_offset = '-302400'
        source = 'MetricAD'
        event_identifier_fields = 'source, title, description, ad_at_kpi_ids'
        ad_at_kpi_ids = ''
        kpi_title = None
        event_data = None
        span = ''
        service_id = data.get('itsi_service_id', 'UNKNOWN NAME')

        service_object = ItsiService(self.session_key, self.owner)
        impacted_service = service_object.get(self.owner, service_id)

        if not impacted_service:
            self.logger.warn('No corresponding services were found, no MAD alert message will be pushed')
            return event_data

        requested_kpis = impacted_service.get('kpis', [])
        for kpi in requested_kpis:
            if kpi_id == kpi.get('_key', ''):
                # Alerting is enabled by default from Catwoman onwards.
                # Hence "anomaly_detection_alerting_enabled' is always true.
                # Will leave this condition for now in case.
                if not kpi.get('anomaly_detection_alerting_enabled', False):
                    self.logger.info('Received alert from MAD, but AD alert is not enabled, suppress the MAD alert message')
                    return event_data
                kpi_title = kpi.get('title', '')
                span = str(kpi.get('alert_period', 5)) + 'm'
                break

        # If KPI can not be found, return None
        if not kpi_title:
            self.logger.info('The KPI %s in the service %s was not found, the KPI may have been deleted', kpi_id, service_id)
            return event_data

        if service_id:
            ad_at_kpi_ids = service_id + ':' + kpi_id

        trending_ad_hoc_search = "`get_itsi_summary_index` itsi_kpi_id={1} indexed_is_service_aggregate::1 | reverse | " \
                                 "mad trending alert_value span={0} itsi_kpi_id={1}".format(span, kpi_id)

        cohesive_ad_hoc_search = "`get_itsi_summary_index` itsi_kpi_id={1} indexed_is_service_aggregate::0 | " \
                                 "eval entity_id=if(entity_key==\"N/A\", \"pseudo:\"+entity_title, \"defined:\"+entity_key) | " \
                                 "reverse | mad cohesive alert_value group_by=entity_id span={0} itsi_kpi_id={1}".format(span, kpi_id)


        status = self.default_status
        severity = self.default_severity
        owner = self.default_owner
        try:
            mod_time = datetime.datetime.fromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S.%f')
        except Exception, exc:
            self.logger.exception(exc)
            mod_time = time_stamp

        # Alert type if defaulted to trending.
        alert_type = data.get('alert_type', 'trending')

        if alert_type == 'trending':
            drilldown_search_title = 'Service Level Behavior In 7 days Duration'
            drilldown_search_search = trending_ad_hoc_search
            title = 'Service level alert on KPI: {}'.format(kpi_title)
            description = ('Service level alert on KPI {0}, with anomaly score: {1}, alert_value: {2}, '
                       'threshold: {3}').format(kpi_title, score, alert_value, threshold)
            ad_type = 'trending'

        elif alert_type == 'cohesive':
            drilldown_search_title = 'Entity Level Behavior In 7 days Duration'
            drilldown_search_search = cohesive_ad_hoc_search
            title = 'Entity level alert on KPI: {}'.format(kpi_title)
            (entity_key, entity_title) = self._get_entity_info(data.get('entity_id', ''))
            description = ('Entity level alert on Entity {0} of KPI {1}, with anomaly score: {2}, alert_value: {3}, '
                       'threshold: {4}').format(entity_title, kpi_title, score, alert_value, threshold)
            ad_type = 'cohesive'

        event_data = {
                'status': status,
                'severity': severity,
                'owner': owner,
                'title': title,
                'description': description,
                '_time': time_stamp,
                'mod_time': mod_time,
                'drilldown_search_search': drilldown_search_search,
                'drilldown_search_title': drilldown_search_title,
                'drilldown_search_latest_offset': drilldown_search_latest_offset,
                'drilldown_search_earliest_offset': drilldown_search_earliest_offset,
                'event_identifier_fields': event_identifier_fields,
                'service_ids': service_id,
                'ad_at_kpi_ids': ad_at_kpi_ids,
                'kpiid': kpi_id,
                'source': source
                }
        if alert_type == 'trending':
            event_data.update({'anomaly_detection_type': ad_type})
            return event_data
        elif alert_type == 'cohesive':
            event_data.update({'anomaly_detection_type': ad_type,
                               'entity_key': entity_key,
                               'entity_title': entity_title})

        self.logger.debug('transformed event data: %s' % event_data)
        return event_data

    def create_notable_event(self, data):
        """
        Create notable event based on the transformed data
        @type data: dict
        @param data: transformed data
        @return: None
        """
        try:
            notable_event = ItsiNotableEvent(self.session_key)
            event_id = notable_event.create(data)
            self.logger.debug('notable event created, event id: %s' % event_id)
        except Exception as e:
            self.logger.exception('Unable to create notable event, check log for errors.')
            raise NotableEventMadException(_('Unable to create notable event, %s') % e)
