# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import cherrypy
import sys
import json

import splunk.appserver.mrsparkle.controllers as controllers

from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects

from itsi.searches.compute_health_score import ScoreCalculation, ThresholdSettings
from itsi.health_services.health_services_provider import Provider

from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi.log", "itsi.controllers.health_services")
logger.debug("Setup health provider controller ...")


class HealthProviderService(ITOABaseController, controllers.BaseController):
    '''
        Health Provider
        This controller provides
            - health calculation for given severity and importance list
            - Provide range for given health status
            - Provide status of given score
    '''

    @route('/:action=get_health_score')
    @expose_page(must_login=True, methods=['POST'])
    def get_health(self, action, **kwargs):
        '''
        Get health score for given list of urgency and urgency
        :param action: get_health_score
        :param kwargs: severity_urgency_list: json serialize list of urgency and status
                each item of list should be as follows
                {
                    urgency: {int} {Required} <importance or urgency value>
                    severity_name: {string} {Optional if severity_level specified} <severity name>
                    severity_level: {string} {Optional if severity_name specified} <severity level>
                }
                Note: Either severity_name or severity_level must be present.
        :return: {dict} of in response.data
                health_severity_color: severity color
                health_severity_name: status name
                health_score: health score
                severity_summary: <dict of named tuple which hold all possible severity info>
        '''
        # # Get session key
        try:
            session_key = cherrypy.session.get('sessionKey')
            logger.debug('Request params:%s', kwargs)
            provider = Provider(session_key, logger)
            severity_list = json.loads(kwargs.get('severity_urgency_list'))
            logger.debug("Severity list=%s to process for health score", severity_list)
            output = provider.calculate_score(severity_list)
            threshold_settings = provider.threshold_settings
            # Remove info
            for name in threshold_settings.keys():
                if name == "info":
                    del threshold_settings[name]
            output.data['severity_summary'] = provider.threshold_settings
            logger.debug("Response data:%s", output)
            return self.render_json(output)
        except Exception as e:
            logger.exception(e)
            raise e

    @route('/:action=get_health_range')
    @expose_page(must_login=True, methods=['POST'])
    def get_health_range(self, action, **kwargs):
        '''
        Get health range min and max value of given status
        :param action: get_health_range
        :param kwargs:
            health_status {string} - severity status
        :return: {dict} of in response.data
                health_min
                health_min_included
                health_max
                health_max_included

        '''
        try:
            # # Get session key
            session_key = cherrypy.session.get('sessionKey')
            logger.debug('Request params:%s', kwargs)
            provider = Provider (session_key, logger)
            output = provider.get_min_max_score_for_status(kwargs.get('health_status'))
            logger.debug("Response data:%s", output)
            return self.render_json(output)
        except Exception as e:
            logger.exception(e)
            raise e

    @route('/:action=convert_score_to_status')
    @expose_page(must_login=True, methods=['POST'])
    def getstatus(self, action, **kwargs):
        '''
        For given health score, provide status
        :param action: convert_score_to_status
        :param kwargs:
            health_score {int} - health score
        :return: {dict}
            health_severity_color: severity color
            health_severity_name: status name
        '''
        try:
            # # Get session key
            session_key = cherrypy.session.get('sessionKey')
            logger.debug('Request params:%s', kwargs)
            provider = Provider (session_key, logger)
            output = provider.get_score_to_status(kwargs.get('health_score'))
            logger.debug("Response data:%s", output)
            return self.render_json(output)
        except Exception as e:
            logger.exception(e)
            raise e
