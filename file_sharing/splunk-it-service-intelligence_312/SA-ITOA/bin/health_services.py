# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json
import cherrypy

from urlparse import parse_qs

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects

from itsi.health_services.health_services_provider import Provider

from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ITOAError, handle_json_in_splunkd

from base_splunkd_rest import BaseSplunkdRest

logger = setup_logging("itsi_health_service_provider.log", "itsi.controllers.health_services")
logger.debug("Setup health provider controller ...")

def path_validate(f) :
    def wrapper (self, *args, **kwargs) :
        if len (self.pathParts) != 3 :
            raise cherrypy.HTTPError (
                status  = 404,
                message =
                '{} arguments provided'.format (
                    'Insufficient' if len (self.pathParts) < 4 else 'Too many'))

        return f (self, *args, **kwargs)
    return wrapper

class health_services(BaseSplunkdRest) :

    @handle_json_in_splunkd
    @path_validate
    def handle_POST (self) :
        try :
            provider = Provider (self.sessionKey, logger)

            if self.pathParts[2] == 'get_health_score' :
                severity_list = json.loads (self.args.get ('severity_urgency_list'))
                output = provider.calculate_score (severity_list)
                threshold_settings = provider.threshold_settings
                # Remove info
                for name in threshold_settings.keys():
                    if name == "info":
                        del threshold_settings[name]
                    output.data['severity_summary'] = provider.threshold_settings
                self.response.write (self.render_json (output))
            elif self.pathParts[2] == 'get_health_range' :
                output = provider.get_min_max_score_for_status (self.args.get ('health_status'))
                self.response.write (self.render_json (output))
            elif self.pathParts[2] == 'convert_score_to_status' :
                output = provider.get_score_to_status (self.args.get ('health_score'))
                self.response.write (self.render_json(output))
            else :
                pass
        except Exception as e:
            logger.exception(e)
            raise

    @path_validate
    def handle_GET (self) :
        '''
        Function only exists to test pointing a browser at the endpoint
        '''
        self.response.write ('')
