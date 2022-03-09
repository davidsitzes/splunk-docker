# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import splunk.rest
import sys

from splunk.appserver.mrsparkle.lib import jsonresponse

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

class BaseSplunkdRest(splunk.rest.BaseRestHandler):
    """
    Base class for all of ITSI's splunkd endpoints
    """
    def render_json(self, response_data):
        '''
        given data, convert it to a JSON which is consumable by a web client
        '''
        if isinstance(response_data, jsonresponse.JsonResponse):
            response = response_data.toJson().replace("</", "<\\/")
        else:
            response = json.dumps(response_data).replace("</", "<\\/")

        # Pad with 256 bytes of whitespace for IE security issue. See SPL-34355
        return ' ' * 256  + '\n' + response

