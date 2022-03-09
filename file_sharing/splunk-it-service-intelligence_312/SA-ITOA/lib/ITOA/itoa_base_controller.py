# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import cherrypy
from splunk.appserver.mrsparkle.lib import jsonresponse

class ITOABaseController(object):
    """
    Provide custom behaviors to all our web services
    """

    @classmethod
    def render_json(cls, response_data, set_mime='application/json'):
        """
        Used to convert objects into json responses. Also will change json mime type around to enable gzip compression

        :param response_data: the raw response itself
        :param set_mime: override the mime type of a response
        :return: returns the string response
        """
        # Always enable compression by setting to application/json
        if set_mime == 'text/json':
            set_mime = 'application/json'

        cherrypy.response.headers['Content-Type'] = set_mime

        # Escape slashes if they exist in the data
        if isinstance(response_data, jsonresponse.JsonResponse):
            response = response_data.toJson().replace("</", "<\\/")
        else:
            response = json.dumps(response_data).replace("</", "<\\/")

        # Pad with 256 bytes of whitespace for IE security issue. See SPL-34355
        return ' ' * 256 + '\n' + response

