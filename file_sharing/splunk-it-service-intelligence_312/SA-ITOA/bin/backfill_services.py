# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.backfill.itsi_backfill_requests import BackfillRequestCollection, BackfillRequestModel

from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ITOAError, handle_json_in_splunkd

from base_splunkd_rest import BaseSplunkdRest


logger = setup_logging("itsi_backfill_services.log", "itsi.controllers.backfill_services")
logger.debug("Initialized backfill services log...")

def handle_path_terms(f):
    def wrapper(self, *args, **kwargs):
        """
        path must be either
        /services/backfill_services/<owner>
        or
        /services/backfill_services/<owner>/<key id>
        """
        len_ = len(self.pathParts)
        if len_ > 4 :
            raise ITOAError(status="404", message=_("Bad argument count."))
        if len_ == 4 :
            self.args.update({ 'id_' : self.pathParts[3] })

        return f(self, *args, **kwargs)
    return wrapper

class backfill_services(BaseSplunkdRest):
    """
    Provides splunkd endpoints for backfill operations
    """

    def get_interface_adapter(self, session_key, _cached_interface={}):
        """
        Lazy init method for the interface adapter
        The interface class instance is cached in the mutable _cached_interface default
        arg array and is persisted between calls to this function.
        """
        if len(_cached_interface) == 0 or session_key not in _cached_interface:
            logger.debug("Caching interface adapter for session key %s", session_key)
            _cached_interface.clear()
            _cached_interface[session_key] = BackfillRequestModel.initialize_interface(session_key)

        return _cached_interface[session_key]


    @handle_json_in_splunkd
    @handle_path_terms
    def handle_GET(self):
        interface = self.get_interface_adapter(self.sessionKey)

        if 'id_' not in self.args :
            filter_data = None

            if 'filter' in self.args:
                filter_data = json.loads(self.args['filter'])

            collection = BackfillRequestCollection(interface=interface)
            collection.fetch(filters=filter_data)
            self.response.write(self.render_json([x.data for x in collection]))
        else :
            id_ = self.args['id_']
            try:
                request_model = BackfillRequestModel.fetch_from_key(id_, interface=interface)
                self.response.write(self.render_json(request_model.data))
            except Exception as e:
                logger.exception(e)
                logger.error("Exception thrown when trying to fetch from key %s", id_)
                raise ITOAError(status="404", message=_("Failed to fetch resource with id {}.").format(id_))

    def _handlePostPut(self, id_):
        interface = self.get_interface_adapter(self.sessionKey)
        post_data = self.args.get('data') or self.args  # postargs get wrapped in 'data' attr
        if id_ :
            request_model = BackfillRequestModel(post_data, key=id_, interface=interface)
        else :
            request_model = BackfillRequestModel(post_data, interface=interface)

        self.response.write(self.render_json(request_model.save()))


    @handle_json_in_splunkd
    @handle_path_terms
    def handle_PUT(self):
        if 'id_' not in self.args :
            raise ITOAError(status  = "404",
                            message = _("PUT request requires the ID_ parameter, "
                                      "consider POST if you don't wish to pass one"))

        self._handlePostPut(self.args['id_'])


    @handle_json_in_splunkd
    @handle_path_terms
    def handle_POST(self):
        """
        parsed args must be the attributes dict for the backfill request
        The following attributes are expected (see itsi_backfill_requests.py for details):
            'status' (set to 'new')
            'search' (obtained from the backfill search endpoint)
            'kpi_id'
            'earliest' (epoch seconds)
            'latest' (epoch seconds)
        """
        self._handlePostPut(self.args['id_'] if 'id_' in self.args else None)


    @handle_json_in_splunkd
    @handle_path_terms
    def handle_DELETE(self):
        interface = self.get_interface_adapter(self.sessionKey)

        if 'id_' not in self.args :
            logger.warning("Batch-deleting all backfill requests!")

            collection = BackfillRequestCollection(interface=self.get_interface_adapter(self.sessionKey))
            collection.fetch()
            self.response.write(collection.delete())

        else :
            try:
                request_model = BackfillRequestModel.fetch_from_key(self.args['id_'], interface=interface)
                self.response.write(request_model.delete())

            except Exception as e:
                logger.exception(e)
                logger.error("Exception thrown when trying to fetch from key %s", self.args['id_'])
                raise ITOAError(status="404", message=_("Failed to fetch resource with id {}.").format(self.args['id_']))
