# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import itsi_module_common as utils
from ITOA.setup_logging import setup_logging


class ItsiModuleDataModel(object):

    _base_url = '/servicesNS/nobody/%s/datamodel/model'
    _base_args = '?output_mode=json&count=-1&concise=true'

    def __init__(self, session_key, app='SA-ITOA', owner='nobody', logger=None):
        """
        Initializes the ItsiModuleEntitySourceTemplate object

        @type session_key: string
        @param session_key: the session key

        @type app: string
        @param app: the app context, defaults to SA-ITOA

        @type owner: string
        @param owner: the owner context, defaults to nobody

        @type logger: string
        @param logger: the logger
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.object_type = 'data_model'

        if logger is None:
            self.logger = setup_logging('itsi_module_interface.log',
                                        'itsi.controllers.itsi_module_interface')
        else:
            self.logger = logger

    def get_count(self, itsi_module, **kwargs):
        """
        Returns the count of data models in a given module

        If itsi_module is specified as "-", returns counts of data models for all modules

        @type itsi_module: string
        @param itsi_module: ITSI module that was requested
        """
        data_model_endpoint = utils.get_object_endpoint(self._base_url, self._base_args, itsi_module, None)
        self.logger.debug('Attempting get_count from entity source template endpoint: %s', data_model_endpoint)

        response = utils.construct_count_response(data_model_endpoint, itsi_module, self.object_type, self.session_key)
        self.logger.debug('Get_count response for entity source template %s in module %s: %s', data_model_endpoint,
                          itsi_module, json.dumps(response))
        return response

    def validate(self, itsi_module, object_id):
        """
        This is just a stub method that is written in order to make sure that the validate
        endpoint iterates through validation for all of the different object types.  As of now,
        there is no validation that is done for datamodels, so this will just return an empty
        list for errors and for infos

        @type itsi_module: string
        @param itsi_module: Module which is being used

        @type object_id: string
        @param object_id: Object id
        """
        return utils.construct_validation_result(errors=[], infos=[])
