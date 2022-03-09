# {copyright}
'''
This module simplifies the interaction with datamodel objects when working
with splunkd
'''
import splunk.rest as rest
from splunk import ResourceNotFound
import json
from .itoa_exceptions import ItoaDatamodelContextError

from .setup_logging import setup_logging

LOGGER = setup_logging("itsi.log", "itoa.datamodel")

# pylint: disable = interface-not-implemented
class DatamodelInterface(object):
    '''
    Provides a simple interface for interacting with the datamodel endpoints
    '''

    def __init__(self):
        '''
        Pythons init, right now just sends a debug message to the logger
        @param self: Self pointer
        '''
        LOGGER.debug("Initializing datamodel_interface")

    @classmethod
    def get_datamodel(cls, session_key, host, app, model_name):
        '''
        Retrieves the associated datamodel,from which you can grab all of the objects or whatever you want
        parsed out from the json provided by the datamodel

        @param self:  The pointer to the object
        @type self: datamodel_interface

        @param session_key: The splunkd session key
        @type session_key: string

        @param host: The target host to retrieve this info from - most likely localhost
        @type host: string

        @param app: The app context to retrieve this data from
        @type app: string

        @param model_name: The name of the datamodel
        @type model_name: string
        '''
        if model_name and model_name != '':
            model_name = '/' + model_name
        else:
            model_name = '' #Force assignment
        uri = host + '/servicesNS/nobody/' + app + '/datamodel/model' + model_name
        #If it starts with a slash, let rest.simpleRequest handle everything beyond the path
        if not uri.startswith("https://") and not uri.startswith("/"):
            uri = 'https://' + uri
        get_args = {"output_mode":"json", "count": 0}

        parsed_content = None
        try:
            response, content = rest.simpleRequest(uri,
                                                   method="GET",
                                                   raiseAllErrors=False,
                                                   sessionKey=session_key,
                                                   getargs=get_args)
            if response.status != 200 and response.status != 201:
                LOGGER.error("Error when requesting datamodel response_code=" + str(response.status))
                return {}
            parsed_content = json.loads(content)
        except ResourceNotFound as e:
            LOGGER.exception(e)
            raise ItoaDatamodelContextError(e.message, LOGGER)
        datamodels = {}
        #Take the parsed response and only get the json strings out of it
        for datamodel in parsed_content['entry']:
            #For some reason the definition is loaded into the description field ... whatever
            content = datamodel.get('content', None)
            if content == None:
                LOGGER.error("Error getting datamodel content")
                continue
            datamodel_definition_string = content['description']
            datamodel_definition = json.loads(datamodel_definition_string)
            model_name = datamodel_definition['modelName']
            datamodels[model_name] = datamodel_definition
        return datamodels

    @classmethod
    def get_all_datamodels(cls, session_key, host, app):
        '''
        Gets all known datamodels present within the app context

        @param session_key: The splunkd session key
        @type session_key: string

        @param host:  The host to get this info from
        @type host: string

        @param app: The app context to retrieve the data in
        @type app: string
        '''
        #Gets all of the datamodels, returned as an array of dicts (parsed from json)
        return cls.get_datamodel(session_key, host, app, '')

