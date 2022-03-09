# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import argparse
import sys
import json
import urllib

import splunk.rest as rest
from splunk import ResourceNotFound
from splunk.appserver.mrsparkle.lib import i18n
import itsi_module_cli_common as common

"""
A script that generate ITSI module contents for the following confs:
    - itsi_service_template.conf
    - inputs.conf
    - itsi_kpi_base_search.conf
    - itsi_kpi_template.conf
"""


class ItsiModuleContentGenerator:
    """
    Class that can generates contents for a module from existing Splunk/ITSI object
    """

    def __init__(
        self,
        server,
        user,
        password,
        scheme,
        port,
        itsi_module,
        service_title_list,
        entity_source_template_id_list,
        datamodel_name_list,
        overwrite
    ):
        """
        Initialize objects

        @type server: basestring
        @param server: splunk server

        @type user: basestring
        @param user: splunk user

        @type password: basestring
        @param password: splunk password

        @type scheme: basestring
        @param scheme: scheme for splunkd management port

        @type port: basestring
        @param port: splunkd management port

        @type itsi_module: basestring
        @param itsi_module: name of ITSI module

        @type service_title_list: list
        @param service_title_list: list of service titles to be templatized

        @type entity_source_template_id_list: list
        @param entity_source_template_id_list: list of entity source templates to be templatized

        @type datamodel_name_list: list
        @param datamodel_name_list: list of datamodel names to import into module

        @rtype: object
        @return: instance of the class
        """
        self._server = server
        self._user = user
        self._password = password
        self._scheme = scheme
        self._port = port

        self._itsi_module = itsi_module

        self._host_path = '{}://{}:{}'.format(self._scheme, self._server, self._port)

        self._session_key = common.get_session_key(self._user, self._password, self._host_path)

        self._entity_source_template_id_list = entity_source_template_id_list if entity_source_template_id_list else []
        self._entity_source_template_ids = ['itsi_csv_import://' +
                                            entity_source_template_id for entity_source_template_id
                                            in entity_source_template_id_list]
        self._service_title_list = service_title_list
        self._datamodel_name_list = datamodel_name_list if datamodel_name_list else []
        self._overwrite = overwrite

        self._confs_to_be_cleaned_list = ['inputs',
                                          'itsi_kpi_base_search',
                                          'itsi_kpi_template',
                                          'itsi_service_template']

    def validate_inputs(self):
        """
        Validate following inputs: service_id, entity_source_template_id and datamodel_name
        """
        # Validate given service titles and get corresponding service ids
        self._service_ids = self._get_service_id_by_title_and_validate()

        # Get existing entity source template ids from itsi app
        existing_entity_source_template_ids = self._get_conf_stanzas('inputs')

        # Validate entity source template ids obtained from command line against existing ones
        self._validate_object_against_existing_splunk_instance(existing_entity_source_template_ids,
                                                               self._entity_source_template_ids,
                                                               'entity-search-mod-input')

        # Validate datamodel name against existing datamodel names
        existing_datamodel_name_list = self._get_existing_datamodel_name_list()
        self._validate_object_against_existing_splunk_instance(existing_datamodel_name_list,
                                                               self._datamodel_name_list,
                                                               'datamodel-name')

    def generate_contents(self):
        """
        Generate itsi module contents: inputs.conf, itsi_kpi_base_search.conf, itsi_kpi_template.conf
        and itsi_service_template.conf

        Optional: datamodels.conf and da/models/<datamodel>.json files will be generated if datamodel-name
        is passed from command line
        """
        if not self._service_ids:
            self._service_ids = self._get_service_id_by_title_and_validate()

        # Generate itsi_service_template.conf, itsi_kpi_base_search.conf, itsi_kpi_template.conf stanzas
        # for each service id
        for serviceId in self._service_ids:
            self._generate_itsi_module_contents('service_template',
                                                {'itsi_object_id': serviceId,
                                                 'include_kpi_base_search': 1,
                                                 'include_kpi_group': 1}
                                                )

        # Generate inputs.conf stanza for each entity_source_template_id given
        for entity_source_template_id in self._entity_source_template_id_list:
            self._generate_itsi_module_contents('entity_source_template', {'itsi_object_id': entity_source_template_id})

        # Generate datamodel json file for each datamodel name given.
        if self._datamodel_name_list:
            # The implementation will first get datamodel object by the given datamodel-name
            # Then delete the datamodel from its original app and re-create the same one under itsi_module
            for datamodel_name in self._datamodel_name_list:

                # Get datamodel JSON blob from existing instance
                datamodel_entry = self._get_datamodel(datamodel_name)
                app = datamodel_entry.get('acl').get('app')
                # Don't do anything if datamodel is already in itsi_module folder
                if app == self._itsi_module:
                    break

                datamodel_content = datamodel_entry.get('content')

                # Get remove uri from links. If it's not available, then construct the uri with app name
                delete_uri = datamodel_entry.get('links').get('remove')
                if not delete_uri:
                    delete_uri = '/servicesNS/nobody/%s/datamodel/model/%s' % (app, datamodel_name)

                acceleration = datamodel_content.get('acceleration')
                description = datamodel_content.get('description')
                postargs = {'name': datamodel_name,
                            'description': description,
                            'acceleration': acceleration
                            }

                # Delete existing datamodel from previous namespace
                self._delete_datamodel(self._host_path + delete_uri, datamodel_name)
                # Re-create a new datamodel inside itsi_module
                self._create_datamodel(postargs)

    def overwrite_contents(self):
        """
        Overwrite what's been generated inside itsi module.
        """
        if self._overwrite is True:
            common.print_log_message(_('overwrite-existing-contents flag sets to True. '
                                     'Start cleaning ITSI module contents'))
            for conf in self._confs_to_be_cleaned_list:
                self._clean_conf_file(conf)
            common.print_log_message(_('Cleaning ITSI module contents complete'))

    def _clean_conf_file(self, conf_name):
        """
        Delete contents for specified conf file
        """
        stanza_list = self._get_conf_stanzas(conf_name, self._itsi_module)
        if stanza_list:
            for stanza_name in stanza_list:
                self._delete_conf_stanza(conf_name, stanza_name)

    def _get_service_id_by_title_and_validate(self):
        """
        Get service id by the given service title. It also validates if all given service titles exist

        Notice: nothing will be generated and this CLI will exit out if any of given service titles does not exist

        @rtype: list
        @return: a list of service ids
        """
        getargs = {'output_mode': 'json',
                   'fields': '_key,title'}
        try:
            response, content = rest.simpleRequest(
                self._host_path + '/servicesNS/nobody/SA-ITOA/itoa_interface/service/',
                method='GET',
                sessionKey=self._session_key,
                getargs=getargs)

            if response.status != 200:
                msg = _('Failed to get service id by title.\nError details:\n{}\n{}').format(response, content)
                common.print_log_message(msg, 'ERROR')
                sys.exit(1)

            service_object_list = json.loads(content)
            existing_service_dict = \
                {
                    service_object.get('title'): service_object.get('_key') for service_object in service_object_list
                }
            service_ids = []
            non_existing_service_titles = []
            for service_title in self._service_title_list:
                if service_title not in existing_service_dict:
                    non_existing_service_titles.append(service_title)
                else:
                    service_ids.append(existing_service_dict.get(service_title))
            if non_existing_service_titles:
                msg = \
                    _('Failed: Given service titles: %s do not exist in current system. Nothing has been generated.') % \
                    non_existing_service_titles
                common.print_log_message(msg, 'ERROR')
                sys.exit(1)
            return service_ids
        except Exception as e:
            msg = _('Failed to get service id by title.\nError details: {}.').format(e)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _get_conf_stanzas(self, conf_name, app='itsi', count=-1):
        """
        Get stanza contents of a specific conf file under given namespace

        @type conf_name: string
        @param conf_name: conf file name

        @type app: string
        @param app: namespace to be filtered by

        @type count: int
        @param count: number of results that will be returned

        @rtype: tuple
        @return: tuple of response and content or raise an exception
        """
        getargs = {
            'output_mode': 'json',
            'count': count,
            'search': 'eai:acl.app=%s' % app
        }
        conf_uri = self._host_path + '/servicesNS/nobody/' + app + '/configs/conf-' + conf_name
        try:
            response, content = rest.simpleRequest(
                conf_uri,
                method="GET",
                getargs=getargs,
                sessionKey=self._session_key,
                raiseAllErrors=True
            )
            conf_object = json.loads(content).get('entry')
            return [stanza.get('name') for stanza in conf_object]
        except ResourceNotFound:
            msg = _('Failed to get stanzas from conf file: %s.conf under app: %s.\n') % (conf_name, app) + \
                  _('Given app or ITSI module: %s cannot be found.') % app
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _generate_itsi_module_contents(self, object, postargs):
        """
        Call itsi_module_interface endpoints and generate conf files

        @type itsi_module: string
        @param: itsi_module: name of the itsi module

        @type object: string
        @param: itsi module object

        @type postargs: dict
        @param: dictionary of arguments for POST
        """
        generate_url_path = '/servicesNS/nobody/SA-ITOA/itsi_module_interface/{}/{}'
        endpoint_uri = self._host_path + generate_url_path.format(self._itsi_module, object)

        try:
            response, content = rest.simpleRequest(
                endpoint_uri,
                method='POST',
                sessionKey=self._session_key,
                postargs=postargs)
            if response.status != 200:
                msg = _('Failed to export .conf files.\nError details:\n{}\n{}').format(response, content)
                common.print_log_message(msg, 'ERROR')
                sys.exit(1)
        except Exception as e:
            msg = _('Failed to export .conf files.\nError details: {}.').format(e)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _validate_object_against_existing_splunk_instance(self, existing_objects_attributes,
                                                          objects_attributes_to_validate, cli_argument):
        """
        Validate entity source template ids by comparing to the list of existing entity source template ids found
        under itsi app

        @type existing_entity_source_template_ids: list
        @param existing_entity_source_template_ids: list of existing entity source template id found under itsi app

        @type passed_in_entity_source_template_ids: list
        @param passed_in_entity_source_template_ids: list of entity source template id from command line arguments
        """
        non_existing_object_attributes = list(set(objects_attributes_to_validate) - set(existing_objects_attributes))
        if non_existing_object_attributes:
            common.print_log_message(_('Validation failed. Nothing has been generated.'))
            if cli_argument == 'entity-search-mod-input':
                msg = \
                    _('Given %s id: %s does not exist in ITSI app context. ' \
                    'Please create a csv modular input in ITSI from UI') % (cli_argument, non_existing_object_attributes)
                common.print_log_message(msg)
                sys.exit(1)
            else:
                msg = _('Given %s id: %s does not exist in Splunk.') % (cli_argument, non_existing_object_attributes)
                common.print_log_message(msg)
                sys.exit(1)

    def _get_existing_datamodel_name_list(self):
        """
        Get a list of existing datamodel modelNames

        @type session_key: string
        @param session_key: splunkd session_key

        @type hostPath: string
        @param hostPath: full path of splunkd management path

        @rtype: list
        @return: a list of existing datamodel names
        """
        getargs = {'output_mode': 'json'}
        uri = self._host_path + '/services/datamodel/model'
        response, content = rest.simpleRequest(
            uri,
            method="GET",
            getargs=getargs,
            sessionKey=self._session_key
        )
        if response.status != 200:
            msg = _('Failed to get existing datamodel list.\nError details:\n{}\n{}').format(response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)
        try:
            entries = json.loads(content).get('entry')
            description_list = [entry.get('content').get('description') for entry in entries]
            datamodel_name_list = [json.loads(description).get('modelName') for description in description_list]
            return datamodel_name_list
        except Exception:
            common.print_log_message(_('Failed to get existing datamodel list.', 'ERROR'))
            sys.exit(1)

    def _delete_datamodel(self, delete_uri, datamodel_name):
        """
        Call splunk endpoint to delete a datamodel

        @type session_key: string
        @param session_key: splunkd session_key

        @type delete_uri: string
        @param delete_uri: rest endpoint for deleting datamodel

        @type datamodel_name: string
        @param: modelName for the datamodel to be removed
        """
        response, content = rest.simpleRequest(
            delete_uri,
            method="DELETE",
            sessionKey=self._session_key
        )
        if response.status != 200:
            msg = _('Failed to delete datamodel: {}.\nError details:\n{}\n{}').format(datamodel_name, response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _create_datamodel(self, postargs):
        """
        Call splunk endpoint to create a datamodel

        @type session_key: string
        @param session_key: splunkd session key

        @type hostPath: string
        @param hostPath: splunkd management host path

        @type itsi_module: string
        @param: itsi_module: name of the itsi module

        @type postargs: dict
        @param: dictionary of arguments for POST
        """
        uri = self._host_path + '/servicesNS/nobody/%s/datamodel/model' % self._itsi_module
        response, content = rest.simpleRequest(
            uri,
            method='POST',
            sessionKey=self._session_key,
            postargs=postargs
        )
        if response.status != 201:
            msg = _('Failed to create datamodel: {}.\nError details:\n{}\n{}').format(postargs.get('name'), response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _get_datamodel(self, datamodel_name):
        """
        Call splunk endpoint to get a datamodel

        Note: This will only get datamodels that have permission set to Global

        @type session_key: string
        @param session_key: splunkd session key

        @type hostPath: string
        @param hostPath: splunkd management host path

        @type postargs: dict
        @param: dictionary of arguments for POST

        @rtype: dict
        @return: JSON object of the datamodel
        """
        uri = self._host_path + '/services/datamodel/model/%s' % datamodel_name
        response, content = rest.simpleRequest(
            uri,
            method="GET",
            sessionKey=self._session_key,
            getargs={'output_mode': 'json'}
        )
        if response.status != 200:
            msg = _('Failed to get datamodel {}.\nError details:\n{}\n{}').format(datamodel_name, response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        try:
            return json.loads(content).get('entry')[0]
        except Exception as e:
            msg = _('Failed to get datamodel {}.\nError details:\n{}').format(datamodel_name, e.message)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

    def _delete_conf_stanza(self, conf_name, conf_stanza_name):
        """
        Delete conf stanza by calling splunk conf endpoints

        @type conf_name: string
        @param conf_name: conf file name

        @type conf_stanza_name: string
        @param conf_stanza: stanza name to update

        """
        base_url_path = '/servicesNS/nobody/{}/configs/conf-{}/{}'
        conf_uri = self._host_path + \
            base_url_path.format(self._itsi_module, conf_name, urllib.quote_plus(conf_stanza_name))
        try:
            response, content = rest.simpleRequest(
                conf_uri,
                method="DELETE",
                sessionKey=self._session_key,
                raiseAllErrors=True
            )
            if response.status != 200:
                msg = response.status + '\n' + \
                      _('Failed to delete stanzas from conf file: %s.conf under app: %s') % \
                      (conf_name, self._itsi_module)
                common.print_log_message(msg, 'ERROR')
                sys.exit(1)
        except ResourceNotFound:
            msg = _('Failed to delete stanzas from conf file: %s.conf under app: %s\n') % (conf_name, self._itsi_module) + \
                  _('conf file: %s.conf or stanza name: %s does not exist') % (conf_name, conf_stanza_name)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)


def main(input_args):
    """
    Main method for ITSI module content generation

    @type input_args: args
    @param input_args: the command-line arguments
    """
    parser = argparse.ArgumentParser(description=_('Script to export all necessary .conf files for ITSI module'))

    # Add required arguments.
    # service-title,entity-search-mod-input and datamodel-name will each be a list type since they can be repeated.
    parser = common.add_common_arguments(parser)
    parser.add_argument(
        '--service-title',
        action='append',
        dest='service_title_list',
        required=True,
        help='Title of ITSI service, required, can be repeated.')
    parser.add_argument(
        '--entity-search-mod-input',
        action='append',
        dest='entity_source_template_id_list',
        help='Mod input stanza name, optional, can be repeated.',
        default=[])
    parser.add_argument(
        '--datamodel-name',
        action='append',
        dest='datamodel_name_list',
        help='Name of the datamodel, optional, can be repeated.',
        default=[])
    parser.add_argument(
        '--overwrite-existing-contents',
        action='store_true',
        dest='overwrite',
        default=False,
        help='Overwrite ITSI module contents. All existing contents will be lost! Defaults to false.')

    # Parse all given arguments
    args = parser.parse_args(input_args)

    itsi_module = args.itsi_module if args.itsi_module.startswith('DA-ITSI-') else 'DA-ITSI-%s' % args.itsi_module

    itsi_module_content_generator = ItsiModuleContentGenerator(
        args.server,
        args.user,
        args.password,
        args.scheme,
        args.port,
        itsi_module,
        args.service_title_list,
        args.entity_source_template_id_list,
        args.datamodel_name_list,
        args.overwrite)

    common.print_log_message(_('Start validating service titles and entity source template IDs'))
    itsi_module_content_generator.validate_inputs()
    common.print_log_message(_('Validation complete'))

    itsi_module_content_generator.overwrite_contents()

    common.print_log_message(_('Start generating contents'))
    itsi_module_content_generator.generate_contents()
    common.print_log_message(_('Generating contents complete'))

if __name__ == '__main__':
    main(sys.argv[1:])
