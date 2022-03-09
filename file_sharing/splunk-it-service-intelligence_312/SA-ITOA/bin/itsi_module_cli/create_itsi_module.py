# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import argparse
import sys
import json

from splunk.rest import simpleRequest
from splunk.appserver.mrsparkle.lib import i18n
import itsi_module_cli_common as common

"""
A script will generates a barebone ITSI module with the name DA-ITSI-*
on specified Splunk instance.
"""


class ItsiModuleCreator:
    """
    Class that can generates a barebone ITSI module.
    """

    def __init__(
        self,
        server,
        user,
        password,
        scheme,
        port,
        itsi_module,
        itsi_module_title,
        itsi_module_description,
        itsi_module_author,
        itsi_module_version,
        overwrite_existing_module
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

        @type itsi_module_title: basestring
        @param itsi_module_title: app label of ITSI module

        @type itsi_module_description: basestring
        @param itsi_module_description: app description of ITSI module

        @type itsi_module_author: basestring
        @param itsi_module_author: author of ITSI module

        @type itsi_module_version: basestring
        @param itsi_module_version: version string of ITSI module

        @type overwrite_existing_module: bool
        @param overwrite_existing_module: flag to overwrite existing ITSI module

        @rtype: object
        @return: instance of the class
        """
        self._server = server
        self._user = user
        self._password = password
        self._scheme = scheme
        self._port = port
        self._itsi_module = itsi_module

        self._itsi_module_title = itsi_module_title
        self._itsi_module_description = itsi_module_description
        self._itsi_module_author = itsi_module_author
        self._itsi_module_version = itsi_module_version
        self._overwrite_existing_module = overwrite_existing_module

        self._host_path = '{}://{}:{}'.format(self._scheme, self._server, self._port)

        self._session_key = common.get_session_key(self._user, self._password, self._host_path)

    def create_itsi_module(self):
        """
        Package ITSI module by calling itsi_module_interface generate_package rest endpoint.
        """
        common.print_log_message(_('Start creating ITSI module...'))

        endpoint_uri = self._host_path + '/servicesNS/nobody/SA-ITOA/itsi_module_interface/{}'.format(self._itsi_module)

        params = {
            'title': self._itsi_module_title,
            'description': self._itsi_module_description,
            'author': self._itsi_module_author,
            'version': self._itsi_module_version,
            'overwrite': self._overwrite_existing_module
        }

        try:
            response, content = simpleRequest(
                endpoint_uri,
                sessionKey=self._session_key,
                method='POST',
                postargs=params)
        except Exception as e:
            msg = _('Unable to create ITSI module.\nError details: {}.').format(str(e))
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        if response['status'].strip() != '200':
            msg = _('Unable to create ITSI module.\nError details:\n{}\n{}').format(response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        common.print_log_message(_('ITSI module created on {}: {}.').format(self._host_path, self._get_app_id(content)))
        common.print_log_message(_('Done creating ITSI module.'))

    def _get_app_id(self, content):
        """
        Get appid.

        @type content: json string
        @param content: json string that contains appid.

        @rtype: basestring
        @return: appid of ITSI module
        """
        request_content = json.loads(content)
        if 'appid' not in request_content or not request_content['appid'] or not request_content['appid'].strip():
            common.print_log_message(_('Fail to get appid for ITSI module.'), 'ERROR')
            sys.exit(1)

        return request_content['appid']


def main(input_args):
    """
    Main method for ITSI module creation

    @type input_args: args
    @param input_args: the command-line arguments
    """
    # Specify command line paramaters
    parser = argparse.ArgumentParser(
        description=_('Generates a barebone ITSI module with the name DA-ITSI-* '
                      'on specified Splunk instance. All errors and warnings will be provided as console output.'))
    parser = common.add_common_arguments(parser)
    parser.add_argument(
        '--module-title',
        dest='itsi_module_title',
        required=True,
        help=_('App label of the ITSI module, required.'))
    parser.add_argument(
        '--module-description',
        dest='itsi_module_description',
        required=True,
        help=_('App description of the ITSI module, required.'))
    parser.add_argument(
        '--module-author',
        dest='itsi_module_author',
        required=True,
        help=_('Author of the ITSI module, required.'))
    parser.add_argument(
        '--module-version',
        dest='itsi_module_version',
        required=True,
        help=_('Version string of the ITSI module, number triple like #.#.#, required.'))
    parser.add_argument(
        '--overwrite-existing-module',
        action='store_true',
        default=False,
        help=_('Overwrite ITSI module, if exists. Any existing content will be lost. Defaults to false.'))

    args = parser.parse_args(input_args)

    # # create ItsiModuleCreator to do actual work
    itsi_module_creator = ItsiModuleCreator(
        args.server,
        args.user,
        args.password,
        args.scheme,
        args.port,
        args.itsi_module,
        args.itsi_module_title,
        args.itsi_module_description,
        args.itsi_module_author,
        args.itsi_module_version,
        args.overwrite_existing_module)

    # create ITSI module
    itsi_module_creator.create_itsi_module()

if __name__ == '__main__':
    main(sys.argv[1:])
