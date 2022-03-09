# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import os
import sys
import json
from urllib2 import urlopen
from urllib2 import URLError
from argparse import ArgumentParser
from shutil import copyfileobj

from splunk.rest import simpleRequest
from splunk.appserver.mrsparkle.lib import i18n
import itsi_module_cli_common as common
from itsi_module_cli_common import print_colors

"""
A script will validate and generate a compressed package of ITSI
module objects on specified Splunk instance, then download the
package to a local path.
"""


class ItsiModulePackager:
    """
    Class that can validate, package ITSI module, and also download the package.
    """

    def __init__(self, server, user, password, itsi_module, scheme, port, output_path, overwrite_existing_package):
        """
        Initialize objects

        @type server: basestring
        @param server: splunk server

        @type user: basestring
        @param user: splunk user

        @type password: basestring
        @param password: splunk password

        @type itsi_module: basestring
        @param itsi_module: name of ITSI module

        @type scheme: basestring
        @param scheme: scheme for splunkd management port

        @type port: basestring
        @param port: splunkd management port

        @type output_path: basestring
        @param output_path: local file path to download package

        @type overwrite_existing_package: bool
        @param overwrite_existing_package: flag to overwrite existing ITSI package during download

        @rtype: object
        @return: instance of the class
        """
        self._server = server
        self._user = user
        self._password = password
        self._itsi_module = itsi_module

        self._scheme = scheme
        self._port = port
        self._overwrite_existing_package = overwrite_existing_package

        if output_path is None or not output_path.strip():
            self._output_path = os.getcwd()
        else:
            self._output_path = os.path.normpath(output_path)

        self._host_path = '{}://{}:{}'.format(self._scheme, self._server, self._port)

        self._session_key = common.get_session_key(self._user, self._password, self._host_path)

    def validate_itsi_module(self):
        """
        Validate ITSI module
        """
        common.print_log_message(_('Start validating ITSI module...'))

        validation_url_path = '/servicesNS/nobody/SA-ITOA/itsi_module_interface/{}/validate'
        endpoint_uri = self._host_path + validation_url_path.format(self._itsi_module)

        type_to_display_string = {
            'module': _('General module'),
            'kpi_base_search': _('KPI base search'),
            'kpi_group': _('KPI group'),
            'entity_source_template': _('Entity source template'),
            'service_template': _('Service template')
        }
        try:
            response, content = simpleRequest(
                endpoint_uri,
                sessionKey=self._session_key,
                method='GET')
        except Exception as e:
            msg = _('Unable to validate ITSI module contents.\nError details: {}.').format(str(e))
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        if response['status'].strip() != '200':
            msg = _('Unable to validate ITSI module.\nError details:\n{}\n{}').format(response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        validation_results = json.loads(content)

        error_count = sum([len(validation_results[object_type]['errors']) for object_type in validation_results
                          if 'errors' in validation_results[object_type]])

        append_log_list = []

        if error_count == 0:
            common.print_with_color(print_colors.OK, '===============', append_log_list)
            common.print_with_color(print_colors.OK, 'No errors found', append_log_list)
            common.print_with_color(print_colors.OK, '===============', append_log_list)
        else:
            common.print_with_color(print_colors.FAIL, '==================================', append_log_list)
            common.print_with_color(print_colors.FAIL,
                                    'Validation failed with %s error(s)' % error_count,
                                    append_log_list)
            common.print_with_color(print_colors.FAIL, '==================================', append_log_list)

            for object_type in validation_results:
                if 'errors' not in validation_results[object_type]:
                    common.print_with_color(print_colors.INFO,
                                            'No %s errors.' % type_to_display_string[object_type],
                                            append_log_list)
                else:
                    common.print_with_color(print_colors.FAIL,
                                            '%s errors:' % type_to_display_string[object_type],
                                            append_log_list)
                    errors_by_key = self._group_errors_by_object_key(validation_results[object_type]['errors'])
                    for key in errors_by_key:
                        common.print_with_color(print_colors.FAIL,
                                                '  %s:' % key,
                                                append_log_list)
                        for error in errors_by_key[key]:
                            common.print_with_color(print_colors.FAIL,
                                                    '    %s' % error,
                                                    append_log_list)

        info_count = sum([len(validation_results[object_type]['infos']) for object_type in validation_results
                         if 'infos' in validation_results[object_type]])

        if info_count:
            common.print_with_color(print_colors.WARNING, '==================================', append_log_list)
            common.print_with_color(print_colors.WARNING, 'Validation with %s warning(s)' % info_count, append_log_list)
            common.print_with_color(print_colors.WARNING, '==================================', append_log_list)

            for object_type in validation_results:
                if 'infos' in validation_results[object_type]:
                    common.print_with_color(print_colors.WARNING,
                                            '%s warnings:' % type_to_display_string[object_type],
                                            append_log_list)

                    infos_by_key = self._group_errors_by_object_key(validation_results[object_type]['infos'])
                    for key in infos_by_key:
                        common.print_with_color(print_colors.WARNING, '  %s:' % key, append_log_list)

                        for info in infos_by_key[key]:
                            common.print_with_color(print_colors.WARNING, '    %s' % info, append_log_list)

        # Log validation errors and warnings
        log_message = '\n'.join(append_log_list)
        common.log_message('\n' + log_message)

        common.print_log_message(_('Done validating ITSI module.'))

        return error_count, info_count

    def package_itsi_module(self):
        """
        Package ITSI module by calling itsi_module_interface generate_package rest endpoint.
        """
        common.print_log_message(_('Start packaging ITSI module...'))

        package_url_path = '/servicesNS/nobody/SA-ITOA/itsi_module_interface/{}/generate_package'
        endpoint_uri = self._host_path + package_url_path.format(self._itsi_module)

        try:
            response, content = simpleRequest(
                endpoint_uri,
                sessionKey=self._session_key,
                method='GET')
        except Exception as e:
            msg = _('Unable to generate ITSI module.\nError details: {}.').format(str(e))
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        if response['status'].strip() != '200':
            msg = _('Unable to generate ITSI module.\nError details:\n{}\n{}').format(response, content)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        self._package_download_url = self._get_package_download_url(content)

        common.print_log_message(_('Package download url: {}').format(self._package_download_url))
        common.print_log_message(_('Done packaging ITSI module.'))

    def download_itsi_module_package(self):
        """
        Download ITSI module package
        """
        common.print_log_message(_('Start downloading ITSI module package...'))

        if not self._package_download_url:
            common.print_log_message(_('No download url.'), 'ERROR')
            sys.exit(1)

        # make sure output path exists
        try:
            if not os.path.exists(self._output_path):
                os.makedirs(self._output_path)
        except os.error as err:
            msg = _('Fail to create output path: {}.\nError details: {}.').format(self._output_path, err)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        # check if output file exists
        output_file = os.path.join(self._output_path, self._package_download_url.split('/')[-1])
        if os.path.exists(output_file):
            common.print_log_message(_('Output file {} already exists.\n').format(output_file))
            if not self._overwrite_existing_package:
                msg = _('If you want to overwrite it, please run me again and pass \'--overwrite-existing-package\'.' \
                      '\n Operation cancelled.')
                common.print_log_message(msg)
                return
            else:
                common.print_log_message(_('You have choose to overwrite it.'))

        # request package from url
        try:
            opened_url = urlopen(self._package_download_url)
        except URLError as e:
            msg = _('Fail to open url: {}\n').format(self._package_download_url) + _('Error details:{}').format(e)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        # write package to output file
        try:
            with open(output_file, 'wb') as fp:
                copyfileobj(opened_url, fp)
        except Exception as e:
            msg = _('Fail to download package from \n {} \n to {}\n').format(self._package_download_url, output_file) + \
                  _('Error details:{}').format(e)
            common.print_log_message(msg, 'ERROR')
            sys.exit(1)

        common.print_log_message(
            _('Successfully download package from \n {} \n to {}').format(self._package_download_url, output_file))
        common.print_log_message(_('Done downloading ITSI module package.'))

    def _get_package_download_url(self, content):
        """
        Get download url.

        @type content: json string
        @param content: json string that contains url.

        @rtype: basestring
        @return: package download url
        """
        request_content = json.loads(content)
        if 'url' not in request_content or not request_content['url'] or not request_content['url'].strip():
            common.print_log_message(_('Fail to get a valid url to download ITSI module package!'), 'ERROR')
            sys.exit(1)

        return request_content['url']

    def _group_errors_by_object_key(self, errors):
        """
        Group the errors array by the object key

        @type errors: array
        @param errors: an array of arrays containing error text

        @rtype: dict
        @return: a dictionary of errors by key
        """
        error_dict = {}
        for error in errors:
            if error[1] not in error_dict:
                error_dict[error[1]] = []
            error_dict[error[1]].append(error[2])

        return error_dict


def main(input_args):
    """
    Main method for ITSI module packaging

    @type input_args: args
    @param input_args: the command-line arguments
    """
    # Specify command line parameters
    parser = ArgumentParser(
        description=_('Validates and generates a compressed package of ITSI module objects on specified Splunk instance, \
            then downloads the package to a local path. It is recommended that you restart the Splunk instance before \
            running this command to avoid issues related to cached artifacts. \
            All errors and warnings will be provided as console output.'))
    parser = common.add_common_arguments(parser)
    parser.add_argument(
        '--output',
        metavar='OUTPUT_PATH',
        dest='output_path',
        help='Output path, optional. Defaults to current path')
    parser.add_argument(
        '--overwrite-existing-package',
        action='store_true',
        help='Overwrite ITSI module package, if exists, during download. Defaults to false.')

    args = parser.parse_args(input_args)

    # create ItsiModulePackager to do actual work
    itsi_module = args.itsi_module if args.itsi_module.startswith('DA-ITSI-') else 'DA-ITSI-%s' % args.itsi_module
    itsi_module_packager = ItsiModulePackager(
        args.server,
        args.user,
        args.password,
        itsi_module,
        args.scheme,
        args.port,
        args.output_path,
        args.overwrite_existing_package)

    # validate ITSI module
    error_count, info_count = itsi_module_packager.validate_itsi_module()

    if error_count > 0:
        common.print_log_message(_('Please fix validation errors and try again.'))
        sys.exit(1)

    # package ITSI module
    itsi_module_packager.package_itsi_module()

    # download ITSI module package
    itsi_module_packager.download_itsi_module_package()

    print 'Done.'

if __name__ == '__main__':
    main(sys.argv[1:])
