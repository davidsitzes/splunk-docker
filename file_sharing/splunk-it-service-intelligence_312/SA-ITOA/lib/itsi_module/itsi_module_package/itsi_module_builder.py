# $(copyright)

import os
import tarfile
import shutil
import urllib

from itsi_module_asset_generator import ItsiModuleAssetGenerator
from ITOA.setup_logging import setup_logging
import itsi_module_builder_util as builder_util
import splunk.rest
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import normalizeBoolean


class ItsiModuleBuilder(object):
    """
    Main class that validate app meta, call ItsiModuleAssetGenerator to generate ITSI module app.
    """

    def __init__(self, app_name, uri=None, session_key=None, logger=None):
        """
        Initialize objects

        @type app_name: basestring
        @param app_name: module app name

        @type uri: basestring
        @param uri: uri of splunk server to call

        @type session_key: basestring
        @param session_key: session key

        @type logger: object
        @param logger: logger to use

        @rtype: object
        @return: instance of the class
        """
        self._validation_package_name(app_name)

        self._splunk_uri = uri
        self._splunk_session_key = session_key
        self._app_name = app_name
        if logger is None:
            self._logger = setup_logging('itsi_module_interface.log',
                                         'itsi.module.module_builder')
        else:
            self._logger = logger

        self._parent_dir = os.path.split(os.path.realpath(__file__))[0]
        self._resource_dir = os.path.join(self._parent_dir, "resources")
        self._splunk_app_dir = make_splunkhome_path(['etc', 'apps'])
        self._current_app_dir = os.path.join(self._splunk_app_dir,
                                             self._app_name)

        self._asset_generator = ItsiModuleAssetGenerator(
            self._resource_dir, self._current_app_dir, self._app_name, self._logger)

    def generate_module(self, meta, overwrite=False):
        """
        Generate ITSI module app after validation and also update splunkd about new app

        @type meta: dict
        @param meta: app metadata

        @type overwrite: boolean
        @param overwrite: overwrite existing module app if true

        @return: dict of file upload results
        """
        self._validation_project_basic_meta(meta, overwrite)

        upload_results = self._asset_generator.generate_itsimodule_assets(meta)

        self._notify_splunkd()

        return upload_results

    def update_module(self, meta):
        """
        Update metadata fields and files of an existing ITSI module, overwrites existing files.

        @type meta: dict
        @param meta: app metadata
        @return: dict of file upload results
        """
        if not os.path.isdir(self._current_app_dir):
            raise Exception(_('The requested ITSI module does not exist.'))
        update_result = self._asset_generator.update_module_metadata(meta)

        self._refresh_app_conf()
        self._notify_splunkd()

        return update_result

    def _notify_splunkd(self):
        """
        Notify splunkd about the newly created or updated app

        @return: None
        """
        try:
            splunk.rest.simpleRequest('apps/local/_reload', sessionKey=self._splunk_session_key)
        except Exception as e:
            message = _('failed to notify splunkd that app has been updated:{}. Exception details:{}, {}').format(
                self._app_name, type(e).__name__, e.message)
            self._logger.error(message)
            raise Exception(message)
        self._logger.info('successfully notify splunkd that app has been installed:%s' % self._app_name)

    def _validation_project_basic_meta(self, meta, overwrite):
        """
        Validate app meta

        @type meta: dict
        @param meta: app metadata

        @type overwrite: boolean
        @param overwrite: overwrite existing app if true

        @return: None or Exception
        """
        app_name = meta.get('app_name', '')

        if app_name:
            self._validation_package_name(app_name)

            if self._app_name != app_name:
                message = _('App name in metadata is not consistent')
                self._logger.error(message)
                raise Exception(message)

            if not overwrite:
                # can not overwrite the existing app
                if os.path.isdir(self._current_app_dir):
                    raise Exception(_('ITSI module already exists: {}').format(
                        self._app_name))
        else:
            message = _('ITSI module name is missing')
            self._logger.error(message)
            raise Exception(message)

    def _validation_package_name(self, package_name):
        """
        Validate app package name

        @type package_name: basestring
        @param package_name: app package name

        @return: None or Exception
        """
        if builder_util.contain_reserved_chars(package_name):
            raise Exception(_('ITSI module name cannot contain spaces or special characters.'))

    def package_module(self, make_readonly):
        """
        Package ITSI module app into .spl package file.

        @type make_readonly: boolean
        @param make_readonly: flag that is used to make module read only in SPL

        @rtype tuple
        @return tuple: tuple of
                {string} package file name
                {string} full file path of package

        @rtype: object
        @return: None or Exception
        """
        # Make sure that ITSI module exists
        app_path = os.path.join(self._splunk_app_dir, self._app_name)
        if not os.path.exists(app_path):
            message = _('ITSI module does not exist. Nothing to package')
            self._logger.error(message)
            raise Exception(message)

        # Make sure before SPL is generated to set readonly flag in itsi_module_settings.conf
        self._set_readonly_status(make_readonly)

        # Copy ITSI module to package workspace dir
        package_workspace = make_splunkhome_path(['var', 'data', "itsimodulebuilder", "package", self._app_name])
        builder_util.prepare_app_package_workspace(package_workspace, app_path)

        package_file_name = builder_util.get_download_package_name(self._app_name)
        self._logger.info('copy %s from %s to %s for package' % (package_file_name, app_path, package_workspace))

        # Package ITSI module from package workspace dir to download path
        download_file_path = builder_util.get_package_file_full_path_with_package_name(package_file_name)
        with tarfile.open(download_file_path, "w:gz") as tar:
            tar.add(package_workspace,
                    arcname=os.path.basename(package_workspace))

        # Clean up package workspace dir
        shutil.rmtree(package_workspace)

        # Delete the stanza that had the read only flag set before packaging started
        self._delete_readonly_flag()

        return package_file_name, download_file_path

    def _set_readonly_status(self, readonly_status):
        """
        This creates the stanza within itsi_module_settings.conf for the given module context, and then
        sets the read only flag to the specified value in the request.  This is only to be done upon the
        step when the ITSI module is being packaged into an SPL.

        @type readonly_status: Boolean
        @param readonly_status: The value of whether the module is going to be read only when packaged
        """
        conf_endpoint = '/servicesNS/nobody/{}/configs/conf-itsi_module_settings'.format(self._app_name)
        stanza_name = 'settings://{}'.format(self._app_name)

        # We are going to need to encode the stanza to correctly target it to write the readonly flag
        encoded_stanza_name = urllib.quote_plus(stanza_name)
        stanza_args = {
            'name': stanza_name
        }
        # To be consistent, make sure the flag is written to the conf file as a 0 or a 1
        readonly_args = {
            'is_read_only': 1 if readonly_status else 0
        }
        try:
            # First, create the conf stanza in the file name
            self._logger.info('Writing CONF stanza {} to file {}....'.format(stanza_name, 'itsi_module_settings.conf'))
            splunk.rest.simpleRequest(conf_endpoint, method='POST', sessionKey=self._splunk_session_key, postargs=stanza_args)

            # Then, set the flag to true or false
            self._logger.info('Writing is_read_only={} flag to CONF stanza...'.format(readonly_args['is_read_only']))
            created_stanza_url = '{}/{}'.format(conf_endpoint, encoded_stanza_name)
            splunk.rest.simpleRequest(created_stanza_url, method='POST', sessionKey=self._splunk_session_key, postargs=readonly_args)
        except Exception as e:
            message = _('failed to set read only flag in itsi_module_settings.conf for {}.  Exception details: {}, {}').format(
                self._app_name, type(e).__name__, e.message)
            self._logger.error(message)
            raise Exception(message)
        self._logger.info('Successfully set read only flag for {}!'.format(self._app_name))

    def _delete_readonly_flag(self):
        """
        This is to be run after module SPL has been packaged.  Deleting this stanza will make the module
        writable within the context of the splunk instance, while the person who installs the packaged SPL
        will have a read only version of the module
        """
        stanza_name = 'settings://{}'.format(self._app_name)
        stanza_to_delete = urllib.quote_plus(stanza_name)
        delete_stanza_url = '/servicesNS/nobody/{}/configs/conf-itsi_module_settings/{}'.format(self._app_name, stanza_to_delete)
        try:
            self._logger.info('Deleting CONF stanza {}...'.format(stanza_name))
            splunk.rest.simpleRequest(delete_stanza_url, method='DELETE', sessionKey=self._splunk_session_key)
        except Exception as e:
            message = _('failed to delete stanza {} from itsi_module_settings.conf.  Exception details: {}, {}').format(
                stanza_name, type(e).__name__, e.message)
            self._logger.error(message)
            raise Exception(message)
        self._logger.info('Successfully deleted stanza {}!'.format(stanza_name))

    def _refresh_app_conf(self):
        refresh_url = '/servicesNS/nobody/{}/configs/conf-app/_reload'.format(self._app_name)
        try:
            self._logger.info('Refreshing app.conf...')
            splunk.rest.simpleRequest(refresh_url, sessionKey=self._splunk_session_key)
        except Exception as e:
            message = _('failed to refresh app.conf for {}. Exception details:{}, {}').format(
                self._app_name, type(e).__name__, e.message)
            self._logger.error(message)
            raise Exception(message)
        self._logger.info('"Successfully refreshed app.conf for {}!'.format(self._app_name))
