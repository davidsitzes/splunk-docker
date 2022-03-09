# $(copyright)
import base64
import uuid

import os
import shutil

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import safe_remove, maybe_makedirs
from mako.template import Template

from ITOA.setup_logging import setup_logging


class ItsiModuleAssetGenerator(object):
    """
    Class that generate ITSI module app.
    """

    _METADATA_FILE_MAX_SIZE = 2 * 1024 * 1024

    def __init__(self, resource_dir, dst_dir, app_name=None, logger=None):
        """
        Initialize objects

        @type resource_dir: basestring
        @param resource_dir: resource directory for barebone ITSI module app

        @type dst_dir: basestring
        @param dst_dir: destination where ITSI module app is created

        @type app_name: basestring
        @param app_name: ITSI module app name

        @type logger: object
        @param logger: logger to use

        @rtype: object
        @return: instance of the class
        """

        if not app_name:
            self._app_name = os.path.split(dst_dir)[-1]
        else:
            self._app_name = app_name

        self._resource_dir = resource_dir
        self._dst_dir = dst_dir

        if logger is None:
            self._logger = setup_logging('itsi_module_interface.log',
                                         'itsi.module.module_builder')
        else:
            self._logger = logger

    def generate_itsimodule_assets(self, meta):
        """
        Generate ITSI module app by first remove old folder, create new folder with
        files on destination, then fill in app.conf with app metadata.

        @type meta: dict
        @param meta: app metadata

        @return: dict indicating upload results
            {
                code: 200 if all is successful, 403 if any file is invalid, 500 if internal error occurs
                error_message: list, contains any message for invalid file or internal error
            }
        """
        self._remove_dst_folders()
        self._generate_folders()
        self._generate_app_conf(meta)
        self._generate_itsi_module_settings_conf(meta)
        return self._save_meta_files(meta)

    def update_module_metadata(self, meta):
        """
        Update metadata fields in app.conf and upload icon and readme files.
        *Bails if update of app.conf fails and exception boils up to rest layer.
        *Failure in uploading files is silent and is listed in returned response

        @type meta: dict
        @param meta: app metadata

        @return: dict indicating upload results
            {
                code: 200 if all is successful, 403 if any file is invalid, 500 if internal error occurs
                error_message: list, contains any message for invalid file or internal error
            }
        """
        self._update_app_conf(meta)
        return self._save_meta_files(meta)

    def _remove_dst_folders(self):
        """
        Remove destination folder

        @return: None
        """
        safe_remove(self._dst_dir)

    def _generate_folders(self):
        """
        Generate folder at destination path

        @return: None
        """
        if os.path.exists(self._dst_dir):
            msg = _("Directory {} is not empty.").format(self._dst_dir)
            self._logger.error(msg)
            raise Exception(msg)
        shutil.copytree(self._resource_dir,
                        self._dst_dir,
                        ignore=shutil.ignore_patterns('*.template'))

    def _generate_itsi_module_settings_conf(self, meta):
        """
        Render itsi_module_settings.conf as an empty file, this by default should
        make the module in moduler builder editable

        @type meta: object
        @param meta: app metadata

        @return: None
        """
        targetfile = os.path.join(self._dst_dir, 'local', 'itsi_module_settings.conf')
        with open(targetfile, 'w+') as write_file:
            write_file.write('')
        self._logger.info('generated itsi_module_settings.conf at %s', self._dst_dir)

    def _generate_app_conf(self, meta):
        """
        Render app.conf at destination with app metadata.

        @type meta: dict
        @param meta: app metadata

        @return: None
        """
        author = meta.get("author", None)
        version = meta.get("version", None)
        description = meta.get("description", None)
        app_name = meta.get('app_name', None)
        title = meta.get('title', None)
        filename = os.path.join(self._resource_dir, 'local',
                                'app.conf.template')
        temp = Template(filename=filename)
        tran = temp.render(author=author,
                           version=version,
                           description=description,
                           app_name=app_name,
                           title=title)
        targetfile = os.path.join(self._dst_dir, "local", "app.conf")
        with open(targetfile, "w+") as write_file:
            write_file.write(tran.strip())
        self._logger.info('generated app.conf at %s', self._dst_dir)

    def _update_app_conf(self, meta):
        """
        @type meta: dict
        @param meta: app metadata

        @return: None
        """

        if meta.get('app_name', None) != self._app_name:
            raise Exception(_('App id cannot be updated'))

        old_app_conf = self._backup_app_conf()
        try:
            self._generate_app_conf(meta)
            safe_remove(old_app_conf)
        except Exception as e:
            self._restore_app_conf(old_app_conf)
            raise Exception(_('Cannot update metadata. Error: {}').format(e.message))

    def _save_meta_files(self, meta):
        """
        Save meta files to the specified ITSI module folder
        Fails silently and reports save result of each file in the returned dict

        @param meta: dict
            {
                readme: <string, optional>
                small_icon: <string, optional>
                large_icon: <string, optional>
            }
        @return: dict indicating result of saving each file
        """
        meta_file_names = ['readme', 'small_icon', 'large_icon']
        meta_files = {k: v for k, v in meta.items() if k in meta_file_names}

        result = {'code': 200, 'error_message': []}
        if not len(meta_files) > 0:
            return result

        icon_dir = os.path.join(self._dst_dir, 'static')
        dst = {
            'readme': os.path.join(self._dst_dir, 'README.txt'),
            'small_icon': os.path.join(icon_dir, 'appIcon.png'),
            'large_icon': os.path.join(icon_dir, 'appIcon_2x.png')
        }

        temp_dir = os.path.join(self._dst_dir, 'tmp' + str(uuid.uuid1()))
        try:
            maybe_makedirs(temp_dir, True)
            maybe_makedirs(icon_dir, True)
            for filename, content in meta_files.iteritems():
                file_path = os.path.join(temp_dir, filename)
                with open(file_path, 'wb') as f:
                    f.write(self._base64_decode(content))
                if self._validate_meta_file(file_path):
                    shutil.move(file_path, dst[filename])
                else:
                    result['code'] = 403
                    result['error_message'].append('upload failed. File {} exceeds maximum size.'.format(filename))
            return result
        except Exception as e:
            msg = _('Error while saving meta files: {}').format(e)
            self._logger.error(msg)
            result['code'] = 500
            result['error_message'].append(msg)
            return result
        finally:
            safe_remove(temp_dir)

    def _validate_meta_file(self, file_path):
        """
        Validates the uploaded file. Currently only checks file size.
        Max size is 2M.

        @param file_path: full path of the file to be checked

        @return: True / False
        """
        return os.path.getsize(file_path) <= self._METADATA_FILE_MAX_SIZE

    def _base64_decode(self, content):
        """
        Attempt to decode the string using base64, in the event of incorrect padding,
        try adding the trailing '='. If that fails, try removing the trailing few bytes.
        If both don't work, throw the exception.
        @param content: <string>
        @return: decoded string
        """
        try:
            return base64.standard_b64decode(content)
        except TypeError as e:
            trailing_bytes = len(content) % 4
            if trailing_bytes == 0:
                raise e
            else:
                try:
                    content += b'=' * (4 - trailing_bytes)
                    return base64.standard_b64decode(content)
                except TypeError:
                    return base64.standard_b64decode(content[:len(content) - 4])

    def _backup_app_conf(self):
        """
        Creates a backup of the current app.conf for rollback use

        @return: string: full path of the backup file
        """
        original = os.path.join(self._dst_dir, 'local', 'app.conf')
        backup = os.path.join(self._dst_dir, 'local', 'app.conf.bak')
        shutil.move(original, backup)
        return backup

    def _restore_app_conf(self, backup):
        """
        Restore the specified backup app.conf file

        @param backup: full path of the backup file

        @return: None
        """
        restore = os.path.join(self._dst_dir, 'local', 'app.conf')
        shutil.move(backup, restore)
