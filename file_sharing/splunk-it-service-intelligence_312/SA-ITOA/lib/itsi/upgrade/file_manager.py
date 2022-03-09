# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import os
import errno
import zipfile
import glob
import shutil
import json

import logging
from ITOA.setup_logging import setup_logging
logger = setup_logging("itsi_config.log", "itsi.filemanager",
                       is_console_header=True)

class FileManager(object):
    """
    Manager file operation
    """
    DELIMITER = "___"
    @staticmethod
    def delete_file(path):
        """
        Deletes the file at the path provided
        :param path: path to delete file at
        :return:
        """
        try:
            os.remove(path)
        except OSError as e:
            logger.warning(e)

    @staticmethod
    def is_file(path):
        """
        Check if it is file or not

        @type path: basestring
        @param path: directory path

        @rtype: bool
        @return: True or False
        """
        return os.path.isfile(path)

    @staticmethod
    def is_directory(path):
        """
        Check if it is directory

        @type path: basestring
        @param path: directory path

        @rtype: bool
        @return: True or False
        """
        return os.path.isdir(path)

    @staticmethod
    def is_exists(path):
        return os.path.exists(path)

    @staticmethod
    def get_base_dir(file):
        """
        Get base dir of given file. If directory is passed then return dir

        @type file: basestring
        @param file: file path

        @return: Base directory - if file path is passed
        @rtype: basestring
        """
        if os.path.isfile(file):
            return os.path.dirname(file)
        elif os.path.isdir(file):
            return file
        elif file is None:
            return os.getcwd()

    @staticmethod
    def create_directory(path):
        """
        Create directory

        @type path: basestring
        @param path: directory path
        @return:
        """
        try:
            os.makedirs(path)
            logger.debug("Successfully create directory, path=%s", path)
        except OSError as e:
            if e.errno != errno.EEXIST:
                logger.exception(e)
                raise e

    @staticmethod
    def zip_directory(root_path, name_of_zip_file):
        """
        Zip the directory

        @type path: basestring
        @param path: directory path
        """
        try:
            os.chdir(os.path.dirname(root_path))
            with zipfile.ZipFile(name_of_zip_file + '.zip',
                                 "w",
                                 zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as zf:
                for root, _, filenames in os.walk(os.path.basename(root_path)):
                    for name in filenames:
                        name = os.path.join(root, name)
                        name = os.path.normpath(name)
                        zf.write(name, name)
        except Exception as exc:
            logger.exception(exc)
            raise

    @staticmethod
    def unzip_backup(path_to_zip_file, extract_to_path):
        """
        Unzip the backup zip file and rename the extracted folder to the parent folder name in extract_to_path

        @type path_to_zip_file: basestring
        @param path_to_zip_file: path to zip file including .zip extension

        @type extract_to_path: basestring
        @param extract_to_path: path to extract to
        """
        zip_ref = zipfile.ZipFile(path_to_zip_file, 'r')
        zip_ref.extractall(extract_to_path)
        zip_ref.close()

    @staticmethod
    def delete_working_directory(path):
        """
        Delete the working directory that contains the json files

        @type path: basestring
        @param path: directory path
        """
        try:
            shutil.rmtree(path)
        except OSError as ose:
            logger.exception(ose)
            raise


    @staticmethod
    def write_to_file(file_path, data, flag='w+'):
        """
        Write a valid json convert-able data to the file_path

        @type file_path: basestring
        @param file_path: file_path path

        @type data: dict
        @param data: json data to write

        @type flag: basestring
        @param flag: file_path opening flags

        @return:
        """
        with open(file_path, flag) as fp:
            fp.writelines(json.dumps(data))

    @staticmethod
    def read_data(file_path, flag='r'):
        """
        Read data from given file_path and return json object

        @type file_path: basestring
        @param file_path: file_path path

        @type flag: basestring
        @param flag: file_path opening flags

        @rtype: json dict
        @return: json based dict
        """
        with open(file_path, flag) as fp:
            data = json.load(fp)

        return data

    @staticmethod
    def clean_file(file_path):
        """
        Delete content of the file

        @type file_path: basestring
        @param file_path: file path

        @return:
        """
        if os.path.exists(file_path):
            try:
                open(file_path, "w").close()
            except Exception as exc:
                logger.error(exc.message)
                logger.info("Failed to clean existing file, will append data to existing file")

    @staticmethod
    def get_rolling_file_name(file_path, rolling_file_number=0):
        """
        Get rolling file name
        for example: ('/tmp/foo.txt,2) would return /tmp/foo___2.txt where ____ is the DELIMITER string

        @type file_path: basestring
        @param file_path: file path

        @type rolling_file_number: integer
        @param rolling_file_number: rolling file number

        @rtype: basestring
        @return: file name
        """
        basedir = os.path.dirname(file_path)
        basefilename = os.path.basename(file_path)
        tmp_file = basefilename[0:basefilename.rfind(".")] + FileManager.DELIMITER +\
                   str(rolling_file_number) + basefilename[basefilename.rfind("."): len(basefilename)]
        return os.path.join(basedir, tmp_file)


    @staticmethod
    def get_zip_file_names(directory_path):
        """
        Get filenames with a .zip extension in the directory provided by directory_path

        @:rtype: list
        @return: list of filenames

        """
        file_paths = glob.glob(os.path.join(directory_path,'*.zip'))
        if isinstance(file_paths, list) and len(file_paths)>0:
            return [fpath.split(os.sep)[-1].split('.zip')[-2] for fpath in file_paths]
        else:
            return None
