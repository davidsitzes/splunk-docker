# $(copyright)

import os
import re
import shutil

import splunk.clilib.cli_common as comm

from splunk.clilib.bundle_paths import make_splunkhome_path
from ITOA.setup_logging import setup_logging

logger = setup_logging('itsi_module_interface.log', 'itsi.controllers.itsi_module_interface')

_RESERVED_NAME_CHARS = re.compile("[\s<>\:\"\/\\\|\?\*]")


def contain_reserved_chars(path_str):
    """
    Check if the given path contains any special char
    """
    return _RESERVED_NAME_CHARS.search(path_str) is not None


def _parse_version_in_app_conf(conf_file_name):
    """
    Get app's version given app.conf file
    """
    if os.path.isfile(conf_file_name):
        with open(conf_file_name, 'r') as f:
            logger.debug("Open file %s to read app version.",
                         conf_file_name)
            for l in f.readlines():
                logger.debug("Begin to match line: %s", l)
                m = re.search("version\s*=\s*([\d\.]+)", l)
                if m:
                    ver = m.group(1)
                    logger.debug("Get app version %s", ver)
                    return ver
    else:
        logger.debug("File %s not found!", conf_file_name)

    return None


def _get_app_version(app_name):
    """
    Get app version given app name
    """
    app_home = os.path.sep.join([os.environ["SPLUNK_HOME"], "etc", "apps",
                                 app_name])
    default_app_conf_file = os.path.sep.join([app_home, "default", "app.conf"])
    local_app_conf_file = os.path.sep.join([app_home, "local", "app.conf"])
    ver = _parse_version_in_app_conf(local_app_conf_file)
    if not ver:
        ver = _parse_version_in_app_conf(default_app_conf_file)
    if not ver:
        logger.error('Can not find version property in app.conf')
        ver = "unknown_version"
    return ver


def get_download_package_name(app_name):
    """
    Get download package name for a app given its app name
    """
    ver = _get_app_version(app_name).replace(".", "_")
    return '{}_{}.spl'.format(app_name, ver)


def get_package_file_full_path_with_package_name(package_file_name):
    """
    Get download package's full path with given package file name
    """

    download_dir = make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'appserver', 'static', 'download'])
    if not os.path.isdir(download_dir):
        os.makedirs(download_dir)
    return os.path.join(download_dir, package_file_name)


def prepare_app_package_workspace(package_workspace, app_source_path):
    """
    Prepare app package workspace.
    It copies app package folder to this workspce, then merge all conf files.
    """
    if not os.path.exists(os.path.dirname(package_workspace)):
        os.makedirs(os.path.dirname(package_workspace))
    if os.path.exists(package_workspace):
        shutil.rmtree(package_workspace)

    # TAG-11885. Since local.meta contains info that are irrelevant for ITSI module,
    # we will not include it for app package.
    shutil.copytree(app_source_path,
                    package_workspace,
                    ignore=shutil.ignore_patterns('*.pyc', '*.pyo', 'local.meta'))

    # merge all the conf file
    _merge_all_contents(package_workspace)


def _merge_conf_file(src, dest, conf_file_name):
    """
    Merge a conf file given src dir, dest dir and conf file name.

    @type src: string
    @param src: path to src directory to copy from

    @type dest: string
    @param dest: path to dest directory to copy to

    @type conf_file_name: string
    @param conf_file_name: name of the conf file to be merged
    """
    dft_conf = os.path.join(dest, conf_file_name)
    usr_conf = os.path.join(src, conf_file_name)

    # Only do merge on .conf file. For other non-conf files, replace what's in default with files under local
    if os.path.isfile(dft_conf) and conf_file_name.endswith('.conf'):
        if os.path.isfile(usr_conf):

            logger.debug("Start merging %s to %s", usr_conf, dft_conf)

            src_conf = comm.readConfFile(usr_conf)
            dst_conf = comm.readConfFile(dft_conf)

            for k in src_conf.keys():
                if k in dst_conf:
                    dst_conf[k].update(src_conf[k])
                    logger.debug("%s is updated by %s during merge", dst_conf[k], src_conf[k])
                else:
                    dst_conf[k] = src_conf[k]
                    logger.debug("%s is added during merge", dst_conf[k])

            comm.removeItem(dft_conf)
            comm.writeConfFile(dft_conf, dst_conf)
            logger.debug("%s is merged to %s. The merged content is %s", usr_conf, dft_conf, dst_conf)
        else:
            logger.debug("No need to merge. User Conf %s not found!",
                         usr_conf)
    else:
        if os.path.isfile(usr_conf):
            shutil.copyfile(usr_conf, dft_conf)
            logger.debug("copy %s to %s", usr_conf, dft_conf)
        else:
            logger.error(
                "Both default conf %s and user conf %s are not found!",
                dft_conf, usr_conf)


def _merge_all_contents(app_root_dir):
    """
    Merge all contents given root dir.

    @type app_root_dir: string
    @param app_root_dir: path to itsi module root directory
    """
    if not os.path.isdir(app_root_dir):
        logger.error("App dir %s not found!", app_root_dir)
        return
    local_dir = os.path.join(app_root_dir, "local")
    if not os.path.isdir(local_dir):
        logger.info("Local conf dir %s not found.", local_dir)
        return  # no need to merge
    dft_dir = os.path.join(app_root_dir, "default")
    if not os.path.isdir(dft_dir):
        os.makedirs(dft_dir)
        logger.info("Make default conf dir %s", dft_dir)
    logger.info("Start merging %s directory to %s " % (local_dir, dft_dir))
    # Merge local and default folders
    _merge_two_dirs(local_dir, dft_dir)
    logger.info("Finished merging %s directory to %s " % (local_dir, dft_dir))
    shutil.rmtree(local_dir)
    logger.debug("remove local conf dir %s", local_dir)


def _merge_two_dirs(src, dest):
    """
    Helper function to merge two directories.
    If dest directory does not exist, copy the entire src directory to dest directory
    If dest directory does exist, merge all conf files and recursively call this function

    @type src: string
    @param src: path to src directory to copy from

    @type dest: string
    @param dest: path to dest directory to copy to
    """
    FILENAMES = 2
    SUBDIRNAMES = 1
    ACCEPTED_FILE_EXTENSIONS = ['conf', 'json', 'xml', 'py', 'js', 'css', 'html', 'txt']
    # Copy all .conf files in current directory if there's any
    local_conf_files = [file for file in os.walk(src).next()[FILENAMES] if file.split('.')[-1] in ACCEPTED_FILE_EXTENSIONS]
    if local_conf_files:
        for conf in local_conf_files:
            _merge_conf_file(src, dest, conf)

    # Get a list of sub directory names
    subdirs = os.walk(src).next()[SUBDIRNAMES]
    if subdirs:
        logger.info('sub directories exist in current directory %s' % subdirs)
        for subdir in subdirs:
            merge_to_dir = os.path.join(dest, subdir)
            merge_from_dir = os.path.join(src, subdir)
            # Copy the entire directory from local to default if default does not have such sub directory
            if not os.path.isdir(merge_to_dir):
                shutil.copytree(merge_from_dir, merge_to_dir, ignore=shutil.ignore_patterns('*.pyc', '*.pyo'))
            else:
                _merge_two_dirs(merge_from_dir, merge_to_dir)
