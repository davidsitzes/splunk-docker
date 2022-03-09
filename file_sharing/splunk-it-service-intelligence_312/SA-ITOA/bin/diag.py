# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

'''
A script that allows for the following:
    - Register the ITSI diag utility function with the core diag infrastructure.
    - Collect ITSI specific diag information.
    For Detail diag information, refer to the following wiki:
    https://confluence.splunk.com/display/CMTY/App-extensions+to+Diag
'''

import os
import re
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
logger = setup_logging("itsi_config.log", "itsi.diag")

SCRIPT_NAME = __file__

FILE_EXTENSION = '.json'

# using the **args pattern to ignore options we don't care about.
def setup(parser=None, app_dir=None, callback=None, **kwargs):
    """
    This is a diag registry function which registers the app diag utility function with the
    diag infrastructure in the core.

    @type    parser: function object
    @param   parser: parser function
    @type   app_dir: string
    @param  app_dir: location of the application directory
    @type  callback: function object
    @param callback: any callback function
    @type  **kwargs: string tuples
    @param **kwargs: any optional arguments
    @rtype None
    @return: None
    """
    logger.debug("[ITSI Diag] in setup")
    if callback is not None:
        callback.will_need_rest()
    logger.info("[ITSI Diag] Diag extensions initialized")


def collect_diag_info(diag, options=None, global_options=None, app_dir=None, **args):
    """
    This is the actual diag collection implementation for ITSI

    @type      diag: function object
    @param     diag: callback diag function pointer
    @type   options: string
    @param  options: diag options
    @type   global_options: string
    @param  global_options: diag options
    @type   app_dir: string
    @param  app_dir: location of the application
    @type    **args: string tuples
    @param **kwargs: any optional arguments
    @rtype None
    @return: None
    """
    logger.info("[ITSI Diag] Collecting Diag from ITSI")
    logger.debug("[ITSI Diag] in collect_diag_info")

    total_count = 0
    SPLUNK_HOME = os.environ['SPLUNK_HOME']

    # Build up a list of collections to be collected and sent to diag.
    # User have to enter a list of the apps that are ITSI relevant.
    # The collecting utility will parse the all the specific collections from
    #  <APP_Name>/default/collections.conf file.

    CONF_FILE = '/default/collections.conf'
    KVSTORE_RST_PATH = '/servicesNS/nobody/%s/storage/collections/data/'

    # List of apps that are related to ITSI
    app_list = ['SA-ITOA',
                'SA-ITSI-ATAD',
                'SA-UserAccess']

    kvstore_collections = []

    # Parse the etc/apps/<app_name>/default/collections.conf file
    #    and retrive a list of the kvstore collections.
    # Retrieve the kvstore content directly via restful endpoints.
    try:
        for app in app_list:
            final_app_rst_path = KVSTORE_RST_PATH % app
            target_path = (SPLUNK_HOME + '/etc/apps/' + '%s' + CONF_FILE) % app
            logger.info("[ITSI Diag] Retrieve kvstore collection list from %s." % target_path)

            # Parsing of the collections.conf is based on the standard collections file format.
            # Assumes that collection name are identified by [], such as
            # [<collection-name>]
            # The following parsing logic will look for [ and ], extract the collection name
            #   and ignore the rest of the collection options.
            # Format of collections.conf can be found in the following official Splunk linkL
            #   http://docs.splunk.com/Documentation/Splunk/latest/Admin/Collectionsconf
            for line in open(os.path.abspath(target_path), 'r').readlines():
                keyword = re.search(r'\[(.*)\]', line)
                if keyword:
                    kvstore_collections.append(keyword.group(1))

            for collection in kvstore_collections:
                full_rst_uri = final_app_rst_path + collection
                diag_json_file = collection + FILE_EXTENSION
                diag.add_rest_endpoint(full_rst_uri, diag_json_file)
                logger.info("[ITSI Diag] Collect %s into ITSI diag" % full_rst_uri)

            total_count += len(kvstore_collections)
            kvstore_collections[:] = []
        logger.info("[ITSI Diag] Total number of %s collections have been captured" % total_count)
    except Exception:
        logger.exception("[ITSI Diag] Unable to locate the kvstore collection.")
        pass
