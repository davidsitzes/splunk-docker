# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.setup_logging import setup_logging

from deploy_default_lookup_files import deployDefaultLookupFiles

class ITInstaller(object):
    """
    Performs the various operations necessary to install ITSI
    """

    @staticmethod
    def doInstall( sessionKey=None, splunk_home = None, logger = None, force = False ):

        # Compute the locations of the Splunk apps directory
        splunk_app_dir = make_splunkhome_path(['etc', 'apps'])

        # Setup a logger if none was provided
        if logger is None:
            # Get the handler
            logger = setup_logging("itsi_install.log", "itsi.install")

        # Log a message noting the ITSI install is starting
        if logger:
            logger.info("IT Service Intelligence install is starting, splunk_app_dir=%s" % (splunk_app_dir))

        # Run the various operations, note we limit all actions to just the itsi app
        logger.debug("Total path for installer: %s" % (splunk_app_dir))
        deployDefaultLookupFiles( make_splunkhome_path(['etc', 'apps', 'itsi']), logger=logger)

        # Log a message noting the ITSI install is done
        if logger:
            logger.info("ITSI install has completed")
