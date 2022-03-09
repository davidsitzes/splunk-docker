# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that runs on startup and load default ACL to KV store
if it is not available
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.event_management.utils import CorrelationSearchDefaultAclLoader
from ITOA.itoa_common import modular_input_should_run
from ITOA.setup_logging import setup_logging
from SA_ITOA_app_common.solnlib.modular_input import ModularInput


class ItsiCorrelationSearchAclLoader(ModularInput):
    """
    Mod input that handles Upgrades which is primarily migration of data
    from older version to current version
    """

    title = _("IT Service Intelligence Default Correlation Search ACL loader")
    description = _("Load default correlation search acl")
    handlers = None
    app = 'SA-ITOA'
    name = 'itsi_default_correlation_search_acl_loader'
    use_single_instance = False
    use_kvstore_checkpointer = False
    use_hec_event_writer = False

    def extra_arguments(self):
        return [{
            'name': "log_level",
            'title': _("Logging Level"),
            'description': _("This is the level at which the modular input will log data")
        }]

    def do_run(self, input_config):
        """
        - This is the method called by splunkd when mod input is enabled.
        @param input_config: config passed down by splunkd
        """
        logger = setup_logging('itsi_event_management.log', 'itsi.correlation_search')
        if not modular_input_should_run(self.session_key, logger):
            logger.debug("modular input will not run on this SHC member")
            return
        try:
            CorrelationSearchDefaultAclLoader(self.session_key, logger).default_acl_loader()
            logger.info("Successfully set acl for default correlation search")
        except Exception as e:
            logger.error("Failed to set acl for default correlation search")
            logger.exception(e)
            raise

if __name__ == "__main__":
    worker = ItsiCorrelationSearchAclLoader()
    worker.execute()
