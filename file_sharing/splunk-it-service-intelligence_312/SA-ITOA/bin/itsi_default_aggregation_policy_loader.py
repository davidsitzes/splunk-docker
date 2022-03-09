# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that runs on startup and load default policy to KV store
if it is not available
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.event_management.utils import NotableEventDefaultPolicyLoader
from ITOA.itoa_common import modular_input_should_run
from ITOA.setup_logging import setup_logging

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

class ItsiAggregationPolicyLoader(ModularInput):
    """
    Mod input that handles Upgrades which is primarily migration of data
    from older version to current version
    """

    title = _("IT Service Intelligence Default Policy Loader")
    description = _("Load default aggregation policy")
    handlers = None
    app = 'SA-ITOA'
    name = 'itsi_default_aggregation_policy_loader'
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
        logger = setup_logging('itsi_event_management.log', 'itsi.notable_event_policy_aggregator')
        if not modular_input_should_run(self.session_key, logger):
            logger.debug("modular input will not run on this SHC member")
            return
        try:
            ret = NotableEventDefaultPolicyLoader(self.session_key, logger).upload_default_policy()
            if not ret:
                logger.error('Failed to create default policy')
            else:
                logger.info("Successfully uploaded default policy")
        except Exception as e:
            logger.exception(e)
            raise

if __name__ == "__main__":
    worker = ItsiAggregationPolicyLoader()
    worker.execute()
