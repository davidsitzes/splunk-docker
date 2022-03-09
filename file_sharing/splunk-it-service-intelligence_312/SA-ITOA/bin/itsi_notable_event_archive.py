# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input which moves events from KV Store to Index
"""

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import modular_input_should_run
from ITOA.setup_logging import setup_logging
from itsi.event_management.itsi_notable_event_retention_policy import ItsiNotableEventRetentionPolicy

from SA_ITOA_app_common.solnlib.modular_input import ModularInput


class ItsiNotableEventArchiveModularInput(ModularInput):
    """
    Mod input which move events from kv store collection to index
    """

    title                    = _("IT Service Intelligence Notable Event Archiver")
    description              = _("Move notable events from KV store collection to " \
                               "index based upon retention policy")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_notable_event_archive'
    use_single_instance      = False
    use_kvstore_checkpointer = False
    use_hec_event_writer     = False

    def extra_arguments(self):
        return [{
                'name'        : "owner",
                'title'       : _("namespace"),
                'description' : _("namespace under which KV store operation is called. Default is 'nobody'")
            }]

    def do_run(self, input_config):
        """
        This is the method called by splunkd when mod input is enabled.
        @param stanzas: stanza
        """

        logger = setup_logging("itsi_event_management.log", "itsi.notable_event.archive")
        if not modular_input_should_run(self.session_key, logger=logger):
            logger.info("Will not run modular input on this node")
            return

        input_config = input_config.values()[0]

        if isinstance(input_config, dict):
            owner = input_config.get('owner', 'nobody')
        else:
            owner = 'nobody'

        ItsiNotableEventRetentionPolicy(self.session_key, owner=owner).execute()


if __name__ == "__main__":
    worker = ItsiNotableEventArchiveModularInput()
    worker.execute()
    sys.exit(0)
