# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITSI-Licensechecker', 'lib']))
from license_checker import LicenseCheck

from ITOA.itoa_common import modular_input_should_run, get_itoa_logger

from SA_ITSI_Licensechecker_app_common.solnlib.modular_input import ModularInput
from SA_ITSI_Licensechecker_app_common.solnlib.splunk_rest_client import SplunkRestClient

class LicenseCheckModularInput(ModularInput):
    title                       = 'IT Service Intelligence license checker'
    description                 = 'Modular input to check if Splunk instance has valid IT Service Intelligence License'
    handlers                    = None
    app                         = "SA-ITSI-Licensechecker"
    name                        = "itsi_license_checker"
    use_single_instance         = False
    use_kvstore_checkpointer    = False
    use_hec_event_writer        = False

    def extra_arguments(self):
        return [{
            'name': 'app_name',
            'title': 'Application name',
            'description': 'Application name, defaults to itsi.'
            }]

    def do_run(self, stanza):
        """
        @type stanza: dict
        @param stanza: config for this modular input
        """

        if not modular_input_should_run(self.session_key):
            logger = get_itoa_logger("itsi.license_checker", "itsi_license_checker.log")
            logger.info("Will not run modular input on this node.")
            return

        # mod input config comes in as a dict, key'ed by the name of the modular
        # input. the value is the config we care about.
        stanza = stanza.values()[0]

        self.app = stanza.get('app_name', 'itsi')

        license_checker = LicenseCheck(self.server_uri, self.session_key, self.app)
        messages = license_checker.verify_license_expiration()
        msg = SplunkRestClient(session_key=self.session_key, app=self.app).messages

        for item in messages:
            try:
                msg.post(name='some_msg', value=item.get('message'), severity='info')
            except Exception:
                pass # best effort

if __name__ == "__main__":
    worker = LicenseCheckModularInput()
    worker.execute()
    sys.exit(0)
