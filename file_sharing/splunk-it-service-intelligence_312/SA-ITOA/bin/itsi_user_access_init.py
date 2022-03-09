# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
A script that registers ITSI's capabilities with SA-UserAccess and
then disables its own subsequent runs after a successful run.
"""

import copy
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.event_management.notable_event_utils import CAPABILITY_MATRIX as CAPABILITY_MATRIX_NOTABLE_EVENTS
from maintenance_services.constants import CAPABILITY_MATRIX as CAPABILITY_MATRIX_MAINTENANCE_SERVICES
from ITOA.setup_logging import setup_logging
from ITOA.itoa_common import modular_input_should_run, get_current_utc_epoch
from ITOA.storage.itoa_storage import ITOAStorage

from SA_ITOA_app_common.solnlib.modular_input import ModularInput

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import UserAccess
from user_access_errors import BadRequest

logger = setup_logging("itsi_config.log", "itsi.user_access_init")


class ITSIUserAccessInit(ModularInput):
    '''
    Modular input responsible for registering the capabilities matrix with SA-UserAccess
    It shuts itself off after doing this once
    '''
    title                    = _("IT Service Intelligence Access Control Registration")
    description              = _("Register ITSI's capabilities with SA-UserAccess")
    handlers                 = None
    app                      = 'SA-ITOA'
    name                     = 'itsi_user_access_init'
    use_single_instance      = True
    use_kvstore_checkpointer = False
    use_hec_event_writer     = False

    def extra_arguments(self):
        return [{
                'name'        : "log_level",
                'title'       : _("Logging Level"),
                'description' : _("This is the level at which the modular input will log data")
            },
            {
                'name'        : "registered_capabilities",
                'title'       : _("Configuration Flag"),
                'description' : _("This flag indicates whether or not the app has previously " \
                                "registered its capabilities")
            },
            {
                'name'        : "app_name",
                'title'       : _("App name"),
                'description' : _("String indicating name of app which wishes to register its capabilities")
            }]

    def register_app_capabilities(self, app_name):
        '''
        A custom method to register app capabilities. The logic always
        re-writes the capability matrix as it is desirable for upgrade scenario.
        This piece of code will eventually change when we get rid of SA-UserAccess
        and starting app-common'ing.

        @type app_name: string
        @param app_name: represents app name
            Ex: itsi/es etc...

        @type capability_matrix: dict
        @param capability_matrix: capabilities viz-a-viz app objects
            Ex:
                {
                    'glass_table': {
                        'read': 'read_itsi_glass_table',
                        'write': 'write_itsi_glass_table',
                        'delete': 'delete_itsi_glass_table'
                        },
                    'deep_dive': {
                        'read': 'read_itsi_deep_dive',
                        'write': 'write_itsi_deep_dive',
                        'delete': 'delete_itsi_deep_dive'
                        },
                    ...
                }

        @type session_key: string
        @param session_key : splunkd session key

        @return True on successful registration, False if otherwise
        '''
        LOG_PREFIX = "[ITSIUserAccessInit] [register_app_capabilities] "
        STORE_NAME = UserAccess.get_app_capability_store_name()
        if not isinstance(app_name, basestring) or not isinstance(CAPABILITY_MATRIX, dict):
            message = _('Expecting a non-None string for app_name and a non-None dict for capability_matrix')
            logger.error('%s %s', LOG_PREFIX, message)
            return False

        # Work on the copy of the matrix
        capability_matrix = copy.deepcopy(CAPABILITY_MATRIX)

        if not isinstance(CAPABILITY_MATRIX_NOTABLE_EVENTS, dict):
            message = _('Expecting a non-None dict for capability_matrix_notable_events')
            logger.error('%s %s', LOG_PREFIX, message)
            return False
        capability_matrix.update(CAPABILITY_MATRIX_NOTABLE_EVENTS)

        if not isinstance(CAPABILITY_MATRIX_MAINTENANCE_SERVICES, dict):
            message = _('Expecting a non-None dict for capability_matrix_maintenance_services')
            logger.error('%s %s', LOG_PREFIX, message)
            return False
        capability_matrix.update(CAPABILITY_MATRIX_MAINTENANCE_SERVICES)

        # Adding mod time
        capability_matrix["mod_time"] = get_current_utc_epoch()

        try:
            app_capabilities = UserAccess.get_app_capabilities(app_name, self.session_key, logger)
            success, data = UserAccess.store.single_update(
                store_name=STORE_NAME,
                record=capability_matrix,
                session_key=self.session_key,
                logger=logger, record_id=app_name)

        # Unable to find app
        except BadRequest:
            logger.info("%s has not registered its capabilities. Will try registering now.", app_name)
            success, data = UserAccess.store.create(
                store_name=STORE_NAME,
                record=capability_matrix,
                session_key=self.session_key,
                logger=logger, record_id=app_name)

        if success is True:
            logger.debug("Successfully registered capabilities for app %s. Response: %s", app_name, data)
        else:
            logger.error("Unable to register capabilities for app %s", app_name)
        return success

    def do_run(self, input_config):
        """
        Entry point for the modular input
        @type input_config: dict
        @param input_config: input configuration for this modular input
            input_config is a dictionary key'ed by the name of the modular input
            the configuration for this input is contained in the corresponding
            value
        """

        if not modular_input_should_run(self.session_key):
            logger.info("Will not run modular input on this node.")
            return

        LOG_PREFIX = "[ITSIUserAccessInit] [run] "
        logger.info("Starting: Input config=%s" % input_config)

        # input_config is a dictionary key'ed by the name of the modular input
        # the configuration for this input is contained in the corresponding value
        for stanza_name, stanza_data in input_config.iteritems():
            self.process_itsi_user_access(stanza_data)

        logger.debug("Finished: Input config=%s" % input_config)

    def process_itsi_user_access(self, config):

        LOG_PREFIX = "[ITSIUserAccessInit] [process_itsi_user_access] "
        app_name = config.get('app_name', 'itsi')

        kvstore = ITOAStorage()
        if kvstore.wait_for_storage_init(self.session_key):
            try:
                registered = self.register_app_capabilities(app_name)

            except Exception as e:
                logger.exception("Registration of capabilities failed")
                raise

            if not registered:
                logger.error('Unable to register capabilities "%s" for app %s We will try again.',
                    CAPABILITY_MATRIX, app_name)
                return


if __name__ == "__main__":
    worker = ITSIUserAccessInit()
    worker.execute()
    sys.exit(0)
