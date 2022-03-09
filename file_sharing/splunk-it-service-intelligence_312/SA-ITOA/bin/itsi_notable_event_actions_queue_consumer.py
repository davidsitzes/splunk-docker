# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Modular Input that is intended to run forever. It does the following: 
    1. Poll kvstore collection which is being populated by a Producer.
    2. Consume entries in the order in which they were received.
    3. Audit success/failure in the ITSI Audit Index.

"""
import sys
import uuid

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging
from itsi.event_management.itsi_notable_event_queue_consumer import ITSINotableEventActionsQueueConsumer

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', 'SA_ITOA_app_common']))
from solnlib.modular_input import ModularInput


class QueueConsumer(ModularInput):
    """
    Class that implements all the required steps. See method `do_run`.
    """

    title = _('IT Service Intelligence Actions Queue Consumer')
    description = _('Consumes producer data from KV Store and executes a Notable Event Action')
    app = 'SA-ITOA'
    name = 'itsi_notable_event_actions_queue_consumer'
    use_single_instance = False
    use_kvstore_checkpointer = False
    use_hec_event_writer = False

    def extra_arguments(self):
        return [
            {
                'name': 'exec_delay_time',
                'title': _('Execution delay time'),
                'description': _('Induce some delay (in seconds) in execution after reading'
                               ' from queue. Defaults to 0 seconds')
            },
            {
                'name': 'timeout',
                'title': _('timeout for given action'),
                'description': _('Time out value for action queue. Default timeout is 30 minutes'),
                'required_on_create': True,
                'required_on_edit': True
            },
            {
                'name': 'batch_size',
                'title': _('Batch size'),
                'description': _('Number of jobs to be claimed in one request. Default valiue is 5'),
                'required_on_create': True,
                'required_on_edit': True
            }
        ]

    def do_run(self, stanzas_config):
        """
        This is the method called by splunkd when mod input is enabled.
        @type stanzas_config: dict
        @param stanzas_config: input config for all stanzas passed down by
            splunkd.
        """
        logger = setup_logging('itsi_event_management.log', 'itsi.event_management.queue_consumer')

        stanza_name = stanzas_config.iterkeys().next()
        stanza_config = stanzas_config.itervalues().next()

        try:
            exec_delay_time = float(stanza_config.get('exec_delay_time', 0))
        except (TypeError, ValueError), e:
            exec_delay_time = 0  # default to '0' seconds

        ck = self.checkpointer
        key = stanza_name + 'id'
        modular_input_uuid = ck.get(key)

        if modular_input_uuid is None:
            modular_input_uuid = str(uuid.uuid1())
            # Save module id for this modular input so we can persist this id across splunk restart
            # we can't save in inputs.conf because it is being replicated on SHC
            ck.update(key, modular_input_uuid)

        logger.info('Starting queue consumer=%s, id=%s', stanza_name, modular_input_uuid)
        timeout = stanza_config.get('timeout', 1800)
        batch_count = stanza_config.get('batch_size', 5)
        try:
            logger.info('%s with configuration=%s has started consuming queue contents..', stanza_name, stanza_config)
            consumer = ITSINotableEventActionsQueueConsumer(self.session_key,
                                                            logger, exec_delay_time,
                                                            modular_input_uuid,
                                                            timeout, batch_count)
            consumer.consume_forever()
        except Exception as e:
            logger.exception('Encountered exception when consuming. "%s".', e)
            raise
        finally:
            logger.info('Shutting queue stanza=%s, it will resume on given interval', stanza_name)


if __name__ == "__main__":
    worker = QueueConsumer()
    worker.execute()
