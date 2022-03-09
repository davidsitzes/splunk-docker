# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import json

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.setup_logging import setup_logging
from itsi.event_management.sdk.custom_event_action_base import CustomEventActionBase
from ITOA.event_management.notable_event_ticketing import ExternalTicket


class LinkTicket(CustomEventActionBase):
	"""
	Class that performs Link Ticket action on notable events.
	
	Until 2.6.x, link ticket was handled via SA-ITOA event management
	rest interface for ticketing.
	Post 2.6.x, link ticket will be handled as a real alert action,
	where this script will act as an link ticket action script 
	for alerts.
	"""

	TICKET_SYSTEM_KEY = 'ticket_system'
	TICKET_ID_KEY = 'ticket_id'
	TICKET_URL_KEY = 'ticket_url'
	TICKET_OPERATION_KEY = 'operation'
	TICKET_KWARGS_KEY = 'kwargs'

	def __init__(self, settings):
		"""
		Initialize the object
		@type settings: dict/basestring
		@param settings: incoming settings for this alert action that splunkd
			passes via stdin.

		@returns Nothing
		"""
		self.logger = setup_logging("itsi_event_management.log", "itsi.event_action.link_ticket")

		super(LinkTicket, self).__init__(settings, self.logger)

		self.ticket_system = None
		self.ticket_id = None
		self.ticket_url = None
		self.ticket_operation = None
		self.kwargs = {}

	def get_ticket_info(self):
		"""
		Gets ticketing information from configs and
		sets class variables.
		"""
		config = self.get_config()
		self.ticket_system = config.get(self.TICKET_SYSTEM_KEY, None)
		self.ticket_id = config.get(self.TICKET_ID_KEY, None)
		self.ticket_url = config.get(self.TICKET_URL_KEY, None)
		self.ticket_operation = config.get(self.TICKET_OPERATION_KEY, None)

		temp = config.get(self.TICKET_KWARGS_KEY, None)
		if temp is not None and len(temp.strip()) != 0:
			try:
				self.kwargs = json.loads(temp)
			except Exception as e:
				self.logger.error('Invalid kwargs provided for creating ticket. Exception: %s', e)
				sys.exit(1)

	def upsert_ticket(self, events):
		"""
		Updates/creates ticket for single or multiple events 
		using ExternalTicket module.
		
		@param events: list of event ids
		"""
		session_key = self.get_session_key()
		if len(events) == 1:
			external_ticket = ExternalTicket(events[0], session_key, self.logger)
			external_ticket.upsert(self.ticket_system, self.ticket_id, self.ticket_url, **self.kwargs)
		elif len(events) > 1:
			ExternalTicket.bulk_upsert(events, self.ticket_system, self.ticket_id, self.ticket_url,
										session_key, self.logger, **self.kwargs)
		else:
			self.logger.info("No associated events to upsert ticket.")

	def delete_ticket(self, events):
		"""
		Deletes ticket for single event using ExternalTicket module.
		@param event_id: id of event
		"""
		session_key = self.get_session_key()
		if len(events) == 1:
			external_ticket = ExternalTicket(events[0], session_key, self.logger)
			external_ticket.delete(self.ticket_system, self.ticket_id)
		elif len(events) > 1:
			ExternalTicket.bulk_delete(events, self.ticket_system, self.ticket_id, session_key, self.logger)
		else:
			self.logger.info("No associated events to delete ticket.")

	def execute(self):
		"""
		Performs two types of ticketing action, create/update and delete.
		1. create/update ticket: fetches events from result file and perform
		create/update ticket for each event.
		2. delete ticket: fetches event from result file and performs delete
		ticket for single event.
		"""
		self.logger.debug('Received settings from splunkd=`%s`', json.dumps(self.settings))

		try:
			self.get_ticket_info()

			if self.ticket_operation == 'upsert':
				if self.ticket_system is None:
					self.logger.error('Ticket System must be defined to create or update ticket.')
					sys.exit(1)
				if self.ticket_url is None:
					self.logger.error('Ticket URL must be defined to create or update ticket.')
					sys.exit(1)
				if self.ticket_id is None:
					self.logger.error('Ticket ID must be defined to create or update ticket.')
					sys.exit(1)

				events = []
				for data in self.get_event():
					event_id = self.extract_event_id(data)
					events.append(event_id)

				self.upsert_ticket(events)

			elif self.ticket_operation == 'delete':
				if self.ticket_system is None:
					self.logger.error('Ticket System must be provided to delete ticket.')
					sys.exit(1)
				if self.ticket_id is None:
					self.logger.error('Ticket ID must be provided to delete ticket.')
					sys.exit(1)

				# assuming, delete ticket is only applicable for single event
				events = []
				for data in self.get_event():
					event_id = self.extract_event_id(data)
					events.append(event_id)
				self.delete_ticket(events)

		except ValueError, e:
			pass  # best case, try every event.

		except Exception, e:
			self.logger.error('Failed to execute link ticket action.')
			self.logger.exception(e)
			sys.exit(1)

if __name__ == "__main__":
	if len(sys.argv) > 1 and sys.argv[1] == '--execute':
		input_params = sys.stdin.read()
		link_ticket = LinkTicket(input_params)
		link_ticket.execute()
