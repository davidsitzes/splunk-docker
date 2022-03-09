# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import os
import os.path
import re
import shutil
import sys
import json
import traceback
try:
	from cStringIO import StringIO
except:
	from StringIO import StringIO

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.controller_utils import (
	ITOAError,
	check_object_update_allowed
)

# try:  # noqa: F401
#	 from typing import Iterator, Sequence, Dict, List, Text, Type, Any, Optional, Union, Callable, Tuple, Generator  # noqa: F401
#	 from itsi.csv_import.itoa_bulk_import_preview_utils import ServicePreviewer, EntityPreviewer  # noqa: F401
# except:  # noqa: F401
#	 pass  # noqa: F401

from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from itsi.csv_import import CSVLoaderError, CSVLoaderBadReq, BulkImporter
from itsi.csv_import.itoa_bulk_import_common import logger, set_transaction, spool_dirloc, spool_fileloc, ImportConfig
from itsi.csv_import.itoa_bulk_import_preview_utils import build_reader, DEFAULT_PREVIEW_SAMPLE_LIMIT

DEFAULT_ASYNCHRONOUS_THRESHOLD = 100

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))

logger.debug('Initialized itoa bulk import interface provider log')

BUFFER_SPARE = 4096


def generate_previews(fileloc, limit, source='the CSV file'):
	# type: (Text, int, Text) -> Dict[Text, Any]
	no_data_warning = _('No or insufficient data found. Please check {} and try again.').format(source)

	with open(fileloc, 'rbU') as csvfile:
		reader = build_reader(csvfile)
		try:
			headers = reader.next()
		except StopIteration:
			raise ITOAError(status=400, message=no_data_warning)

	# Pass one: get the full length of the file, with offsets recorded.
	count = 0
	checkpoints = []
	with open(fileloc, 'rbU') as csvfile:
		offsets = 0
		for (count, line) in enumerate(csvfile):
			if (count % limit == 0):
				checkpoints.append((count, offsets))
			offsets = offsets + len(line)

	# '2' is acceptable: header plus one line of data.  enumerate's count starts at zero.
	if count < 1:
		raise ITOAError(status=400, message=no_data_warning)

	# Pass two: Only read in the preview.
	preview = []  # type: List[List[Text]]
	with open(fileloc, 'rbU') as csvfile:
		reader = build_reader(csvfile)
		dummy = reader.next()  # noqa: F841  skip header; we've already recorded it and are discarding it.
		for (c, row) in enumerate(reader):
			if c >= limit:
				break
			preview.append(row)

	# No middle or end.  Why '3'?  If your limit is 100, and you have 101 entries, you
	# will have two checkpoints, but it makes no sense to show them, as they overlap
	# 99.0099% of their entries.
	if len(checkpoints) < 3:
		return {
			'preview_length': count,
			'headers': headers,
			'preview_data_blocks': {
				'top': preview
			}
		}

	# Pass three: Read in a preview from the end of the file.
	end_preview = []  # type: List[List[Text]]
	with open(fileloc, 'rbU') as csvfile:
		position = checkpoints[int(len(checkpoints)) - 2][1]
		csvfile.seek(position)
		datafile = StringIO(csvfile.read())
		end_preview = list(build_reader(datafile))
		end_preview = end_preview[(-1 * limit):]

	# No middle
	if len(checkpoints) < 4:
		return {
			'preview_length': count,
			'headers': headers,
			'preview_data_blocks': {
				'top': preview,
				'middle': [],
				'middle_position': -1,
				'end': end_preview,
				'end_position': count - limit
			}
		}

	# Pass four: Read in a preview from the middle of the file.
	middle_preview = []  # type: List[List[Text]]
	midpoint = int(len(checkpoints) / 2) - 1
	with open(fileloc, 'rbU') as csvfile:
		position = checkpoints[midpoint][1]
		readsize = checkpoints[midpoint + 1][1] - position
		csvfile.seek(position)
		datafile = StringIO(csvfile.read(readsize + BUFFER_SPARE))
		reader = build_reader(datafile)
		reader.next()
		for (c, row) in enumerate(reader):
			if c >= limit:
				break
			middle_preview.append(row)

	return {
		'preview_length': count,
		'headers': headers,
		'preview_data_blocks': {
			'top': preview,
			'middle': middle_preview,
			'middle_position': checkpoints[midpoint][0],
			'end': end_preview,
			'end_position': count - limit
		}
	}


class ItsiBulkImportInterfaceProvider(ItoaInterfaceProviderBase):
	def _confirm_action(self, action_name, expected_name):
		# type: (Text, Text) -> None
		if action_name != expected_name:
			raise ITOAError(status='500', message=_('Unsupported HTTP action'))

	def _confirm_method(self, expected_methods):
		# type: (List[Text]) -> None
		if self._rest_method not in expected_methods:
			message = _('Unsupported HTTP method "{}"').format(self._rest_method)
			logger.error('csv_upload failed: {}'.format(message))
			raise ITOAError(status='501', message=message)

	def _confirm_keys(self, kwargs, keys=[]):
		# type: (Dict[Text, Any], List[Text]) -> None
		missing_keys = [key for key in keys if key not in kwargs]
		if missing_keys:
			message = _('Missing key(s) in data sent to server "{}"').format(", ".join(missing_keys))
			logger.error('csv_upload failed: {}'.format(message))
			raise ITOAError(status='400', message=message)

	def _confirm_contract(self, action, expected_action, expected_methods, kwargs, keys):
		# type: (Text, Text, List[Text], Dict[Text, Any], List[Text]) -> None
		self._confirm_action(action, expected_action)
		self._confirm_method(expected_methods)
		self._confirm_keys(kwargs, keys)

	def _csv_upload(self, transaction_id, fileobj, **kwargs):
		# type: (Text, file, **Any) -> Text
		"""
		Given a file handle and a transaction_id, store the contents of the file handle to
		a local spool directory.
		"""
		set_transaction(transaction_id)
		check_object_update_allowed(self._session_key, logger)
		import_config = ImportConfig(self._session_key)
		limit = kwargs.get('preview_size', import_config.get('preview_sample_limit', DEFAULT_PREVIEW_SAMPLE_LIMIT))

		regex = re.compile(r'^[A-Za-z0-9-]+$')
		if not regex.match(transaction_id):
			error_msg = _('Transaction id provided contains characters not supported.')
			logger.error(error_msg)
			raise ITOAError(status='400', message=error_msg)

		try:

			dirloc = spool_dirloc()
			fileloc = spool_fileloc('csv_import_{}.csv'.format(transaction_id))

			if not os.path.exists(dirloc):
				os.makedirs(dirloc)
			with open(fileloc, 'wb') as f:
				shutil.copyfileobj(fileobj, f)
			csvdata = generate_previews(fileloc, limit)
			duplication_check = {}
			dupcolumns = set()
			for header in csvdata['headers']:
				if header in duplication_check:
					dupcolumns.add(header)
					duplication_check[header] += 1
				else:
					duplication_check[header] = 1
			if len(duplication_check) != len(csvdata['headers']):
				error_message = _('The following column names are duplicated: {}. Change the column names and try again.').format(','.join(dupcolumns))
				raise ITOAError(status='400', message=error_message)
			return self.render_json(csvdata)



		# ITOA Errors have already been handled; re-raise them up to the main handler.
		except ITOAError as e:
			logger.exception(e)
			raise

		except UnicodeDecodeError as e:
			raise ITOAError(status='400', message=_('The file is not in ASCII or UTF format.  Encoding not detected.  Please review the CSV file.'))

		except Exception as e:
			logger.info('Exception ' + str(traceback.format_exc()))
			msg = getattr(e, 'message', None) or getattr(e, 'msg', None) or str(e)
			logger.exception('csv_upload failed: {}', msg)
			raise ITOAError(status='500', message=_('CSV Upload failure.  Please see the logs for more detail.'))

	def _csv_from_search(self, transaction_id, search_string, index_earliest, index_latest, **kwargs):
		# type (Text, Text) -> Text
		"""
		Loads entities/services from a search string into a spooled file.
		# @param transaction_id: A unique key for this transaction
		# @param search: the search string
		"""
		set_transaction(transaction_id)
		check_object_update_allowed(self._session_key, logger)

		regex = re.compile(r'^[A-Za-z0-9-]+$')
		if not regex.match(transaction_id):
			error_msg = _('Transaction id provided contains characters not supported.')
			logger.error(error_msg)
			raise ITOAError(status='400', message=error_msg)

		dirloc = spool_dirloc()
		fileloc = spool_fileloc('csv_import_{}.csv'.format(transaction_id))

		search_string = search_string.strip()
		if (len(search_string) > 1) and not (search_string[0] == '|'):
			search_string = 'search {}'.format(search_string)

		import_config = ImportConfig(self._session_key)
		limit = kwargs.get('preview_size', import_config.get('preview_sample_limit', DEFAULT_PREVIEW_SAMPLE_LIMIT))

		params = {
			'search': search_string,
			'output_mode': 'json',
			'earliest_time': index_earliest,
			'latest_time': index_latest,
			'count': 0
		}

		try:
			if not os.path.exists(dirloc):
				os.makedirs(dirloc)

			path = '/servicesNS/nobody/{}/search/jobs'.format('SA-ITOA')
			response, content_in_json = rest.simpleRequest(
				path,
				sessionKey=self._session_key,
				method='POST',
				postargs=params)

			if response['status'].strip() != '201':
				message = _('Unable to reach Splunkd.')
				if isinstance(content_in_json, basestring):
					try:
						content = json.loads(content_in_json)
						print content
						if content and 'messages' in content and content['messages']:
							message = _('Message from splunkd: {}').format(content['messages'][0]['text'])
					except:
						pass  # Wasn't JSON.
				raise ITOAError(status='400', message=_('The search job was not started.  {}').format(message))

			content = json.loads(content_in_json)
			sid = content['sid']  # search id

			path = '/servicesNS/nobody/{}/search/jobs/{}'.format('SA-ITOA', sid)
			while True:
				response, content_as_json = rest.simpleRequest(
					path,
					sessionKey=self._session_key,
					method='GET',
					getargs=params)

				if response['status'].strip() != '200':
					msg = _('Search failed. If this persists, please reach out to support. '
							'Search Error - {}').format(response)
					raise ITOAError(status="500", message=msg)

				content = json.loads(content_as_json)

				if content['entry'][0]['content']['isFailed']:
					msg = _('Error while trying to fetch search results. The search may have failed. '
						   'If this persists, please reach out to support.')
					raise ITOAError(status='500', message=msg)

				if content['entry'][0]['content']['isDone']:
					logger.debug('Done running search. Serializing found entities and/or services.')
					break

			results_path = content['entry'][0]['links']['results']

			params = {
				'output_mode': 'csv',
				'count': 0
			}

			try:
				connection = rest.streamingRequest(
					results_path,
					sessionKey=self._session_key,
					method='GET',
					getargs=params)
			except Exception as e:
				msg = getattr(e, 'message', None) or getattr(e, 'msg', None) or str(e)
				msg = (('Error while trying to fetch search results. The search may have failed. '
						'If this persists, please reach out to support. '
						'Search Error - {}, Search - {}').format(msg, search_string))
				raise ITOAError(status='500', message=msg)

			if response['status'].strip() != '200':
				raise ITOAError(status='500', message=msg)

			with open(fileloc, 'wb') as f:
				for content in connection.readall():
					f.write(content)

			return self.render_json(generate_previews(fileloc, limit, 'your search string'))

		except ITOAError as e:
			logger.exception(traceback.format_exc())
			raise

		except Exception as e:
			message = getattr(e, 'message', None) or getattr(e, 'msg', None) or str(e)
			logger.error('load_csv failed with: %s', message)
			logger.exception(traceback.format_exc())
			raise ITOAError(status='500', message=message)

	def _csv_object_preview(self, transaction_id, bulk_import_spec, owner, Previewer):
		# type: (Text, Dict[Text, Any], Text, Union[ServicePreviewer, EntityPreviewer]) -> Text
		set_transaction(transaction_id)
		check_object_update_allowed(self._session_key, logger)

		try:
			dirloc = spool_dirloc()
			fileloc = spool_fileloc('csv_import_{}.csv'.format(transaction_id))

			if not (os.path.isdir(dirloc) and os.path.isfile(fileloc)):
				message = _('Uploaded data not found')
				logger.error('{} failed with: {}'.format(Previewer.action, message))
				raise ITOAError(status='404', message=message)

			with open(fileloc, 'rbU') as csvfile:
				preview = Previewer(bulk_import_spec, self._session_key, self._current_user, owner)
				reader = build_reader(csvfile)
				return self.render_json(preview(reader, transaction_id))

		# ITOA Errors have already been handled; re-raise them up to the main handler.
		except ITOAError as e:
			logger.exception(e)
			raise

		except CSVLoaderBadReq as e:
			logger.exception(e)
			raise ITOAError(status=400, message=e.message)

		except CSVLoaderError as e:
			logger.exception(e)
			raise ITOAError(status=500, message=e.message)

		except Exception as e:
			msg = getattr(e, 'message', None) or getattr(e, 'msg', None) or str(e)
			logger.exception('preview failed with: {}', msg)
			raise ITOAError(status='500', message=_('Failed to preview CSV data.  Please see the logs for more detail. {}').format(msg))

	def _csv_commit_upload(self, transaction_id, bulk_import_spec, owner):
		# type: (Text, Dict[Text, Any], Text) -> Text

		set_transaction(transaction_id)
		import_config = ImportConfig(self._session_key)
		async_threshold = import_config.get('asynchronous_processing_threshold', DEFAULT_ASYNCHRONOUS_THRESHOLD)

		def need_async(fileloc):
			# type: (str) -> bool
			with open(csvfileloc, 'rbU') as csvfile:
				for (count, _) in enumerate(csvfile):
					if count > async_threshold:
						return True
			return False

		try:
			dirloc = spool_dirloc()
			csvfileloc = spool_fileloc('csv_import_{}.csv'.format(transaction_id))

			if not (os.path.isdir(dirloc) and os.path.isfile(csvfileloc)):
				message = _('Uploaded data was not found')
				logger.error(message)
				raise ITOAError(status='404', message=message)

			bulk_importer = BulkImporter(bulk_import_spec, self._session_key, self._current_user, owner)

			def async_save():
				# type: () -> Dict[Text, Any]
				# Write the configuration to the spool directory, which will cause the mod_input module
				# for one-shot large file uploads to start running.
				metafileloc = spool_fileloc('meta_{}.conf'.format(transaction_id))
				if not (os.path.isdir(dirloc) and os.path.isfile(csvfileloc)):
					message = _('Uploaded data was not found')
					logger.error(message)
					raise ITOAError(status='404', message=message)

				specification = bulk_importer.import_specification.toConf({'transaction_id': transaction_id})
				with open(metafileloc + '-tmp', 'wb') as configfile:
					specification.write(configfile)
				os.rename(metafileloc + '-tmp', metafileloc)
				return {'success': True, 'mode': 'async'}  # type: Dict[Text, Any]

			def sync_save():
				# type: () -> Dict[Text, Any]
				# Save the file directly.
				message = {'success': True, 'mode': 'sync'}  # type: Dict[Text, Any]
				with open(csvfileloc, 'rbU') as csvfile:
					result = bulk_importer.bulk_import(build_reader(csvfile), transaction_id)
					message.update(result)
				os.remove(csvfileloc)  # Synchronous save; cleaning up after ourselves.
				return message

			if need_async(csvfileloc):
				return self.render_json(async_save())
			else:
				return self.render_json(sync_save())

		except ITOAError as e:
			logger.exception(e)
			raise

		except CSVLoaderBadReq as e:
			logger.exception(e)
			raise ITOAError(status=400, message=e.message)

		except CSVLoaderError as e:
			logger.exception(e)
			raise ITOAError(status=500, message=e.message)

		except Exception as e:
			msg = getattr(e, 'message', None) or getattr(e, 'msg', None) or str(e)
			logger.exception('commit failed with: {}', msg)
			raise ITOAError(status='500', message=msg)
