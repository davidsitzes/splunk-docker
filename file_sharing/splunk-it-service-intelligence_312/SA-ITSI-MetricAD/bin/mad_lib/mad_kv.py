import json
import requests
import logging
import sys

from mad_util import MADRESTException
from mad_splunk_util import setup_logging, get_conf_stanza

logger = setup_logging('mad_rest.log', 'mad_rest', level=logging.DEBUG)

KV_STORE_PATH = "storage/collections/data"


class MADKVStoreManager(object):

    # Per http://docs.splunk.com/Documentation/Splunk/6.5.0/RESTREF/RESTkvstore#Limits, 16 MB is max limit for document
    # size in KV store and non-configurable
    _max_document_size_limit_bytes = 16777216  # 16 * 1024 * 1024 = 16 MB

    # Per http://docs.splunk.com/Documentation/Splunk/6.5.0/RESTREF/RESTkvstore#Limits,
    # the max size per batch save in MB is set in the kvstore stanza in the limits.conf
    # file with the name max_size_per_batch_save_mb
    _max_size_per_batch_save = None

    _max_documents_per_batch_save = None

    def __init__(self, host_path, app_id, session_key):
        self.default_request_options = {
            "headers": {
                'Authorization': 'Splunk %s' % session_key,
                "Content-Type": "application/json"
            },
            "verify": False
        }
        self.kv_uri_base = "/".join([host_path, "nobody", app_id, KV_STORE_PATH])
        self.kv_uri_default_params = ["output_mode=json"]
        self._save_ranges = []
        self.session_key = session_key

    def _deserialize_json(self, json_str):
        try:
            if not json_str:
                return None
            else:
                return json.loads(json_str)
        except Exception:
            err_msg = "Unable to deserialize json, possible corrupted result from kvstore\n%s" % json_str
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=500)

    def _handle_response(self, r):
        if 200 <= r.status_code < 300:
            return self._deserialize_json(r.text)
        else:
            raise MADRESTException(r.text, logging.ERROR, r.status_code)

    def _get_kv_url(self, url_extra, params_extra=None):
        if params_extra is None:
            params_extra = []
        full_url = "/".join([self.kv_uri_base] + url_extra) + "?" + "&".join(params_extra + self.kv_uri_default_params)
        logger.debug("kv url is : " + full_url)
        return full_url

    def _get_request_options(self, options_extra):
        options_extra.update(self.default_request_options)
        return options_extra

    def _set_batch_save_size_limit(self):
        """
        Fetches the max size per batch save if not already fetched
        """
        # Sets static variables from limits conf file if not already set
        try:
            if self._max_size_per_batch_save is None or self._max_documents_per_batch_save is None:
                resp, cont = get_conf_stanza(self.session_key, 'limits', 'kvstore')
                entries = cont.get('entry')
                max_mb = False
                max_doc = False
                for entry in entries:
                    if entry.get('name') == 'max_size_per_batch_save_mb':
                        self._max_size_per_batch_save = int(entry.get('content', 50)) * 1024 * 1024
                        max_mb = True
                    if entry.get('name') == 'max_documents_per_batch_save':
                        self._max_documents_per_batch_save = int(entry.get('content', 1000))
                        max_doc = True
                    if max_mb and max_doc:
                        break
        except Exception as e:
            err_msg = 'Error while fetching max_size_per_batch_save for kvstore ' \
                      'from limits.conf. Error is: {0}'.format(e)
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=500)

    def check_payload_size(self, data_list, throw_on_violation=True):
        """
        Method to verify KV store payload size is'nt larger than 16MB limit of per document size

        @type: list
        @param data_list: JSON list payload to verify

        @type: boolean
        @param throw_on_violation: True if violation should trigger exception, else returns bool indicating
            if violation detected

        @rtype: tuple (boolean, integer)
        @return: (True, -1) if no violation detected, (False, size causing violation in bytes) if violation detected
        """
        if not isinstance(data_list, list):
            raise MADRESTException('JSON payload is invalid.')

        self._set_batch_save_size_limit()

        self._save_ranges = []

        cur_size = 0
        first_index = 0
        for idx, data in enumerate(data_list):
            size_of_payload = sys.getsizeof(str(data))
            if size_of_payload > self._max_document_size_limit_bytes:
                if throw_on_violation:
                    raise MADRESTException(
                        'Object you are trying to save is too large (%s bytes). KV store only supports '
                        'documents within 16MB sizes.' % size_of_payload,
                        logging.ERROR,
                        status_code=500
                    )
                else:
                    # Return False indicating violation even if one object violates limits
                    return False, size_of_payload
            cur_size += size_of_payload
            # Check to see if you have reached the max batch save size
            # limit in the current index that you are looking at
            if cur_size >= self._max_size_per_batch_save or (idx - first_index) >= self._max_documents_per_batch_save:
                self._save_ranges.append((first_index, idx))
                first_index = idx
                cur_size = size_of_payload
        self._save_ranges.append((first_index, len(data_list)))

        return True, -1

    def get_all(self, collection_name, params):
        try:
            r = requests.get(self._get_kv_url([collection_name]), **self._get_request_options({"params": params}))
        except Exception as e:
            raise MADRESTException(str(e), logging.ERROR, status_code=500)

        return self._handle_response(r)

    def get(self, collection_name, entity_id, params):
        try:
            r = requests.get(self._get_kv_url([collection_name, entity_id]), **self._get_request_options({"params": params}))
        except Exception as e:
            logging.exception(e.message)
            raise MADRESTException(str(e), logging.ERROR, status_code=500)
        return self._handle_response(r)

    def create(self, collection_name, data):
        try:
            r = requests.post(self._get_kv_url([collection_name]), **self._get_request_options({"data": json.dumps(data)}))
        except Exception as e:
            logging.exception(e.message)
            raise MADRESTException(str(e), logging.ERROR, status_code=500)
        return self._handle_response(r)

    def create_bulk(self, collection_name, data):
        self.check_payload_size(data)

        parsed_contents = []
        for data_range in self._save_ranges:
            data_chunk = json.dumps(data[data_range[0]:data_range[1]])
            parsed_contents.extend(self._execute_batch_save_request(collection_name, data_chunk))
        self._save_ranges = []

        return parsed_contents

    def _execute_batch_save_request(self, collection_name, data):
        try:
            resp = requests.post(self._get_kv_url([collection_name, 'batch_save']),
                                 **self._get_request_options({'data': data}))
        except Exception as e:
            logger.exception(e.message)
            raise MADRESTException(str(e), logging.ERROR, status_code=500)

        return self._handle_response(resp)

    def update(self, collection_name, entity_id, data):
        try:
            r = requests.post(self._get_kv_url([collection_name, entity_id]), **self._get_request_options({"data": json.dumps(data)}))
        except Exception as e:
            logging.exception(e.message)
            raise MADRESTException(str(e), logging.ERROR, status_code=500)
        return self._handle_response(r)

    def delete(self, collection_name, entity_id):
        try:
            r = requests.delete(self._get_kv_url([collection_name, entity_id]), **self.default_request_options)
        except Exception as e:
            logging.exception(e.message)
            raise MADRESTException(str(e), logging.ERROR, status_code=500)
        return self._handle_response(r)
