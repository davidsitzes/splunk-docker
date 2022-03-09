# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import json
import splunk.rest as rest
import splunk
import re
import time
import logging
import urllib
import urllib2
import base64
import os.path
from .packages.solnlib import log
from .packages.solnlib import splunk_rest_client as rest_client
from .packages.solnlib.api_documenter import api, api_operation, api_response, api_path_param, api_body_param,\
  api_get_spec, api_model
from .packages.splunklib import binding

log.Logs.set_context(log_format='%(asctime)s %(levelname)s pid=%(process)d path=%(pathname)s:'
                                'file=%(filename)s:%(funcName)s:%(lineno)d | %(message)s')
logger = log.Logs().get_logger('apifilesave')
logger.setLevel(logging.INFO)


ALLOWED_MIMETYPES = {
    '.bmp': 'image/x-ms-bmp',
    '.gif': 'image/gif',
    '.ico': 'image/vnd.microsoft.icon',
    '.ief': 'image/ief',
    '.jpe': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.pbm': 'image/x-portable-bitmap',
    '.pgm': 'image/x-portable-graymap',
    '.png': 'image/png',
    '.pnm': 'image/x-portable-anymap',
    '.ppm': 'image/x-portable-pixmap',
    '.ras': 'image/x-cmu-raster',
    '.rgb': 'image/x-rgb',
    '.svg': 'image/svg+xml',
    '.tif': 'image/tiff',
    '.tiff': 'image/tiff',
    '.txt': 'text/plain',
    '.xbm': 'image/x-xbitmap',
    '.xpm': 'image/x-xpixmap',
    '.xwd': 'image/x-xwindowdump'
}

def validate_file_record(record):
    """
    Strictly validates the given file record data, checking conditions for data integrity and security

    :param record: The file record data
    :type record: dict

    :returns: returns the file record
    :rtype: dict
    """
    if not record or not isinstance(record, dict):
        raise ArgValidationException(400, 'Input is not valid.')

    acl = record.get('acl', None)
    if not acl or not isinstance(acl, dict):
        raise ArgValidationException(400, 'ACL is not valid.')

    # Remove invalid top-level fields from the record
    for key in record.keys():
        if key not in ['_key', 'name', 'type', 'data', 'acl', 'id']:
            record.pop(key, None)

    content_type = record.get('type', None)
    if content_type not in ALLOWED_MIMETYPES.values():
        raise ArgValidationException(400, 'Type is not valid')

    filename = record.get('name') or ''
    ext = os.path.splitext(filename)[1]
    if not filename or not filename.strip() or ext not in ALLOWED_MIMETYPES:
        raise ArgValidationException(400, 'Name is not valid')

    if ALLOWED_MIMETYPES.get(ext, None) != content_type:
        raise ArgValidationException(400, 'Name and Type do not match')

    content_data = record.get('data', None)
    if not content_data or not content_data.strip():
        raise ArgValidationException(400, 'Data is not valid')

    return record


class FilesaveRestHandler(rest.BaseRestHandler):
    @api()
    def __init__(self, *args, **kwargs):
        rest.BaseRestHandler.__init__(self, *args, **kwargs)
        self.context = ContextUtil.get_context(request=self.request,
                                               sessionKey=self.sessionKey,
                                               pathParts=self.pathParts)
        self.response.setHeader('Content-Type', 'application/json')
        # log.Logs.set_context(root_logger_log_file='apifilesave_{0}'.format(self.context['app']))

    @api_operation('get', 'Retrieving all records', 'get_all')
    @api_response(200, 'files', True)
    @api_operation('get', 'Getting single record by id')
    @api_path_param()
    @api_response(200, 'files')
    def handle_GET(self):
        if self.context['query'].get('spec'):
            response = str(api_get_spec(self.context, ['GET', 'PUT', 'POST', 'DELETE']))
            self.response.write(response)
        else:
            if self.context['id'] is None or '':
                res = self._get_svc().get_all()
                self.response.write(str(res))
            else:
                # TODO:: fix this and only get fields you need in first place.
                res = self._get_svc().get(self.context['id'])
                if res is not None:
                    r = json.loads(res)
                    name = r.get('name', None)
                    data = r.get('data', None)
                    content_type = r.get('type', None)

                    if self.context['action'] == 'download':
                        self.handle_download(r)
                    elif self.context['action'] is None:
                        if 'data' in r:
                            r.__delitem__('data')
                            res = json.dumps(r)
                            self.response.write(str(res))
                    else:
                        self.response.write(str(res))

    def handle_download(self, data):
        data = validate_file_record(data)

        validated_data = data['data']
        res = base64.b64decode(validated_data)

        validated_type = data['type']
        self.response.setHeader('Content-Type', validated_type)

        validated_name = data['name']
        ext = os.path.splitext(validated_name)[1]

        # _key should not be overridable by the user
        safe_filename = '{}{}'.format(data['_key'], ext)
        self.response.setHeader('Content-Disposition', 'attachment;filename={}'.format(safe_filename))

        self.response.write(str(res))

    @api_operation('put', 'Creating new Record', 'create')
    @api_body_param(False, 'files')
    @api_model(False, ['can_write'], 'acl', {'can_write': {'type': 'boolean'}, 'removable': {'type': 'boolean'},
                                             'sharing': {'type': 'string'},
               'can_list': {'type': 'boolean'}, 'can_share_app': {'type': 'boolean'}, 'owner': {'type': 'string'},
                                             'app': {'type': 'string'},
               'can_change_perms': {'type': 'boolean'}, 'perms': {'ref': 'perms'}})
    @api_model(False, ['name', 'id'], 'files', {'name': {'type': 'string'}, '_key': {'type': 'string'},
               'acl': {'$ref': 'acl'}, 'data': {'type': 'byte'}, 'type': {'type': 'string'}})
    @api_model(False, ['read', 'write'], 'perms', {'read': {'type': 'array', 'items': {'type': 'string'}}, 'write':
               {'type': 'array', 'items': {'type': 'string'}}})
    @api_response(200)
    def handle_PUT(self):
        response = self._get_svc().create(self.context['payload'])
        self.response.write(str(response))

    @api_operation('post', 'Updating single record by id', 'update')
    @api_body_param(False, 'files')
    @api_path_param()
    @api_response(200, 'files')
    def handle_POST(self):
        response = self._get_svc().update(self.context['id'], self.context['payload'])
        self.response.write(str(response))

    @api_operation('delete', 'Deleting single record by id')
    @api_path_param()
    @api_response(200)
    def handle_DELETE(self):
        self._get_svc().delete(self.context['id'])
        res = {"Deleted": "True"}
        self.response.write(str(json.dumps(res)))

    def _get_error(self, message, code=''):
        err = dict()
        err['error'] = message
        if code is not '':
            err['code'] = code
        self.response.write(str(err))

    def _get_svc(self):
        return ApifilesaveService(self.context['app'], self.context['session'],
                                  self.context['user'], self.context['collection'])


class ContextUtil(object):

    def __init__(self):
        pass

    @staticmethod
    def get_context(**kwargs):
        request = kwargs.get('request', None)
        session = kwargs.get('sessionKey', None)
        path = kwargs.get('pathParts', None)

        if not request:
            raise ArgValidationException(400, "Request is empty")

        """
        # API --> services/app/version/api/id/action
        # Required --> services, version, app, api
        # Optional --> id, action
        """
        path_keys = ['services', 'app', 'version', 'api', 'id', 'action']
        path_params = dict(zip(path_keys, path))

        context = dict()
        context['request'] = request
        context['user'] = request['userName']
        context['session'] = session
        context['app'] = path_params.get('app')
        context['api'] = path_params.get('api')
        context['collection'] = context['app'] + '_' + context['api']
        if request['payload']:
            context['payload'] = json.loads(request['payload'])
        else:
            context['payload'] = None
        context['id'] = path_params.get('id')
        context['action'] = path_params.get('action')
        context['version'] = path_params.get('version')
        context['query'] = request['query']
        context['headers'] = request['headers']

        return context


class BaseService(object):
    def __init__(self, app_name, session_id, user_name, collection_name):
        self.session_id = session_id
        self.app_name = app_name
        self.user_name = user_name
        self.collection_name = collection_name
        self.options = {'collection_name': collection_name, 'app': app_name, 'session_key': self.session_id}


class ApifilesaveService(BaseService):

    """
    init params
    """
    def __init__(self, *args, **kwargs):
        BaseService.__init__(self, *args, **kwargs)
        self.kv_client = KvStoreHandler(self.collection_name, self.session_id, self.app_name)

    def get_all(self):
        logger.info('Retrieving all records')
        return self.kv_client.get(None)

    def delete_all(self):
        logger.info('Deleting all records')
        return self.kv_client.bulk_delete()

    """
    Get a single record by id
    """
    def get(self, id):
        logger.info('Getting single record with id=%s', id)
        self._validate_id(id)
        return self.kv_client.get(id)

    """
    Create a new record
    """
    def create(self, data):
        logger.info('Creating new Record')
        data = validate_file_record(data)

        data["data"] = self.base64_data(data["data"])
        data['created_on'] = time.time()
        data['created_by'] = self.user_name
        data['metadata'] = dict()
        data['metadata']['version'] = ApifilesaveService._get_latest_version()

        _id = data.get('_key', None)
        if _id is not None and not isinstance(_id, basestring):
            raise ArgValidationException(400, "Id is not valid.")
        return self.kv_client.create(data, _id, True)

    """
    Update existing record by id
    """
    def update(self, id, data):
        logger.info('Updating single record with id=%s', id)
        self._validate_id(id)
        data = validate_file_record(data)

        get_response = self.get(id)
        if not get_response:
            raise FileSaveRestHandlerException(404, "Id not found.")

        res_data = json.loads(get_response)
        if data.get('data') is not None:
            data["data"] = self.base64_data(data.get('data'))
        for k, v in data.iteritems():
            if v is not None:
                res_data[k] = v
        res_data['updated_on'] = time.time()
        res_data['updated_by'] = self.user_name

        res_data['metadata'] = dict()
        res_data['metadata']['version'] = ApifilesaveService._get_latest_version()

        return self.kv_client.single_update(id, res_data, True)

    """
    Delete existing record by id
    """
    def delete(self, id):
        logger.info('Deleting single record with id=%s', id)
        self._validate_id(id)
        return self.kv_client.delete(id)

    def base64_data(self, file_data):
        data_uri_regex = re.compile(r"^data:.+;base64,")
        processed_file_data = re.sub(data_uri_regex, '', file_data)

        try:
            base64.b64decode(processed_file_data)
        except TypeError:
            raise ArgValidationException(400, "Data is not base64 encoded.")

        return processed_file_data

    def _validate_id(self, _id):
        if any([not isinstance(_id, basestring),
               (isinstance(_id, basestring) and not _id.strip())]):
            raise ArgValidationException(400, "Id not found.")

    @staticmethod
    def _get_versions():
        '''
        Returns all versions tuple in ascending order.
        :return: versions
        :rtype: ``tuple``
        '''
        files_object_versions = ('V1',)
        return files_object_versions

    @staticmethod
    def _get_latest_version():
        '''
        Returns latest version from tuple.
        :return: latest version (last version form versions tuple)
        :rtype: ``basestring``
        '''
        files_object_versions = ApifilesaveService._get_versions()
        count = len(files_object_versions)
        return files_object_versions[count - 1]


class KvStoreHandler(object):
    def __init__(self, collection_name, session_key, app, owner='nobody', **context):
        self._collection_data = self._get_collection_data(collection_name,
                                                          session_key, app, owner,
                                                          **context)

    def _get_collection_data(self, collection_name, session_key, app, owner, **context):
        kvstore = rest_client.SplunkRestClient(session_key,
                                               app,
                                               owner=owner,
                                               **context).kvstore

        try:
            kvstore.get(name=collection_name)
        except binding.HTTPError as e:
            raise KVNotExists(404, 'Collection not exists')

        collections = kvstore.list(search=collection_name)
        for collection in collections:
            if collection.name == collection_name:
                return collection.data
        else:
            raise KVNotExists(404, 'Collection not exists')

    def create(self, record, record_id, include_ts=False):
        if record_id:
            record['_key'] = record_id

        if include_ts:
            record['_time'] = time.time()

        ret = self._collection_data.insert(json.dumps(record))
        return json.dumps(ret)

    def get(self, key):
        '''Issue a simple KV store query by key. If key is empty, all records
        will be returned.'''

        if key is None:
            key = ''
        record = self._collection_data.query_by_id(key)
        return json.dumps(record)

    def delete(self, key):
        '''Issue a simple KV store record deletion by key,
            <tt>if key is not None and len(key) > 0</tt>.'''

        if key and isinstance(key, basestring):
            self._collection_data.delete_by_id(key)

        return

    def bulk_delete(self):
        '''Deletes all the records that exist within the collection'''
        return self._collection_data.delete()

    def query(self, json_query, delete=False):
        '''Issue a complex KV store query. The query string is constructed
        from a valid JSON object. <tt>if delete is True and
        isinstance(json_query, dict) and len(json_query) > 0</tt>, all
        records returned by this query are deleted.'''

        # Note, there is currently a bug with this urllib2.quote where
        # the query won't run properly because you encode the url
        # removing the urllib2.quote part should fix but it requires more testing
        q = urllib2.quote(json.dumps(json_query))

        if delete and q:
            return self._collection_data.delete(q)
        else:
            return self._collection_data.query(q)

    def adv_query(self, getargs):
        '''Issue a MORE complex KV store query. The query string is constructed
        from a valid JSON object. Additional parameters such as "limit" can be
        included in the query_options dictionary.

        The allowable_params are: 'fields', 'limit', 'skip', 'sort', 'query'
        '''

        options = {}

        for k, v in getargs.iteritems():
            if k == 'query':
                options['query'] = json.dumps(v)
            elif k == 'fields':
                if isinstance(v, basestring):
                    options['fields'] = v
                elif isinstance(v, list):
                    options['fields'] = ','.join(v)
                else:
                    raise ValueError('Invalid value for fields parameter in KV store query.')
            elif k in ['limit', 'skip']:
                # May raise ValueError
                options[k] = str(int(v))
            elif k == 'sort':
                # Since sort order can be a bit complex, we just expect the
                # consumer to construct their own sort string here.
                if isinstance(v, basestring):
                    options['sort'] = v
                else:
                    raise ValueError('Invalid value for sort parameter in KV store query.')
            else:
                # Invalid parameter is ignored.
                pass

        params = urllib.urlencode(options)
        return self.query(params, False)

    def single_update(self, id, record, include_ts=False):
        # Caller is responsible for ensuring that the input IS NOT an array.
        if include_ts:
            record['_time'] = time.time()

        ret = self._collection_data.update(id, json.dumps(record))
        return json.dumps(ret)

    def batch_update(self, records, include_ts=False):
        for record in records:
            if include_ts:
                record['_time'] = time.time()

        self._collection_data.batch_save(records)

    def batch_create(self, records, include_ts=False):
        for record in records:
            if include_ts:
                record['_time'] = time.time()

        self._collection_data.batch_save(records)


class FileSaveRestHandlerException(splunk.RESTException):
    def __init__(self, status_code, msg):
        splunk.RESTException.__init__(self, status_code, msg)


class ArgValidationException(FileSaveRestHandlerException):
    pass


class KVNotExists(FileSaveRestHandlerException):
    pass
