# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import json
import splunk
import splunk.rest as rest
import logging
import time
from .packages.solnlib import log
from .packages.splunklib import binding
from .packages.solnlib import splunk_rest_client as rest_client

from .packages.solnlib.api_documenter import api, api_operation, api_response, api_path_param,\
  api_body_param, api_get_spec, api_query_param

log.Logs.set_context(log_format='%(asctime)s %(levelname)s %(message)s',
                     root_logger_log_file='gt_icon_collection')
logger = log.Logs().get_logger('gt_icon_collection')
logger.setLevel(logging.INFO)


"""
IconCollectionRestHandler
"""


class IconCollectionRestHandler(rest.BaseRestHandler):

    '''
    Class for handling icon objects.
    '''
    @api()
    def __init__(self, *args, **kwargs):
        '''
        Initialize IconCollectionRestHandler and rest.BaseRestHandler
        Initialize context instance.
        Set default response headers.
        :param args: from BaseRestHandlers
        :param kwargs: from BaseRestHandlers
        '''
        rest.BaseRestHandler.__init__(self, *args, **kwargs)
        self.context = ContextUtil.get_context(request=self.request,
                                               sessionKey=self.sessionKey,
                                               pathParts=self.pathParts)

        self.response.setHeader('Content-Type', 'application/json')

    @api_operation('get', 'Returns all/matched icons.', 'get_all')
    @api_query_param(['sort_key', 'sort_dir', 'limit', 'offset', 'fields', 'filter', 'shared'])
    @api_response(200, 'IconCollection', True)
    @api_operation('get', 'Returns icon object by id')
    @api_path_param()
    @api_response(200, 'IconCollection')
    def handle_GET(self):
        '''
        If id present, it returns the specific icon by id, else it returns multiple icons list.
        :param id: (optional) returns icon by id.
        :type: ``basestring``
        :param id: (optional) list_categories.
        :type: ``bool`` if set, returns a list of distinct categories
        :params query: (optional) dict for icons search (i.e. sort, limit etc..)
        :return: writes to response object.
        '''
        
        spec = self.context['query'].get('spec')
        list_categories = self.context['query'].get('list_categories')
        category = self.context['query'].get('category')

        if spec:   # TODO: figure out how this works
            response = str(api_get_spec(self.context, ['GET', 'PUT', 'POST', 'DELETE']))

        elif list_categories:
            response = self._get_svc().get_categories()

        elif category:
            response = self._get_svc().get_category_icons(self.context['query'])

        else:
            if not self.context['id']:
                response = self._get_svc().get_all(self.context['query'])
            else:
                response = self._get_svc().get(self.context['id'])
            
        self.response.write(str(response))

    @api_operation('put', 'Creates a new icon', 'create')
    @api_body_param(True, 'IconCollection')
    @api_response(200, 'IconCollection')
    def handle_PUT(self):
        '''
        Creates the Icon record in KV.
        :param: dict payload icon object.
        :type: ``dict``
        :return: id of created icon
        :rtype: ``basestring``
        '''
        response = self._get_svc().create(self.context['payload'])
        self.response.write(str(json.dumps(response)))

    @api_operation('post', 'Updates icons by id or in bulk', 'update')
    @api_body_param(True, 'IconCollection')
    @api_path_param()
    @api_response(200, 'IconCollection')
    def handle_POST(self):
        '''
        Updates icon object by id.
        :param: id of icon from path.
        :param: payload of updated icon object.
        :param: category selects icons by category
        :param: new_category sets new category for those icons
        :return: id of saved icon
        :rtype: ``basestring``
        '''
        response = ''
        if self.context['id']:
            response = self._get_svc().update(self.context['id'], self.context['payload'])
        elif self.context['payload']:
            payload = self.context['payload']
            category = payload.get('category')
            new_category = payload.get('new_category')
            if category and new_category:
                response = self._get_svc().bulk_update_category(category, new_category)

        self.response.write(str(response))

    @api_operation('delete', 'Deletes the icon object by id')
    @api_path_param()
    @api_response(200)
    def handle_DELETE(self):
        '''
        Deletes the icon by id or in bulk 
        :param category: if specified, deletes all icons under this category
        :return: true if deleted
        :rtype: ``basestring``
        '''
        category = self.context['query'].get('category')
        filter = self.context['query'].get('filter')
        if category:
            category = category.strip() 
            self._get_svc().bulk_delete_category(category)
        elif filter:
            self._get_svc().bulk_delete(filter)
        else:
            self._get_svc().delete(self.context['id'])
        res = {"Deleted": "True"}
        self.response.write(str(json.dumps(res)))

    def _get_svc(self):
        '''
        Creates the IconService object
        :return: IconService()
        '''
        return IconService(self.context['app'], self.context['session'],
                                 self.context['user'], self.context['collection'])


class ContextUtil(object):

    def __init__(self):
        pass

    @staticmethod
    def get_context(**kwargs):

        '''
        Creates and returns the dict for all the params needed for class
        :param kwargs: dict of request, sessionKey and pathParts from baseRestHandler.
        :type: ``dict``
        :return: Context dict with all the params needed.
        :rtype: ``dict``
        '''

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
        self.options = {'collection': collection_name, 'app': app_name, 'owner': 'nobody'}


class IconService(BaseService):

    """
    init params
    """
    def __init__(self, *args, **kwargs):

        '''
        Creates kv store instance.
        :param args:
        :param kwargs:
        '''
        BaseService.__init__(self, *args, **kwargs)
        self.kv_client = KvStoreHandler(self.collection_name, self.session_id, self.app_name)

    def get_count(self, query_params=dict):
        '''
        Returns total number of matched icons.
        :param query_params: params for sorting, pagination and filtering
        :type: ``dict``
        :return: number of matched icons
        :rtype: ``int``
        '''
        filter = query_params.get('filter', None)

        args = {'fields': '_key'}

        if filter:
            fg = FilterGenerator(filter)
            filter_perm = fg.generate_kvstore_filter()
            args['query'] = filter_perm

        keys = self.kv_client.adv_query(args)
        if keys: return len(keys)

        return 0

    def get_all(self, query_params=dict):
        '''
        Returns matched icons.
        :param query_params: params for sorting, pagination and filtering
        :type: ``dict``
        :return: matched Icon objects
        :rtype: ``basestring``
        '''

        count = self.get_count(query_params)
        
        sort_key = query_params.get('sort_key', 'title')
        sort_dir = query_params.get('sort_dir', 'asc')
        limit = query_params.get('limit', 0)

        offset = query_params.get('offset', 0)
        fields = query_params.get('fields', None)
        filter = query_params.get('filter', None)
        shared = query_params.get('shared', None)
        
        if sort_dir == "asc":
            sort_dir = 1
        else:
            sort_dir = -1     # Default to descending

        args = dict()
        args['sort'] = sort_key + ":" + str(sort_dir)
        args['limit'] = limit
        args['skip'] = int(offset) * int(limit)

        if fields:
            args['fields'] = fields

        if shared:
            args["shared"] = shared
        if filter:
            fg = FilterGenerator(filter)
            filter_perm = fg.generate_kvstore_filter()

            args['query'] = filter_perm

        content = self.kv_client.adv_query(args)
        return '{"total": ' + str(count) + ', "result": ' + json.dumps(content) + '}'

    """
    Get a single icon by id
    """
    def get(self, id):
        '''
        Returns icon object by id (It will also migrate the old icon objects to current object)
        :param id: id of the icon
        :type: ``basestring``
        :return: icon object from KV store
        :rtype: ``basestring``
        '''
        IconService._validate_id(id)
        content = self.kv_client.get(id)

        response = json.loads(content)

        return content

    def get_categories(self):
        '''
        Fetch all entries with category set, then pick distinct values
        '''
        response = self.get_all({'fields': 'category,immutable'})
        icons = json.loads(response)['result'] 
        categories = []
        seen = set()
        for icon in icons:
            category = icon['category']
            if category is not None and not category in seen:
                categories.append({
                    "name": category,
                    "immutable": 1 if 'immutable' in icon and icon['immutable'] == 1 else 0
                })
                seen.add(category)
        return json.dumps(sorted(categories, key=lambda k: k['name']))


    def get_category_icons(self, query_params):
        '''
        Fetch all entries within provided category
        '''
        if not 'category' in query_params:
            return None

        category = query_params['category'].strip()
        filter = [{
          "rule_condition": "AND", 
          "rule_items": [
            {"value": category, "rule_type": "matches", "field": "category", "field_type": "title"}
          ]
        }]
        query_params.pop('category')
        query_params['filter'] = filter
        return self.get_all(query_params)

    def validate_category_name(self, category):
        '''
        Returns false if category name is unacceptable
        '''
        invalid_chars = "~`!#$%\^&*+=\[\]\';,/{}|\":<>\?]#"
        return not any(char in invalid_chars for char in category)

    """
    Create a new icon
    """
    def create(self, data):
        '''
        Validates the Icon against latest icon model object and creates a new icon
        :param data: icon object
        :type: ``dict``
        :return: Saved icon id
        :rtype: ``basestring``
        '''
        
        try:
            content = ''
            if isinstance(data, list):
                self._validate_same_name_icon(data)

                # bulk remove icons marked for removal
                removal_list = []
                save_list = []
                skipped_categories = set()

                if len(data) == 0:
                    return

                for record in data:
                    if '__to_remove' in record:
                        removal_list.append(record)
                    else:
                        record['_owner'] = self.user_name
                        category = record.get('category')
                        if len(category)==0:
                            continue
                        if not self.validate_category_name(category):
                            skipped_categories.add(category)
                            continue
                        save_list.append(record)

                if len(skipped_categories) > 0:
                    logger.error('Skipped categories with names containing special characters: ' + ', '.join(skipped_categories))
                    raise IconException(400, "Special characters are not allowed in category names.")

                if len(removal_list) > 0:
                    q = {"$or":[{"_key":record['_key']} for record in removal_list]}
                    q = json.dumps(q)
                    self.kv_client.bulk_delete(q)

                    logger.info('user:"%s" app:"%s" action:"%s" icons:"%s"' % 
                        (
                         self.user_name, 
                         self.app_name, 
                         'removed', 
                         ','.join(["%s/%s"%(record['category'],record['title']) for record in removal_list])
                        )
                    )

                if len(save_list) > 0:
                    content = self.kv_client.batch_create(save_list)
                    
                    logger.info('user:"%s" app:"%s" action:"%s" icons:"%s"' % 
                        (
                         self.user_name, 
                         self.app_name, 
                         'added', 
                         ','.join(["%s/%s"%(record['category'],record['title']) for record in save_list])
                        )
                    )

            else:
                raise IconException(400, "Payload is expected to be a list.")
            return content

        except IconException as ge:
            logger.error("IconException: {}".format(ge))
            raise ge
        except Exception as e:
            logger.error("Exception: {}".format(e))
            if e.status == 403:
                raise InsufficientPermissionsException(403, "Insufficient permissions to update icon collection.")

            raise e

    """
    Update existing icon by id
    """
    def update(self, id, data):
        '''
        Validates the Icon against latest icon model object and updates a icon by id
        :param id: icon id
        :type: ``basestring``
        :param data: icon object
        :type: ``dict``
        :return: Saved icon id
        :rtype: ``basestring``
        '''
        IconService._validate_id(id)

        try:
            self._validate_same_name_icon(data)
        except IconException as ge:
            logger.error("IconException: {}".format(ge))
            raise ge
        except Exception as e:
            logger.error("Exception: {}".format(e))
            raise IconException(400, e)

        get_response = self.get(id)
        if not get_response:
            raise IconException(404, "Icon not found.")

        res_data = json.loads(get_response)

        for k, v in data.iteritems():
            if v is not None:
                res_data[k] = v

        response = self.kv_client.single_update(id, res_data, True)
        logger.info('user:"%s" app:"%s" action:"%s" id:"%s"' % 
            (
             self.user_name, 
             self.app_name, 
             'updated', 
             id
            )
        )
        return response


    """
    Issue a simple KV store record deletion by category name
    """                 
    def bulk_update_category(self, category, new_category):
        if not self.validate_category_name(new_category):
            raise IconException(400, "Category name cannot contain special characters.")
        
        filter = [{
          "rule_condition": "AND", 
          "rule_items": [
            {"value": category, "rule_type": "matches", "field": "title", "field_type": "title"}
          ]
        }]
        
        fg = FilterGenerator(filter)
        results = self.kv_client.adv_query({
            'fields': ['title', '_key'],
            'query': fg.generate_kvstore_filter()
        })

        updated_result = []
        
        for i, res in enumerate(results):
            results[i]['title'] = new_category

        response = self.kv_client.batch_update(*results)
        logger.info('user:"%s" app:"%s" action:"%s" category_old:"%s" category_new:"%s"' % 
            (
             self.user_name, 
             self.app_name, 
             'renamed', 
             category,
             new_category
            )
        )
        return response


    """
    Delete existing icon by id
    """
    def delete(self, id):
        '''
        Deletes the icon object by id in KV
        :param id: icon id
        :type: ``basestring``
        '''
        IconService._validate_id(id)
        response = self.kv_client.delete(id)
        logger.info('user:"%s" app:"%s" action:"%s" id:"%s"' % 
            (
             self.user_name, 
             self.app_name, 
             'deleted', 
             id
            )
        )
        return response

    """
    Delete multiple icons by query
    """
    def bulk_delete(self, filter):
        '''
        Deletes icon objects by query in KV
        :param filter: filtering query
        :type: ``basestring``
        '''
        q = json.dumps(filter)
        response = self.kv_client.bulk_delete(filter)
        logger.info('user:"%s" app:"%s" action:"%s" filter:"%s"' % 
            (
             self.user_name, 
             self.app_name, 
             'bulk_deleted', 
             str(filter)
            )
        )
        return response

    """
    Delete multiple icons by category
    """
    def bulk_delete_category(self, category):
        '''
        Deletes icon objects by query in KV
        :param filter: filtering query
        :type: ``basestring``
        '''
        filter = [{
          "rule_condition": "AND", 
          "rule_items": [
            {"value": category, "rule_type": "matches", "field": "category", "field_type": "title"}
          ]
        }]
        fg = FilterGenerator(filter)
        q = fg.generate_kvstore_filter()
        q = json.dumps(q)

        response = self.kv_client.bulk_delete(q)
        logger.info('user:"%s" app:"%s" action:"%s" category:"%s"' % 
            (
             self.user_name, 
             self.app_name, 
             'bulk_deleted_category', 
             str(category)
            )
        )        
        return response


    @staticmethod
    def _validate_id(_id):
        '''
        Validates for valid id string.
        :param _id: icon id
        :type: ``basestring``
        :raises: ArgValidationException if missing or not a basestring
        '''
        if any([not isinstance(_id, basestring), (isinstance(_id, basestring) and not _id.strip())]):
            raise ArgValidationException(400, 'Id is missing.')

    def _validate_same_name_icon(self, data):
        args = dict()

        # First check for duplicates in incoming data:
        seen = []
        dups = set()
        for icon in data:
            if '__to_remove' in icon: # don't count icons marked for deletion
                continue
            t = icon['title']
            if t in seen:
                dups.add(t)
            else:
                seen.append(t)
        
        if len(dups) > 0:
            dups = ','.join(dups)
            raise AlreadyExistsException(400, "Trying to add icons with the same name: {}".format(dups))



class KvStoreHandler(object):
    def __init__(self, collection_name, session_key, app, owner='nobody', **context):
        self._collection_data = self._get_collection_data(collection_name,
                                                          session_key, app, owner, **context)

    def _get_collection_data(self, collection_name, session_key, app, owner, **context):
        '''
        Returns collection instance
        :param collection_name: collection name
        :param session_key: session key
        :param app: app name
        :param owner: owner name
        :param context: extra params
        :return: collection instance
        '''
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

    def create(self, record, record_id, include_ts=True):
        '''
        Creates the object in KV
        :param record: object
        :param record_id: kv id
        :param include_ts: boolean to add _time with record
        :return: saved object id
        '''
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

    def bulk_delete(self, q):
        '''
        Issue a simple KV store record deletion by category name
        '''
        return self._collection_data.delete(q)

    def query(self, q):
        # q = urllib2.quote(json.dumps(json_query))
        return self._collection_data.query(**q)

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
                    raise ArgValidationException(400, 'Invalid value for fields parameter in KV store query.')
            elif k in ['limit', 'skip']:
                # May raise ValueError
                options[k] = str(int(v))
            elif k == 'sort':
                # Since sort order can be a bit complex, we just expect the
                # consumer to construct their own sort string here.
                if isinstance(v, basestring):
                    options['sort'] = v
                else:
                    raise ArgValidationException(400, 'Invalid value for sort parameter in KV store query.')
            else:
                # Invalid parameter is ignored.
                pass

        # params = urllib.urlencode(options)
        # logger.debug("params:: {}".format(params))
        return self.query(options)

    def single_update(self, id, record, include_ts=False):
        # Caller is responsible for ensuring that the input IS NOT an array.
        if include_ts:
            record['_time'] = time.time()

        ret = self._collection_data.update(id, json.dumps(record))
        return json.dumps(ret)

    def batch_update(self, records, include_ts=True):
        for record in records:
            if include_ts:
                record['_time'] = time.time()

        return self._collection_data.batch_save(*records)

    def batch_create(self, records, include_ts=True):
        for record in records:
            if include_ts:
                record['_time'] = time.time()

        return self._collection_data.batch_save(*records)


class FilterGenerator(object):
    """
    The filter does a couple separate things.  First, it takes in a json filter specified
    by the UI, which can be a combination of AND's OR's and NOT operations along
    with items that may or may not be wildcarded according to the splunk wildcard specifications
    (e.g. *str, str*, *str* s*tr).
    """
    def __init__(self, source_json=None):
        """
        Construct an itsi filter object
        @param source_json:  A parsed json object, dict or list
        @type source_json: iterable (list,dict)
        """
        self.kvstore_filter = None
        if isinstance(source_json, basestring):
            # We will need to extract the json, if they didn't read the documentation above
            self.source = json.loads(source_json)
        elif isinstance(source_json, dict) or isinstance(source_json, list):
            # We're probably dealing with the right parameters here
            self.source = source_json
        elif source_json is None:
            self.source = []
        else:
            raise ArgValidationException(400, "Source data could not be recognized as a string or parsed json. Data passed in: " + str(source_json))

    def _generate_filter_expression(self, source):
        """
        Generate the root filter expression given a source expression
        There are three parameters
        @param source: The source expression in a json format - defined in ITOA-2287
        @type source: A dict
        """
        log_prefix = "[generate_filter_expression] "
        illegal_characters = ['=', '$', '^']
        if not isinstance(source, dict):
            message = "Expected a dict for the filter expression, got something else"
            logger.error(log_prefix + message)
            raise ArgValidationException(400, message)
        rule_type = source.get('rule_type', '').lower()
        field = source.get('field', None)

        field_type = source.get('field_type')

        if not any(field_type == allowed_type for allowed_type in ['alias', 'info', 'title']):
            message = "Unexpected value='{0}' specified for field type, with type='{1}'".format(field_type,
                                                                                                type(field_type))
            logger.error(log_prefix + message)
            raise ArgValidationException(400, message)

        # Generate filter to identify presence of field in the respective field type
        field_type_filter = {} # do not filter fields by default
        if field_type == 'alias':
            field_type_filter = {'identifier.fields': field}
        elif field_type == 'info':
            field_type_filter = {'informational.fields': field}

        value = source.get('value', None)
        if value is None or '':
            message = "Expected value definition in the json {}".format(source)
            logger.error(log_prefix + message)
            raise ArgValidationException(400, message)

        # For each value specified, construct the required filter
        split_values = value.split(',')
        values_to_regex = []
        for split_value in split_values:
            split_value = split_value.replace("\\", "\\\\");
            for i in illegal_characters:
                if i in split_value:
                    message = "Illegal character %s in value %s" % (i, split_value)
                    logger.error(log_prefix + message)
                    raise ArgValidationException(400, message)

            # All done with validation, now build the filter
            if split_value.find('*') != -1:  # regex value identified
                split_value = split_value.replace('*', '.*?')
                if rule_type == 'not':
                    # Adjust regex to be an exclusion
                    split_value = '(?!' + split_value + ').*'
                kv_filter = {field: {'$regex': '^' + split_value + '$', '$options': 'i'}}
            elif rule_type == 'not':
                # Construct exclusion filter
                # Since the only way to perform case insensitive string compare is using regex,
                # construct a regex for the single value lookup
                # Regex cannot be used for empty value exclusion, so special handle it
                if len(split_value) == 0:
                    kv_filter = {field: {"$ne": split_value}}
                else:
                    # Since the only way to perform case insensitive string compare is using regex,
                    # construct a regex for the single value lookup
                    kv_filter = {field: {'$regex': '^(?!' + split_value + ').*$', '$options': 'i'}}
            else:
                kv_filter = {field: {'$regex': '^' + split_value + '$', '$options': 'i'}}
            values_to_regex.append(kv_filter)

        return {'$and': [field_type_filter, {'$or': values_to_regex}]}

    def generate_kvstore_filter(self, regenerate=False):
        """
        Generates the kvstore_filter from the source json
        @param regenerate:  Force a regeneration of the kvstore_filter, used more in testing
        @type regenerate: Boolean
        """
        if self.kvstore_filter is not None and regenerate is False:
            return self.kvstore_filter
        """
        We plan to currently support only one level of nesting as follows:
            > All rule items are ORed at the top level.
            > Only one level of Nesting is supported and all rule items in the nested level will be ANDed
            > Sample:
                 key1=value1,value1.1 AND key=value2
                 OR
                 key3=value3 AND key4=value4
        We will need to change the json formatting if we're expecting more nesting or combination of AND and OR
        """
        if isinstance(self.source,list):
            or_expressions = []
            # Process the top level OR terms
            for rule_group in self.source:
                or_term = rule_group.get('rule_items')
                and_expressions = []
                # Process the first level nested AND terms
                if isinstance(or_term,list):
                    for and_term in or_term:
                        leaf = self._generate_filter_expression(and_term)
                        and_expressions.append(leaf)
                    or_expressions.append({"$and":and_expressions})
            generated_filter = {"$or": or_expressions }
        else:
            raise ArgValidationException(400, "source filter must be a list")

        self.kvstore_filter = generated_filter
        return self.kvstore_filter


class IconException(splunk.RESTException):
    def __init__(self, status_code, msg):
        splunk.RESTException.__init__(self, status_code, msg)


class ArgValidationException(IconException):
    pass


class InsufficientPermissionsException(IconException):
    pass


class AlreadyExistsException(IconException):
    pass


class KVNotExists(IconException):
    pass
