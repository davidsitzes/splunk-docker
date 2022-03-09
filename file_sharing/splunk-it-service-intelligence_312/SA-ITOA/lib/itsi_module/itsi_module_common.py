# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Utility module for itsi_module.
"""
import os
import re
import sys
import json
import urllib
import cherrypy

import splunk.rest as rest
import itsi_module_package.itsi_module_builder_util as builder_util

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk import ResourceNotFound, RESTException
from ITOA.setup_logging import setup_logging
from splunk.util import normalizeBoolean

logger = setup_logging('itsi_module_interface.log', 'itsi.controllers.itsi_module_interface')

_ALL_MODULES = '-'
_KV_STORE_BASE_URL = 'servicesNS/nobody/SA-ITOA/itoa_interface/kpi_template'

_ICON_BASE_ENDPOINT = 'servicesNS/nobody/{}/static/{}'
_SETTINGS_CONF_FILE = 'itsi_module_settings'


class ItsiModuleError(cherrypy.HTTPError):
    """
    Set the status and msg on the response

    I.e.
    raise ITOAEntityError(
        status=500, message=_("Your call is very important to us ..."))
    """

    def get_error_page(self, *args, **kwargs):
        """
        Returns the error page
        """
        kwargs['noexname'] = 'true'
        return super(ItsiModuleError, self).get_error_page(*args, **kwargs)


def get_object_endpoint(base_url, base_args, itsi_module, object_id, **kwargs):
    """
    Constructs the endpoint for a request

    @type base_url: string
    @param base_url: the base url

    @type base_args: string
    @param base_args: base query parameters/arguments

    @type itsi_module: string
    @param itsi_module: the module ID

    @type object_id: string
    @param object_id: the ITSI object ID

    @type kwargs: dict
    @param kwargs: additional arguments

    @rtype: string
    @return: the constructed endpoint
    """
    # If an object_id is given, set the request endpoint to be "/conf-itsi_kpi_template/<object_id>"
    if object_id is not None:
        return (base_url % itsi_module) + '/' + object_id + base_args
    # Otherwise, the request endpoint will find all kpi templates for the given module,
    # or if module is given as "-", will find kpi templates across all modules
    else:
        url_search = (('&search=eai:acl.app=' + itsi_module) if itsi_module != '-' else '&search=DA-ITSI')
        url = (base_url % itsi_module) + base_args
        return url + url_search


def make_http_get(endpoint, session_key, **kwargs):
    """
    Makes an HTTP GET request, and returns the payload if successful, otherwise throws a 404 if content was not found

    @type endpoint: string
    @param endpoint: endpoint to make request to

    @type session_key: string
    @param session_key: session key to make sure HTTP request is authenticated
    """
    try:
        # Makes an HTTP GET request to the endpoint for the objects
        response, payload = rest.simpleRequest(endpoint, method='GET', sessionKey=session_key, getargs=kwargs)
        return payload
    except ResourceNotFound:
        # Raise an exception if the module or ID doesn't exist
        raise ResourceNotFound(_('The requested module or ID was not found.'))


def extract_metadata_each_module(module, itsi_module_settings):
    """
    Used to modify each module object that is returned from REST call in order to only return relevant information to the end-user

    Includes the base64 encoded icon for the module if the flag "include_icon_data" is passed when making
    the request

    @type module: dict
    @param itsi_module_settings: dict contains module settings

    @type module: dict
    @param module: The object describing each module from apps/local
    """
    content = module['content']
    name = module['name']
    content['package_name'] = name
    del content['disabled']
    content['is_read_only'] = itsi_module_settings.get(name, False)
    content['last_exported_date'] = get_last_exported_date(name)
    return content


def get_itsi_module_settings(session_key):
    get_args = {'output_mode': 'json'}
    try:
        content = json.loads(make_http_get(make_conf_uri(_SETTINGS_CONF_FILE, 'SA-ITOA'), session_key,
                                       **get_args))
    except Exception as e:
        logger.error('Error while reading itsi_module_settings. {}'.format(e.message))
        return {}
    settings_stanza = 'settings://'
    readonly_settings = {}
    for entry in content['entry']:
        if entry['name'].startswith(settings_stanza):
            app = entry['name'].split(settings_stanza)[1]
            readonly_settings[app] = normalizeBoolean(entry['content'].get('is_read_only'))
    return readonly_settings


def include_meta_file_info(itsi_module, metadata):
    app_folder = make_splunkhome_path(['etc', 'apps', itsi_module])
    readme = os.path.join(app_folder, 'README.txt')
    small_icon_file = 'appIcon.png'
    large_icon_file = 'appIcon_2x.png'
    small_icon = os.path.join(app_folder, 'static', small_icon_file)
    large_icon = os.path.join(app_folder, 'static', large_icon_file)

    metadata['readme'] = os.path.isfile(readme)
    metadata['small_icon'] = _ICON_BASE_ENDPOINT.format(itsi_module, small_icon_file) \
        if os.path.isfile(small_icon) else ''
    metadata['large_icon'] = _ICON_BASE_ENDPOINT.format(itsi_module, large_icon_file) \
        if os.path.isfile(large_icon) else ''
    return metadata


def construct_metadata_response(endpoint, itsi_module, session_key, **kwargs):
    """
    Constructs the response for the metadata endpoint at /itsi_module_interface/:module

    @type endpoint: string
    @param endpoint: HTTP endpoint that was requested

    @type itsi_module: string
    @param itsi_module: ITSI module that was requested

    @type session_key: string
    @param session_key: session key to make sure HTTP request is authenticated
    """
    payload = make_http_get(endpoint, session_key)

    # Response loaded as a string, we want to modify it as a dict
    payload_dict = json.loads(payload)

    itsi_module_settings = get_itsi_module_settings(session_key)

    # If request is for a single module, just return the one, otherwise map through
    # the list of module metadata and return that result
    if itsi_module != _ALL_MODULES:
        metadata = extract_metadata_each_module(payload_dict['entry'][0], itsi_module_settings)
        return include_meta_file_info(itsi_module, metadata)
    return map(lambda module:
               extract_metadata_each_module(module, itsi_module_settings), payload_dict['entry'])


def strip_eai_keys(object):
    """
    Removes all keys from response object of the form "eai:<>"

    @type object: dict
    @param object: the object from which to strip the eai key

    @rtype: list
    @return: the list of removed keys
    """
    if type(object) is dict:
        eai_keys = list(k for k, v in object.items() if k.startswith('eai:'))
        for key in eai_keys:
            del object[key]
        return eai_keys


def parse_json_blob_fields(object, obj_json_blob_fields):
    """
    Converts a string field into a dict/JSON object in the same field

    @type object: dict
    @param object: the object content field from within the fields are to be parsed

    @type obj_json_blob_fields: list
    @param obj_json_blob_fields: a list of fields that this operation is applied on within the object
    """
    if type(obj_json_blob_fields) is list:
        for field in obj_json_blob_fields:
            try:
                object['content'][field] = json.loads(object['content'][field])
            except Exception as e:
                logger.exception(e)
                continue
        return object


def construct_get_response(endpoint, object_type, object_id, session_key, obj_json_blob_fields, **kwargs):
    """
    This constructs the response for the HTTP get from either /itsi_module_interface/:module/:object or from /itsi_module_interface/:module/:object/:id_

    @type endpoint: string
    @param endpoint: Endpoint from which to retrieve object

    @type object_type: string
    @param object_type: object type being included.  Can be "kpi_group", "kpi_base_search", "service_template"
    or "entity_source_template"

    @type object_id: string
    @param object_id: when provided, the ID of the object to fetch

    @type session_key: string
    @param session_key: The active session key to authenticate HTTP requests with

    @rtype: list
    @return: the list of object(s)
    """
    # Parse the response string into a dict
    payload_dict = json.loads(make_http_get(endpoint, session_key))

    response_obj_list = []

    object_type = object_type if object_type is not None else ''
    logger.debug('construct_get_response: object_type=%s', object_type)

    # If the request only specified a single object (given an ID), return the
    # first index from content in the payload along with other metadata
    if object_id is not None:
        # Strip all keys that contain "eai" in them
        strip_eai_keys(payload_dict['entry'][0]['content'])
        response_obj = {
            'source_itsi_module': payload_dict['entry'][0]['acl']['app'],
            'object_type': object_type,
            # Note that object_id could be url encoded, for example, for entity_source_template.
            # So set id using entry name from the request response instead.
            'id': payload_dict['entry'][0]['name'],
            'content': payload_dict['entry'][0]['content']
        }
        response_obj_list.append(parse_json_blob_fields(response_obj, obj_json_blob_fields))
    # Otherwise, construct list of objects from the HTTP response for a module
    else:
        for entry_item in payload_dict['entry']:
            # Strip all keys that contain "eai" in them
            strip_eai_keys(entry_item['content'])
            if entry_item['acl']['app'].startswith('DA-ITSI'):
                obj_to_add = {
                    'source_itsi_module': entry_item['acl']['app'],
                    'object_type': object_type,
                    'id': entry_item['name'],
                    'content': entry_item['content']
                }
                obj_to_add = parse_json_blob_fields(obj_to_add, obj_json_blob_fields)
                response_obj_list.append(obj_to_add)

    return response_obj_list


def construct_count_response(endpoint, itsi_module, object_type, session_key, **kwargs):
    """
    Constructs the response for the metadata endpoint at /itsi_module_interface/:module

    @type endpoint: string
    @param endpoint: HTTP endpoint that was requested

    @type itsi_module: string
    @param itsi_module: ITSI module that was requested

    @type object_type: string
    @param object_type: object type being included.  Can be "kpi_group", "kpi_base_search", "service_template"
    or "entity_source_template"

    @type session_key: string
    @param session_key: session key to make sure HTTP request is authenticated
    """
    # Parse the response string into a dict
    payload_dict = json.loads(make_http_get(endpoint, session_key))

    # If the request only specified a single module, construct response object directly from size field
    if itsi_module != '-':
        return {
            object_type: payload_dict['paging']['total']
        }

    # Otherwise, loop through response object and construct counts for each service template in all modules
    else:
        response_dict = {}
        read_kpi_count = object_type == 'kpi_group'
        for element in payload_dict['entry']:
            curr_module = element['acl']['app']
            if curr_module.startswith('DA-ITSI'):
                _increment_count(curr_module, object_type, response_dict)
                if read_kpi_count:
                    try:
                        # In case of malformatted kpis, ignore this field
                        kpis = json.loads(element['content']['kpis'])
                        _increment_count(curr_module, 'kpis', response_dict, len(kpis))
                    except Exception as e:
                        logger.exception(e)
    return response_dict


def _increment_count(curr_module, object_type, response_dict, count=1):
    """
    Increment the count of specified module and object type, create the entry if it doesn't exist
    @type curr_module: string
    @param curr_module: module name
    
    @type object_type: string
    @param object_type: object name
    
    @type response_dict: dict
    @param response_dict: the count dict
    
    @type count: int
    @param count: amount to increment, defaults to 1
    @return: None
    """
    if curr_module not in response_dict:
        response_dict[curr_module] = {}
    if object_type not in response_dict[curr_module]:
        response_dict[curr_module][object_type] = 0
    response_dict[curr_module][object_type] += count


def make_conf_uri(conf_name, itsi_module):
    """
    Construct uri for editing conf files

    @type conf_name: string
    @param conf_name: name of the conf file

    @type itsi_module: string
    @param itsi_module: ITSI module name

    @rtype: string
    @return: url for editing conf files
    """
    return rest.makeSplunkdUri() + 'servicesNS/nobody/' + itsi_module + '/configs/conf-' + conf_name


def create_conf_stanza(session_key, conf_name, conf_stanza, itsi_module):
    """
    Create conf stanza by calling splunk conf endpoints

    @type session_key: string
    @param session_key: session_key

    @type conf_name: string
    @param conf_name: conf file name

    @type conf_stanza: dict
    @param conf_stanza: dict of data to post

    @type itsi_module: string
    @param itsi_module: itsi_module name

    @rtype: tuple
    @return: response and content or raise an exception
    """
    postargs = conf_stanza
    postargs['output_mode'] = 'json'
    conf_uri = make_conf_uri(conf_name, itsi_module)
    try:
        response, content = rest.simpleRequest(
            conf_uri,
            method="POST",
            postargs=postargs,
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return response, content
    except ResourceNotFound:
        raise ItsiModuleError(status=404, message=_('Requested itsi_module does not exist.'))
    except RESTException as restException:
        raise ItsiModuleError(status=400, message=restException.get_message_text())
    except:
        raise ItsiModuleError(status=400, message=_('Error writing data into conf: %s.') % (sys.exc_info()[0]))


def update_conf_stanza(session_key, conf_name, conf_stanza_name, data_to_post, itsi_module):
    """
    Update conf stanza by calling splunk conf endpoints

    @type session_key: string
    @param session_key: session_key

    @type conf_name: string
    @param conf_name: conf file name

    @type conf_stanza_name: string
    @param conf_stanza: stanza name to update

    @type data_to_post: dict
    @param data_to_post: dict of data

    @type itsi_module: string
    @param itsi_module: itsi_module name

    @rtype: tuple
    @return: response and content or raise an exception
    """
    postargs = data_to_post
    postargs['output_mode'] = 'json'
    conf_uri = make_conf_uri(
        conf_name, itsi_module) + '/' + urllib.quote_plus(conf_stanza_name)
    try:
        response, content = rest.simpleRequest(
            conf_uri,
            method="POST",
            postargs=postargs,
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return response, content
    except ResourceNotFound:
        raise ItsiModuleError(status=404, message=_('Requested itsi_module does not exist.'))
    except:
        raise ItsiModuleError(status=400, message=_('Error updating %s: %s.') % (conf_stanza_name, sys.exc_info()[0]))


def delete_conf_stanza(session_key, conf_name, conf_stanza_name, itsi_module):
    """
    Delete conf stanza by calling splunk conf endpoints

    @type session_key: string
    @param session_key: session_key

    @type conf_name: string
    @param conf_name: conf file name

    @type conf_stanza_name: string
    @param conf_stanza: stanza name to update

    @type itsi_module: string
    @param itsi_module: itsi_module name

    @rtype: tuple
    @return: response and content or raise an exception
    """
    conf_uri = make_conf_uri(conf_name, itsi_module) + '/' + \
               urllib.quote_plus(conf_stanza_name)
    try:
        response, content = rest.simpleRequest(
            conf_uri,
            method="DELETE",
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return response, content
    except ResourceNotFound:
        raise ItsiModuleError(status=404, message=_('Requested itsi_module does not exist.'))
    except:
        raise ItsiModuleError(status=400, message=_('Error updating %s: %s.') % (conf_stanza_name, sys.exc_info()[0]))


def templatize_obj_by_id(session_key, object, object_id):
    """
    Templatize an object by id

    @type session_key: string
    @param session_key: session_key

    @type object: string
    @param object: object defined in manifest

    @type object_id: string
    @param object_id: id of the object

    @rtype: tuple
    @return: response and content or raise an exception
    """
    templatize_uri = rest.makeSplunkdUri() + 'servicesNS/nobody/SA-ITOA/itoa_interface/%s/%s/templatize' % (
    object, object_id)
    try:
        response, content = rest.simpleRequest(
            templatize_uri,
            method='GET',
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return response, content

    except RESTException:
        raise ItsiModuleError(status=404,
                              message=_('Requested itsi_object: %s / object_id=%s does not exist.') % (object, object_id))
    except:
        raise ItsiModuleError(status=400, message=_('Error templatizing %s id: %s.') % (object, object_id))


def make_stanza_name(itsi_module, object_title, **kwargs):
    """
    Make object id (stanza name) using the convention <itsi_module>-<title with space replaced by _)

    @type itsi_module: string
    @param itsi_module: ITSI module name

    @type object_title: string
    @param object_title: value of the object title

    @rtype: string
    @return: generated stanza_name or raise an exception
    """
    if not object_title:
        raise ItsiModuleError(status=400, message=_('Object title can not be empty or none.'))
    object_title_with_no_special_chars = replace_special_chars_with_underscore(object_title.strip())
    stanza_name = '-'.join([itsi_module, object_title_with_no_special_chars])
    if 'prefix' in kwargs and kwargs['prefix']:
        stanza_name = kwargs['prefix'] + stanza_name
    if 'suffix' in kwargs and kwargs['suffix']:
        suffix = kwargs['suffix'].strip().replace(' ', '_')
        stanza_name = stanza_name + '_' + suffix
    return stanza_name


def format_value(value):
    """
    Format value based on its type

    @type value: dict,list or string
    @param value: value that needs to be re-formatted

    @rtype: string
    @return: re-formatted value
    """
    if isinstance(value, dict) or isinstance(value, list):
        return json.dumps(value, sort_keys=True, indent=4)
    else:
        return str(value)


def filter_keys_reformat_certain_values_from_payload(itsi_module, accepted_keys, data):
    """
    Filter keys and reformat certain values for writing into conf

    For example, metrics field's value needs to be written to conf
    as json format.

    @type itsi_module: string
    @param itsi_module: ITSI module name

    @type accepted_keys: list
    @param accepted_keys: a list of all accepted keys

    @type data: dict
    @param data: dict of key, values to be filtered

    @rtype: dict
    @return: dict of data with filtered keys and re-formatted data
    """
    filtered_payload = {}
    # Take intersection of accepted_keys and data
    keys = [key for key in data if key in accepted_keys]

    for key in keys:
        if key == 'metrics':
            filtered_payload[key] = format_value(data.get('metrics'))
        elif key == 'source_itsi_da':
            filtered_payload[key] = itsi_module
        elif key == 'kpis':
            filtered_payload[key] = format_value(data.get('kpis'))
        elif key == 'entity_rules':
            filtered_payload[key] = format_value(data.get('entity_rules'))
        else:
            filtered_payload[key] = data.get(key)
    return filtered_payload


def build_module_kpi_mapping_kv_store(session_key, kv_store_args):
    """
    Builds the mapping from module -> KPI id -> KPI, except the values
    for KPIs are retrieved from KV-store

    @type session_key: string
    @param session_key: Session key for HTTP request

    @type kv_store_args: dict
    @param kv_store_args: arguments that determine any filter or fields requested
    """
    kpi_groups = {}
    module_kpi_mapping = {}
    response, content = rest.simpleRequest(
        rest.makeSplunkdUri() + _KV_STORE_BASE_URL,
        method='GET',
        getargs=kv_store_args,
        sessionKey=session_key
    )
    if response.status == 500:
        raise ItsiModuleError(status=500, message=content)
    try:
        kpi_groups = json.loads(content)
    except Exception as e:
        raise ItsiModuleError(status=400, message=e.message)

    for kpi_group in kpi_groups:
        if kpi_group['source_itsi_da'] not in module_kpi_mapping:
            module_kpi_mapping[kpi_group['source_itsi_da']] = {}
        for kpi in kpi_group['kpis']:
            module_kpi_mapping[kpi_group['source_itsi_da']][kpi['kpi_template_kpi_id']] = kpi
    return module_kpi_mapping


def get_conf_by_namespace(session_key, conf_name, app='itsi', count=-1):
    """
    Get content of a specific conf file under given namespace

    @type session_key: string
    @param session_key: splunk session_key

    @type conf_name: string
    @param conf_name: conf file name

    @type filter: dict
    @param filter: filter params
    supported by splunk: http://docs.splunk.com/Documentation/Splunk/6.4.2/RESTREF/RESTprolog#Pagination_and_filtering_parameters

    @type app: string
    @param app: namespace to be filtered by

    @type count: int
    @param count: number of results that will be returned

    @rtype: tuple
    @return: tuple of response and content or raise an exception

    """
    getargs = {
        'output_mode': 'json',
        'count': count,
        'search': 'eai:acl.app=%s' % app
    }
    conf_uri = make_conf_uri(conf_name, app)
    try:
        response, content = rest.simpleRequest(
            conf_uri,
            method="GET",
            getargs=getargs,
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return response, content
    except ResourceNotFound:
        raise ItsiModuleError(status=404, message=_('Requested module/conf file does not exist.'))
    except:
        raise ItsiModuleError(status=400,
                              message=_('Error getting content of conf file %s: %s.') % (conf_name, sys.exc_info()[0]))


def generate_validation_error_line(object_instance, message):
    """
    Generates a list that contains details about a validation error

    @type object_instance: object
    @param object_instance: the module object

    @type message: string
    @param message: the error message

    @rtype: list
    @return: a list of module name, object ID and the message

    """
    return [object_instance['source_itsi_module'], object_instance['id'], message]


def get_obj_by_id(session_key, object, object_id):
    """
    Get an ITSI object by id

    @type session_key: string
    @param session_key: session_key

    @type object: string
    @param object: object defined in manifest

    @type object_id: string
    @param object_id: id of the object

    @rtype: tuple
    @return: response and content or raise an exception
    """
    uri = rest.makeSplunkdUri() + 'servicesNS/nobody/SA-ITOA/itoa_interface/%s/%s' % (object, object_id)
    try:
        response, content = rest.simpleRequest(
            uri,
            method='GET',
            sessionKey=session_key,
            raiseAllErrors=True
        )
        return (response, content)

    except ResourceNotFound:
        raise ItsiModuleError(status=404,
                              message=_('Requested itsi_object: %s / object_id=%s does not exist') % (object, object_id))
    except:
        raise ItsiModuleError(status=400, message=_('Error getting %s id: %s.') % (object, object_id))


def replace_special_chars_with_underscore(string):
    """
    Replace special characters (except _.-) in a string with _

    @type string: string
    @param string: string to replace special chars

    @rtype: string
    @return: updated string with special characters replaced by _
    """
    try:
        string_with_no_special_chars = re.sub('[^a-zA-Z0-9\._-]+', '_', string)
        return re.sub('\_+', '_', string_with_no_special_chars)
    except TypeError:
        raise TypeError(_('Cannot replace special characters in string: %s.') % string)


def construct_validation_result(**kwargs):
    """
    Construct validation result based on arguments.

    @type kwargs: args
    @param kwargs: Key word arguments

    @rtype: dictionary
    @return: dictionary of validation result type to actual contents
    """
    validation_result = {}

    if kwargs:
        for key, value in kwargs.iteritems():
            if value and isinstance(value, list) and len(value):
                validation_result[key] = value
    return validation_result


def get_last_exported_date(itsi_module):
    package_name = builder_util.get_download_package_name(itsi_module)
    full_path = builder_util.get_package_file_full_path_with_package_name(package_name)
    return os.path.getmtime(full_path) if os.path.isfile(full_path) else 0


def get_simple_response(endpoint, keys, session_key, itsi_module):
    """
    Get simplified response for a module object request. only include id and requested keys in response
    @type endpoint: string
    @param endpoint: the conf endpoint
    
    @type keys: list
    @param keys: requested keys
    
    @type session_key: string
    @param session_key: the session key
    
    @type itsi_module: string
    @param itsi_module: the requested module
    
    @rtype: dict
    @return: extracted response
    """
    entries = json.loads(make_http_get(endpoint, session_key))['entry']
    response = []
    is_all_module = itsi_module == _ALL_MODULES
    for entry in entries:
        if is_all_module or entry['acl']['app'] == itsi_module:
            entry = parse_json_blob_fields(entry, keys)
            content = entry['content']
            extracted = {k: content[k] for k in keys if k in content}
            extracted['id'] = entry['name']
            response.append(extracted)
    return response


def filter_kpis(parsed_response, services, service_id):
    filtered_response = []
    for service in services:
        if service['id'] == service_id:
            kpi_ids = set(service['content']['recommended_kpis'] + service['content']['optional_kpis'])
            for response in parsed_response:
                for kpi in response['content']['kpis']:
                    if kpi['kpi_template_kpi_id'] in kpi_ids:
                        filtered_response.append(response)
                        break
    return filtered_response
