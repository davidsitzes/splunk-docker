# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import os
import json
import uuid
import urllib
import time
import traceback
import re
import datetime
from random import random

import splunk.rest as rest
import splunk.util
from splunk.appserver.mrsparkle.lib import i18n
from splunk.entity import setEntity, getEntity, controlEntity, buildEndpoint, deleteEntity, Entity

from ITOA import itoa_common
from ITOA.storage.itoa_storage import ITOAStorage
from ITOA.itoa_factory import instantiate_object

from ITOA.itoa_common import (
    delete_conf_stanza, get_conf,
    save_batch as size_based_batch_save,
    is_size_less_than_50_mb, post_splunk_user_message
    )
from ITOA.version_check import VersionCheck

from .constants import current_itsi_app_version

logger = itoa_common.get_itoa_logger('itsi.object.utils')

#Global Variable Definitions

# The capabilitiy values defined here must match the ones exposed in authorize.conf
CAPABILITY_MATRIX = {
        'rbac' : {
            'read' : 'configure_perms',
            'write' : 'configure_perms',
            'delete' : 'configure_perms'
            },
        'glass_table': {
            'read':'read_itsi_glass_table',
            'write':'write_itsi_glass_table',
            'delete':'delete_itsi_glass_table',
            'interact':'interact_with_itsi_glass_table'
            },
        'deep_dive': {
            'read':'read_itsi_deep_dive',
            'write':'write_itsi_deep_dive',
            'delete':'delete_itsi_deep_dive',
            'interact':'interact_with_itsi_deep_dive'
            },
        'deep_dive_context': {
            'read':'read_itsi_deep_dive_context',
            'write':'write_itsi_deep_dive_context',
            'delete':'delete_itsi_deep_dive_context',
            'interact':'interact_with_itsi_deep_dive_context'
            },
        'home_view': {
            'read':'read_itsi_homeview',
            'write':'write_itsi_homeview',
            'delete':'delete_itsi_homeview',
            'interact':'interact_with_itsi_homeview'
            },
        'event_management_state': {
            'read':'read_itsi_event_management_state',
            'write':'write_itsi_event_management_state',
            'delete':'delete_itsi_event_management_state'
            },
        'service':{
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'base_service_template': {
            'read': 'read_itsi_base_service_template',
            'write': 'write_itsi_base_service_template',
            'delete': 'delete_itsi_base_service_template'
            },
        'entity':{ # subsumed by service capabilities
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'kpi_base_search':{ # subsumed by service capabilities
            'read':'read_itsi_kpi_base_search',
            'write':'write_itsi_kpi_base_search',
            'delete':'delete_itsi_kpi_base_search'
            },
        'team':{ # subsumed by service capabilities
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'kpi':{ # subsumed by service capabilities
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'kpi_template':{ # subsumed by service capabilities
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'entity_relationship':{
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'entity_relationship_rule':{
            'read':'read_itsi_service',
            'write':'write_itsi_service',
            'delete':'delete_itsi_service'
            },
        'kpi_threshold_template':{
            'read':'read_itsi_kpi_threshold_template',
            'write':'write_itsi_kpi_threshold_template',
            'delete':'delete_itsi_kpi_threshold_template'
            },
        'temporary_kpi':{
            'read':'read_itsi_temporary_kpi',
            'write':'write_itsi_temporary_kpi',
            'delete':'delete_itsi_temporary_kpi'
            },
        'backup_restore':{
            'read':'read_itsi_backup_restore',
            'write':'write_itsi_backup_restore',
            'delete':'delete_itsi_backup_restore'
            },
        'files':{
            'read':'read_itsi_backup_restore',
            'write':'write_itsi_backup_restore',
            'delete':'delete_itsi_backup_restore'
            },
        'saved_page':None
    }

OBJECT_COLLECTION_MATRIX = {
    'team': 'itsi_team',
    'service': 'itsi_services', # itsi_service collection
    'base_service_template': 'itsi_base_service_template',
    'entity': 'itsi_services',
    'kpi': 'itsi_services',
    'kpi_base_search': 'itsi_services',
    'kpi_template': 'itsi_services',
    'kpi_threshold_template':'itsi_services',
    'saved_page':'itsi_services',
    'deep_dive':'itsi_pages', # itsi_pages
    'glass_table':'itsi_pages',
    'home_view':'itsi_service_analyzer', # itsi_service_analyzer
    'migration':'itsi_migration', # itsi_migration
    'event_management_state': 'itsi_event_management',
    'backup_restore': 'itsi_backup_restore_queue',
    'entity_relationship': 'itsi_entity_relationships',
    'entity_relationship_rule': 'itsi_entity_relationship_rules'
}

SECURABLE_OBJECT_LIST = [
    'service',
    'kpi_base_search',
    'kpi_template',
    'kpi_threshold_template',
    'entity',
    'base_service_template'
]

# List of securable object_types that can be contained only inside of the Global Security Group
GLOBAL_ONLY_SECURABLE_OBJECT_LIST = [
    'kpi_base_search',
    'kpi_template',
    'kpi_threshold_template',
    'entity',
    'base_service_template'
]

GLOBAL_SECURITY_GROUP_CONFIG = {
    'key': 'default_itsi_security_group',
    'title': 'Global'
}

SECURABLE_OBJECT_SERVICE_CONTENT_KEY = {
    'base_service_template': 'linked_services'
}

DEFAULT_SCHEDULED_BACKUP_KEY = 'ItsiDefaultScheduledBackup'

# default team settings import is handled by import_team_settings method
BLACK_LIST = ['notable_event_review_security_group', 'default_itsi_security_group']

# unsupported characters
ILLEGAL_CHARACTERS = ['=', '$', '^']

class ITOAInterfaceUtils(object):
    '''
    Utility methods for appserver/controllers/itoa_interface.py
    '''

    KV_STORE_COLLECTION_URI = '/servicesNS/nobody/SA-ITOA/storage/collections/data/itsi_services'
    KV_STORE_NEW_MIGRATION_COLLECTION_URI = '/servicesNS/nobody/SA-ITOA/storage/collections/data/itsi_migration'

    @staticmethod
    def fetch_shkpi_id(service_obj):
        '''
        for a given service_obj, fetch the shkpi _key
        service_obj = {
            'title' : '',
            ...
            'kpis' : [
                        {
                        <kpi fields>
                        '_key' : 'SHKPI....'
                        }
                    ]
            }

        '''
        if (not isinstance(service_obj, dict)) or (service_obj is None) or (len(service_obj) == 0):
            return None
        kpis = service_obj.get('kpis', [])

        # no kpis exist, lets add a SHKPI to this service
        if len(kpis) == 0:
            shkpi_dict = ITOAInterfaceUtils.generate_shkpi_dict(service_obj.get('_key'))
            if shkpi_dict:
                service_obj['kpis'] = [shkpi_dict]

        for kpi in kpis:
            kpi_key = kpi.get('_key', '')
            if kpi_key.startswith('SHKPI'):
                return kpi_key
        return None

    @staticmethod
    def generate_backend_key():
        '''
        generate a random ID for a service health kpi
        '''
        return str(uuid.uuid4())

    @staticmethod
    def validate_thresholds(thresholds_container, thresholds_key):
        '''
        Validate that the thresholds are in the correct format
        (container fields should be containers, number fields should be numbers)
        NOTE: It does not check that max is above min, or any other value checking
        @param thresholds_container: The container for the thresholds
        @type thresholds_container: dict
        @param thresholds_key: The key indicating the threshold to examine
        @type thresholds_key: string
        '''
        if not itoa_common.is_valid_dict(thresholds_container):
            # Ignore validation for incorrect containers
            return

        if ((thresholds_key not in thresholds_container) or
                (not itoa_common.is_valid_dict(thresholds_container[thresholds_key]))):
            thresholds_container[thresholds_key] = {}

        thresholds = thresholds_container[thresholds_key]

        for field_name in ['isMaxStatic', 'isMinStatic']:
            if ((field_name not in thresholds) or
                    (not isinstance(thresholds[field_name], bool))):
                thresholds[field_name] = False

        def validate_num_field(field_name, container):
            itoa_common.normalize_num_field(container, field_name, numclass=float)

        validate_num_field('baseSeverityValue', thresholds)

        if (('thresholdLevels' not in thresholds) or
                (not itoa_common.is_valid_list(thresholds['thresholdLevels']))):
            thresholds['thresholdLevels'] = []

        for threshold_level in thresholds['thresholdLevels']:
            validate_num_field('dynamicParam', threshold_level)
            validate_num_field('thresholdValue', threshold_level)
            validate_num_field('severityValue', threshold_level)

    @staticmethod
    def validate_aggregate_thresholds(aggregate_thresholds_container):
        # Assume aggregate_thresholds_container has already been validated for valid dict

        ITOAInterfaceUtils.validate_thresholds(aggregate_thresholds_container, 'aggregate_thresholds')

    @staticmethod
    def validate_entity_thresholds(entity_thresholds_container):
        # Assume entity_thresholds_container has already been validated for valid dict

        ITOAInterfaceUtils.validate_thresholds(entity_thresholds_container, 'entity_thresholds')\

    @staticmethod
    def generate_shkpi_dict(service_backend_key):
        '''
        every service that is created; needs a service health kpi by default...
        this is nothing but a static dict...
        '''
        if any([
            not isinstance(service_backend_key, basestring),
            isinstance(service_backend_key, basestring) and not service_backend_key.strip()
            ]):
            return None

        service_id = str(service_backend_key)
        shkpi_key = 'SHKPI-' + str(service_backend_key)
        return {
            "title": "ServiceHealthScore",
            "threshold_eval": "",
            "alert_on": "both",
            "datamodel": {
                "datamodel": "",
                "object": "",
                "owner_field": "",
                "field": ""
                },
            "unit": "",
            "gap_severity_value": "-1",
            "search_aggregate": (
                                "`get_full_itsi_summary_service({0})`"
                                " source=service_health_monitor | stats latest(health_score) AS"
                                " aggregate"
                                ).format(service_id),
            "search_alert_earliest": "15",
            "kpi_template_kpi_id": "",
            "type": "service_health",
            "_owner": "nobody",
            "adaptive_thresholds_is_enabled": False,
            "source": "",
            "urgency": "11",
            "anomaly_detection_is_enabled": False,
            "cohesive_anomaly_detection_is_enabled": False,
            "target": "",
            "time_variate_thresholds_specification": {
                "policies": {
                    "default_policy": {
                        "policy_type": "static",
                        "title": "Default",
                        "time_blocks": [],
                        "aggregate_thresholds": {
                            "thresholdLevels": [],
                            "gaugeMax": 100,
                            "gaugeMin": 0,
                            "baseSeverityLabel": "info",
                            "metricField": "count",
                            "search": "",
                            "renderBoundaryMin": 0,
                            "baseSeverityValue": 1,
                            "baseSeverityColor": "#AED3E5",
                            "isMaxStatic": False,
                            "isMinStatic": True,
                            "baseSeverityColorLight": "#E3F0F6",
                            "renderBoundaryMax": 100
                        },
                        "entity_thresholds": {
                            "thresholdLevels": [],
                            "gaugeMax": 100,
                            "gaugeMin": 0,
                            "baseSeverityLabel": "info",
                            "metricField": "count",
                            "search": "",
                            "renderBoundaryMin": 0,
                            "baseSeverityValue": 1,
                            "baseSeverityColor": "#AED3E5",
                            "isMaxStatic": False,
                            "isMinStatic": True,
                            "baseSeverityColorLight": "#E3F0F6",
                            "renderBoundaryMax": 100
                        }
                    }
                }
            },
            "threshold_field": "aggregate",
            "aggregate_eval": "",
            "description": "",
            "search_buckets": "",
            "is_service_entity_filter": False,
            "aggregate_statop": "avg",
            "backfill_enabled": False,
            "alert_eval": "",
            "entity_statop": "avg",
            "aggregate_thresholds": {
                "thresholdLevels": [
                    {
                        "thresholdValue": 0,
                        "severityLabel": "critical",
                        "severityValue": 6,
                        "severityColor": "#B50101",
                        "severityColorLight": "#E5A6A6"
                    },
                    {
                        "thresholdValue": 20,
                        "severityLabel": "high",
                        "severityValue": 5,
                        "severityColor": "#F26A35",
                        "severityColorLight": "#FBCBB9"
                    },
                    {
                        "thresholdValue": 40,
                        "severityLabel": "medium",
                        "severityValue": 4,
                        "severityColor": "#FCB64E",
                        "severityColorLight": "#FEE6C1"
                    },
                    {
                        "thresholdValue": 60,
                        "severityLabel": "low",
                        "severityValue": 3,
                        "severityColor": "#FFE98C",
                        "severityColorLight": "#FFF4C5"
                    },
                    {
                        "thresholdValue": 80,
                        "severityLabel": "normal",
                        "severityValue": 2,
                        "severityColor": "#99D18B",
                        "severityColorLight": "#DCEFD7"
                    }
                ],
                "gaugeMax": 100,
                "isMaxStatic": False,
                "baseSeverityLabel": "normal",
                "metricField": "count",
                "search": "",
                "renderBoundaryMin": 0,
                "baseSeverityValue": 2,
                "baseSeverityColor": "#99D18B",
                "gaugeMin": 0,
                "isMinStatic": True,
                "baseSeverityColorLight": "#DCEFD7",
                "renderBoundaryMax": 100
                },
            "anomaly_detection_training_window": "-7d",
            "entity_thresholds": {
                "thresholdLevels": [
                    {
                        "thresholdValue": 0,
                        "severityLabel": "critical",
                        "severityValue": 6,
                        "severityColor": "#B50101",
                        "severityColorLight": "#E5A6A6"
                    },
                    {
                        "thresholdValue": 20,
                        "severityLabel": "high",
                        "severityValue": 5,
                        "severityColor": "#F26A35",
                        "severityColorLight": "#FBCBB9"
                    },
                    {
                        "thresholdValue": 40,
                        "severityLabel": "medium",
                        "severityValue": 4,
                        "severityColor": "#FCB64E",
                        "severityColorLight": "#FEE6C1"
                    },
                    {
                        "thresholdValue": 60,
                        "severityLabel": "low",
                        "severityValue": 3,
                        "severityColor": "#FFE98C",
                        "severityColorLight": "#FFF4C5"
                    },
                    {
                        "thresholdValue": 80,
                        "severityLabel": "normal",
                        "severityValue": 2,
                        "severityColor": "#99D18B",
                        "severityColorLight": "#DCEFD7"
                    }
                ],
                "gaugeMax": 100,
                "isMaxStatic": False,
                "baseSeverityLabel": "normal",
                "metricField": "count",
                "search": "",
                "renderBoundaryMin": 0,
                "baseSeverityValue": 2,
                "baseSeverityColor": "#99D18B",
                "gaugeMin": 0,
                "isMinStatic": True,
                "baseSeverityColorLight": "#DCEFD7",
                "renderBoundaryMax": 100
                },
            "datamodel_filter": [],
            "alert_lag": "30",
            "kpi_base_search": "",
            "base_search": (
                            "`get_full_itsi_summary_service({0})`"
                            " source=service_health_monitor"
                            ).format(service_id),
            "anomaly_detection_sensitivity": 0.999,
            "search_time_series_aggregate":(
                                            "`get_full_itsi_summary_service({0})`"
                                            " source=service_health_monitor | timechart"
                                            " avg(health_score) AS aggregate"
                                            ).format(service_id),
            "tz_offset": None,
            "is_entity_breakdown": False,
            "search_time_series": (
                                    "`get_full_itsi_summary_service({0})`"
                                    " source=service_health_monitor | timechart"
                                    " avg(health_score) AS aggregate"
                                    ).format(service_id),
            "search_alert": "",
            "search": (
                        "`get_full_itsi_summary_service({0})`"
                        " source=service_health_monitor | stats"
                        " latest(health_score) AS aggregate"
                        ).format(service_id),
            "time_variate_thresholds": False,
            "search_alert_entities": "",
            "anomaly_detection_alerting_enabled": False,
            "adaptive_thresholding_training_window": "-7d",
            "gap_severity_color": "#CCCCCC",
            "entity_id_fields": "",
            "entity_breakdown_id_fields": "",
            "alert_period": "1",
            "gap_severity": "unknown",
            "gap_severity_color_light": "#EEEEEE",
            "search_time_series_entities": "",
            "entity_alias_filtering_fields": None,
            "search_time_compare": (
                                    '`get_full_itsi_summary_service({0})`'
                                    ' source=service_health_monitor [| stats'
                                    ' count | addinfo | eval search= "earliest=" +'
                                    ' tostring(info_min_time-(info_max_time-info_min_time))+'
                                    ' " latest=" + tostring(info_max_time)'
                                    ' |fields search] | addinfo | eval'
                                    ' bucket=if(_time<info_max_time-((info_max_time-info_min_time)/2),'
                                    ' "last_window", "current_window") | stats'
                                    ' avg(health_score) AS aggregate BY bucket | reverse | delta'
                                    ' aggregate AS window_delta | search bucket=current_window |'
                                    ' eval window_direction=if(window_delta >0, "increase",'
                                    ' if(window_delta < 0, "decrease", "none"))'
                                    ).format(service_id),
            "_key": shkpi_key,
            "search_occurrences": 1,
            "backfill_earliest_time": "-7d",
            "search_type": "adhoc"
        }

    @staticmethod
    def generate_kpi_base_search():
        return {
            "title":"kpi_base_search_template",
            "description":"",
            "acl":{"can_change_perms":True,
                   "sharing":"app",
                   "can_write":True,
                   "modifiable":True,
                   "can_share_app":True,
                   "owner":"admin",
                   "perms":{"read":["*"],
                            "write":["*"]},
                   "can_share_global":True,
                   "can_share_user":True},
            "_owner":"nobody",
            "source_itsi_da":"itsi",
            "base_search":"*",
            "search_alert_earliest":"5",
            "alert_period":"5",
            "is_entity_breakdown":False,
            "entity_id_fields":"host",
            "entity_breakdown_id_fields":"",
            "entity_alias_filtering_fields":None,
            "is_service_entity_filter":False,
            "metrics":[],
            "metric_qualifier":"",
            "alert_lag":"30",
            "_user":"nobody",
            "object_type":"kpi_base_search",
            "permissions":{"read":True,
                           "user":"admin",
                           "group":{"read":True,"delete":True,"write":True},
                           "delete":True,
                           "write":True},
            "actions":"",
            "isFirstTimeSaveDone":False}


    @staticmethod
    def make_array_of_strings(arr_val):
        '''
        Make sure that this is an array of strings
        '''
        if arr_val is None:
            return None
        if type(arr_val) is not list:
            arr_val = arr_val.split(',')
        # remove whitespace in them strings
        arr_val = [i.strip() for i in arr_val]
        return arr_val

    @staticmethod
    def make_dict_from_kv_string(kv_string):
        '''
        From a comma separated list of kv pairs, construct a hash
        e.g. a=b,c=d,e=f --> {"a":"b","c":"d","e":"f"}
        '''
        if kv_string is None or len(kv_string) == 0:
            return None
        kv_array = kv_string.split(',')
        kv_dict = {}
        for i in kv_array:
            # TODO: Now that I think about it, pair could actually
            # be more than a pair.  Would require some changes to
            # the mapping structure
            pair = i.split("=")
            # Remove the leading and trailing whitespaces
            if len(pair) == 1:
                continue  # key is equal to nothing :( sad panda
            if len(pair[1]) == 0:
                continue  # key is equal to nothing :( sad panda
            pair = [x.strip() for x in pair]
            kv_dict[pair[0]] = pair[1]  # For now we'll ignore anything beyond the first k=v
        return kv_dict

    @staticmethod
    def make_dict_from_string(dict_string):
        """
        @type dict_string: basestring
        @param dict_string: a string

        @rtype: dict[list]|None
        @return: a valid dictionary from dict_string or None
        """
        if not isinstance(dict_string, basestring) or len(dict_string) == 0:
            return None

        try:
            final_dict = json.loads(dict_string)
            if isinstance(final_dict, dict):
                return {k: ITOAInterfaceUtils.make_array_of_strings(v) for k, v in final_dict.iteritems()}
        except ValueError:
            pass

        return None

    @staticmethod
    def _validate_keys_in_json(keys_as_list, json_object):
        '''
        Validates if keys are present in given json_object
        @param keys_as_list: List of keys to check in json_object
        @param json_object: json object to verify against

        @return True if valid; False if invalid
        @return missing key as string
        '''
        for key in keys_as_list:
            if key not in json_object:
                return False, key
        return True, ""

    @staticmethod
    def trim_dict(obj_as_dict, remove_fields):
        '''
        From a given dictionary, remove fields we dont want...
        @param json_obj - dictionary to work on
        @param remove_fields - list of fields to remove
        @return set of fields that were removed...
        '''
        set_of_removed = set()

        if any([
            not isinstance(obj_as_dict, dict),
            isinstance(obj_as_dict, dict) and len(obj_as_dict) == 0,
            len(remove_fields) == 0
            ]):
            return set_of_removed

        for field in remove_fields:
            removed_field = obj_as_dict.pop(field, None)
            if removed_field is not None:
                set_of_removed.add(removed_field)
        return set_of_removed

    @staticmethod
    def replace_append_info(json_obj, replace_fields={}, replace_fields_types={}, add_fields={}):
        '''
        In json_obj, replace some fields, and add some new fields....
        @param json_obj: dict to work on...
        @param replace_fields: represents existing/old field,
                value represents new field to replace with
                {'old_field':'new_field'} replace 'old_field' by 'new_field'
        @param replace_fields_types: types of these new fields from above....
                                {'new_field':str/list/dict/...}
        @param add_fields = fields to add, key represents new field; value represents type of new field
                                {'add_this_new_field': str/list/dict/...}
        @return return True if successful, False if otherwise
        '''
        if len(replace_fields) > 0:
            if len(replace_fields_types) == 0:
                return False, ('replace_fields={} needs replace_fields_types={}'
                        'to be valid/non-empty').format(
                                                json.dumps(replace_fields),
                                                json.dumps(replace_fields_types))

        # replace some fields...
        for field in replace_fields:
            if json_obj.get(field) is not None and json_obj.get(replace_fields[field]) is None:
                existing_type = type(json_obj[field])  # fetch existing type
                json_obj[replace_fields[field]] = existing_type(
                    json_obj[field])  # create new field with same type & value
                del json_obj[field]  # delete existing
            else:
                # add this new field even if it's old nemesis doesn't exist
                if json_obj.get(replace_fields[field]) is None:
                    json_obj[replace_fields[field]] = replace_fields_types[replace_fields[field]]()

        # now add some fields if needed...
        for field in add_fields:
            if json_obj.get(field) is None:
                json_obj[field] = add_fields[field]()

        return True, ''

    @staticmethod
    def get_version_from_kv(session_key, hostpath=None):
        '''
        Collect version information from kv
        @param {string} session_key: session key
        @param {string} hostPath: splunkd uri

        @rtype tuple
        @return tuple: tuple of
                {string} old version
                {string} KV stanza key which old version information
        '''
        uri = ITOAInterfaceUtils.KV_STORE_NEW_MIGRATION_COLLECTION_URI
        if hostpath:
            uri = hostpath + uri
        getargs = {'query': json.dumps({"itsi_latest_version": {"$gt": "1.0.0"}})}
        # There is issue, if we call this function in modular input too soon,
        # we get 503 error which Service Unavailable
        # this means that KV store has not initialized yet
        # Also, we wait for 2 min in case of SHC rolling restart
        retry = 1
        while retry <= 24:
            rsp, content = rest.simpleRequest(uri, sessionKey=session_key,
                                              raiseAllErrors=False, getargs=getargs)
            if rsp.status != 503:
                break
            logger.info("KV store service is unavailable. Retry %s of 24", str(retry))
            time.sleep(5)
            retry += 1

        if rsp.status != 200 and rsp.status != 201:
            logger.error("Got bad status code %s - Aborting. Response %s", rsp.status, rsp)
            raise Exception(_("Got bad status code %s - Aborting.") % rsp.status)

        # Update existing schema
        logger.debug("uri:%s return content:%s", ITOAInterfaceUtils.KV_STORE_COLLECTION_URI, content)
        json_data = json.loads(content)

        if len(json_data) == 0:
            logger.info("Could not find any migration stanza. It seems to be fresh installation")
            return None, None
        else:
            entry = json_data[0]
            old_version = entry.get('itsi_latest_version')
            key = entry.get('_key')
            logger.info("Collected version:%s from kv, schema _key:%s", old_version, key)
            return old_version, key

    @staticmethod
    def update_version_to_kv(session_key, id, new_version, old_version, is_migration_done):
        '''
        Update version information to KV
        @param {string} session_key: Splunk session key
        @param {string} id: KV store schema id, if id is none then create new stanza
        @param {string} new_version: new version
        @param {string} old_version: old version
        @param {boolean} flag for if migration_done or not

        @rtype boolean (True/False)
        @return flag if data is updated successfully
        '''
        uri = ITOAInterfaceUtils.KV_STORE_NEW_MIGRATION_COLLECTION_URI
        if id:
            uri = uri + '/' + id

        migration_title = "version_info_update_record_{0}".format(int(itoa_common.get_current_utc_epoch()))
        data = {"title": migration_title,
                "itsi_latest_version": new_version,
                "itsi_old_version": old_version,
                "object_type": "migration",
                "is_migration_done": is_migration_done
                }
        rsp, content = rest.simpleRequest(uri, sessionKey=session_key,
                            raiseAllErrors=False, jsonargs=json.dumps(data), method='POST')
        if rsp.status != 200 and rsp.status != 201:
            logger.error("Got bad status code %s - Aborting.  Response %s", rsp.status, rsp)
            return False
        logger.info('Successful update KV store with latest_version:%s, old_version:%s, is_migration_done:%s',
                    new_version, old_version, is_migration_done)
        return True

    @staticmethod
    def _get_launcher_uri(app, owner):
        '''
        Return uri for get version of app
        @param {string} app: app name
        @param {string} owner: owner name
        '''
        return rest.makeSplunkdUri() + 'servicesNS/' + owner + '/' + app + '/configs/conf-app/launcher'

    @staticmethod
    def get_app_version(session_key, app="itsi", owner="nobody", fetch_conf_only=False):
        '''
        Get app version from app.conf file

        @type: string
        @param session_key - session key

        @type: string
        @param app - app name

        @type: string
        @param owner - owner name

        @type: boolean
        @param fetch_conf_only - is cached version for app okay to use or not, True indicates no

        @return version number or None
        @rtype string/None
        '''
        if (
            not fetch_conf_only and
            app.lower() == 'itsi' and
            VersionCheck.validate_version(current_itsi_app_version, is_accept_empty=False)
        ):
            return current_itsi_app_version

        try:
            getargs = {'output_mode': 'json'}
            response, content = rest.simpleRequest(ITOAInterfaceUtils._get_launcher_uri(app, owner),
                                                   sessionKey=session_key, getargs=getargs)
            if response.status != 200 and response.status != 201:
                logger.error("Failed to get app:%s version, error:%s", app, response)
                return None
            else:
                json_data = json.loads(content)
                entry = json_data.get('entry')[0]
                content = entry.get('content')
                logger.debug("App Version Content: %s of uri:%s", content, ITOAInterfaceUtils._get_launcher_uri(app, owner))
                return content.get('version')
        except Exception as e:
            logger.exception(e)
            return None

    @staticmethod
    def create_message(session_key, description, severity='info', app='itsi', owner='nobody'):
        '''
        Create splunk system message
        @param {string} session_key - splunk session key
        @param {string} description - app name
        @param {string} app - app
        @param {string} owner - owner
        @return nothing
        '''
        logger.info("Creating system message:%s", description)
        return post_splunk_user_message(
            description,
            session_key=session_key,
            severity=severity,
            namespace=app,
            owner=owner
        )

    @staticmethod
    def get_modular_input(session_key, app, owner, mod_input_name, mod_instance_name):
        """
        Get modular inputs

        @type session_key: basestring
        @param session_key: splunkd session key

        @type app: basestring
        @param app: app name under which modular input is needed

        @type owner: basestring
        @param owner: user name

        @type mod_input_name: basestring
        @param mod_input_name: Modular input name

        @type mod_instance_name: mod_instance_name
        @param mod_instance_name: modular input instance name

        @rtype: object
        @return: Entity object
        """
        entity_path = "/data/inputs/" + mod_input_name
        return getEntity(entity_path, mod_instance_name, sessionKey=session_key, namespace=app, owner=owner)

    @staticmethod
    def create_modular_input(session_key, app, owner, mod_input_name, post_args):
        """
        Create modular input

        @type session_key: basestring
        @param session_key: splunkd session key

        @type app: basestring
        @param app: app name under which modular input is needed

        @type owner: basestring
        @param owner: user name

        @type mod_input_name: basestring
        @param mod_input_name: Modular input name

        @type post_args: dict
        @param post_args: Optional and required post_args of modular input to create it
                         Note: Must contain instance name in 'name' attribute of dict

        @rtype: bool
        @return: True - if operation is successful otherwise False
        """
        entity_path = "/data/inputs/" + mod_input_name
        entity = getEntity(entity_path, '_new', sessionKey=session_key, namespace=app, owner=owner)
        # Content must contain required parameters
        ITOAInterfaceUtils.update_modular_input(session_key, entity, post_args)

    @staticmethod
    def control_modular_input(session_key, app, owner, mod_input_name, mod_instance_name, action):
        """
        Perform remove/enable/disable modular input

        @type session_key: basestring
        @param session_key: splunkd session key

        @type app: basestring
        @param app: app name under which modular input is needed

        @type owner: basestring
        @param owner: user name

        @type mod_input_name: basestring
        @param mod_input_name: modular input name

        @type mod_instance_name: basestring
        @param mod_instance_name: modular input instance name

        @type action: basestring
        @param action: action name ('remove', 'enable', 'disable')

        @rtype: bool
        @return: True - if operation is successful otherwise False
        """
        entity_path = "/data/inputs/" + mod_input_name
        uri = buildEndpoint(entity_path, entityName=mod_instance_name, namespace=app, owner=owner)
        if action == 'enable':
            uri += '/enable'
        if action == 'disable':
            uri += '/disable'
        return controlEntity(action, uri, session_key)

    @staticmethod
    def delete_modular_input(session_key, app, owner, mod_input_name, mod_instance_name):
        """
        Delete modular input

        @type session_key: basestring
        @param session_key: splunkd session key

        @type app: basestring
        @param app: app name under which modular input is needed

        @type owner: basestring
        @param owner: user name

        @type mod_input_name: basestring
        @param mod_input_name: Modular input name

        @type mod_instance_name: basestring
        @param mod_instance_name: modular input instance name

        @rtype: bool
        @return: True - if operation is successful otherwise False
        """
        entity_path = "/data/inputs/" + mod_input_name
        return deleteEntity(entity_path, mod_instance_name, app, owner, sessionKey=session_key)

    @staticmethod
    def update_modular_input(session_key, entity, post_arguments):
        """
        Update modular input
        @type session_key: basestring
        @param session_key: session_key

        @type entity: object
        @param entity: Entity object which hold information for a modualr input

        @type post_arguments: dict
        @param post_arguments: properties to set

        @rtype: bool
        @return: True - if operation is successful otherwise False
        """
        if not entity or not isinstance(entity, Entity):
            logger.error("Invalid entity, failed to update")
            return False

        # Content must contain required parameters
        for key in entity.requiredFields:
            if key in post_arguments.keys():
                entity[key] = post_arguments.get(key)
            else:
                logger.debug("Required field %s does not exits, hence can't create new entity", key)
                return False

        for opt_key in entity.optionalFields:
            if opt_key in post_arguments.keys():
                entity[opt_key] = post_arguments.get(opt_key)
        return setEntity(entity, sessionKey=session_key)

    @staticmethod
    def merge_with_sec_filter(filter_data, sec_filter_data):
        """
        Combined the security group filter with user custom filer
        @type filter_data: dict
        @param filter_data: custom filter
        @type sec_filter_data: dict
        @param sec_filter_data: security group filter (generated by system)
        @rtype: dict
        @return: a merged filter
        """
        new_filter = {}
        if filter_data and sec_filter_data:
            if '$or' in filter_data.keys() or '$and' in filter_data.keys():
                new_filter = {'$and': [filter_data]}
                new_filter['$and'].append(sec_filter_data)
            else:
                new_filter.update(filter_data)
                new_filter.update(sec_filter_data)
        elif sec_filter_data:
            new_filter = sec_filter_data
        else:
            new_filter = filter_data

        return new_filter

    @staticmethod
    def remove_illegal_character_from_entity_rules(entity_rules):
        """
        Replace illegal characters in a string with ''
    
        @type string: list
        @param string: entity rules to replace special chars
        """
        replace_fields = ['field', 'value']
        if not itoa_common.is_valid_list(entity_rules):
            logger.warning('Invalid entity rules: {}'.format(entity_rules))
            return
        for entity_rule in entity_rules:
            for rule_item in entity_rule.get('rule_items', []):
                for replace_field in replace_fields:
                    if replace_field in rule_item:
                        for illegal_character in ILLEGAL_CHARACTERS:
                            rule_item[replace_field] = rule_item[replace_field].replace(illegal_character, '')


class ItsiSettingsImporter(itoa_common.ItoaBase):
    log_prefix = 'ItsiSettingsImporter'

    conf_prefix = 'itsi_'
    app = 'SA-ITOA'

    supported_settings = [
        # Import these before others below
        [
            'team'
        ],
        # Having imported dependencies above, now import these
        [
            'service',
            'deep_dive',
            'glass_table',
            'kpi_base_search',
            'kpi_template',
            'kpi_threshold_template'
        ]
    ]

    skip_setting_update = ['kpi_threshold_template']

    def __init__(self, session_key):
        super(ItsiSettingsImporter, self).__init__(session_key)

    def import_itsi_settings(self, owner):
        '''
        Imports ITSI settings from conf files across apps
        Note that this imports KPI template settings for ITSI modules

        @rtype: boolean
        @return: indicates if import succeeded (True) or had one or more failures (False)
        '''
        settings_urls = self.find_settings_urls()
        return self.import_setting(owner=owner, itsi_settings_urls=settings_urls)

    @staticmethod
    def get_supported_settings_conf_names():
        settings_conf_names = []
        for settings_list in ItsiSettingsImporter.supported_settings:
            settings_conf_names.append([
                (ItsiSettingsImporter.conf_prefix + setting)
                for setting in settings_list
            ])
        return settings_conf_names

    def find_settings_urls(self):
        '''
        Using splunkd rest, we'll grab the stanzas from the ITSI confs for all apps
        settings on the local host and spit them out

        @rtype: list of dict
        @return: a list of dict of urls corresponding to stanza names for ITSI settings found
            The dicts in the list MUST be imported in that order for dependency management
        '''
        settings_urls = []

        # First, check to see that the endpoints exist in the properties
        properties_location = '/servicesNS/nobody/' + urllib.quote_plus(self.app) + '/properties'
        rsp, content = rest.simpleRequest(
            properties_location,
            sessionKey=self.session_key,
            raiseAllErrors=False,
            getargs={'output_mode': 'json'}
        )

        if rsp.status != 200 and rsp.status != 201:
            logger.error("Error getting properties root %s", properties_location)
            return settings_urls

        properties_dict = json.loads(content)
        settings_names_found = [prop['name'] for prop in properties_dict['entry']]

        # Filter out the ones not returned by end point
        supported_settings_found_in_conf = []
        for settings_list in self.get_supported_settings_conf_names():
            supported_settings_found_in_conf.append([
                setting for setting in settings_list if setting in settings_names_found
            ])

        for settings_list in supported_settings_found_in_conf:
            settings_urls_dict = {}
            for setting_name in settings_list:
                path = properties_location + '/' + urllib.quote_plus(setting_name)
                rsp, content = rest.simpleRequest(
                    path,
                    sessionKey=self.session_key,
                    raiseAllErrors=False,
                    getargs={'output_mode': 'json'}
                )
                if rsp.status != 200 and rsp.status != 201:
                    logger.error('Error getting data from rest endpoint %s', path)
                    continue

                try:
                    config = json.loads(content)
                    #Strip the conf prefix from the stanza
                    prefix_stripped_setting = setting_name[len(self.conf_prefix):]
                    settings_urls_dict[prefix_stripped_setting] = []
                    for entry in config['entry']:
                        url = entry.get('id')
                        if url != None:
                            settings_urls_dict[prefix_stripped_setting].append(url)
                except Exception:
                    logger.exception('Error parsing json content')
            settings_urls.append(settings_urls_dict)
        return settings_urls

    def get_itsi_setting(self, setting_stanza_path):
        '''
        The itsi_stuff_dict commonly contains urls of records stored in conf files
        that need to be stored elsewhere, so we'll grab them from their locations online
        and make sure that these are in a format acceptable to for input

        @type setting_stanza_path: string
        @param setting_stanza_path: path (url) for the stanza to read settings from

        @rtype: dict
        @return: stanza content for the given path
        '''
        rsp, content = rest.simpleRequest(
            setting_stanza_path,
            sessionKey=self.session_key,
            raiseAllErrors=False,
            getargs={'output_mode': 'json'}
        )
        if rsp.status != 200:
            logger.error('Record %s not found, ignoring', setting_stanza_path)
            return None
        try:
            _key = os.path.split(setting_stanza_path)[1]
            normalized_setting = {}
            config = json.loads(content)
            for entry in config['entry']:
                title = entry['name']
                content = entry['content']

                # Normalize conf values to Python

                # Talk to owner of SVG viz in Glass Table before changing the next line
                if title == 'svg_content' or title == 'svg_coordinates':
                    # There are some interesting things with glass table here
                    logger.debug('Special case string for SVG viz in glass table')
                elif (content.startswith('[') and content.endswith(']')) or (
                        content.startswith('{') and content.endswith('}')):
                    logger.debug('Entry %s key %s is json', _key, title)
                    content = json.loads(content)

                if type(content) in [str, unicode]:
                    if content.lower() == 'true':
                        content = True
                    elif content.lower() == 'false':
                        content = False
                    elif content == 'null':
                        content = None

                normalized_setting[title] = content
            normalized_setting['_key'] = _key
            return normalized_setting
        except Exception:
            logger.exception('Error parsing json content from %s, possibly malformed, ignoring', setting_stanza_path)
            return None

    def import_setting(self, owner, itsi_settings_urls):
        '''
        Imports the information into the statestore backend, or whatever backend you're using (skipping if
        conf files are being used, because duh, thats where we're getting the information from originally)
        It will retain all of the original information, including the default service ids, entity ids, kpi ids, etc)

        @type itsi_settings_urls: list of dict
        @param itsi_settings_urls: list of dicts mapping setting to its url to be imported in the order in the list
            for dependency management

        @rtype: boolean
        @return: indicates if import succeeded (True) or had one or more failures (False)
        '''
        itoa = ITOAStorage()
        if itoa.backend == 'conf':
            return False

        # Check if kv store is ready to perform operation
        # Wait for max 5 minutes then gave up so we can take of it
        if not itoa.wait_for_storage_init(self.session_key):
            is_all_import_success = False
            raise Exception(_("KV Store is not initialized. We have tried for 5 minutes but KV store still not available."))

        is_all_import_success = True
        # Other methods we'll go through the official apis to transfer things
        for itsi_settings_urls_dict in itsi_settings_urls:
            for setting_name in itsi_settings_urls_dict.keys():
                logger.debug('Importing settings of type %s', setting_name)
                for path in itsi_settings_urls_dict[setting_name]:
                    normalized_setting = self.get_itsi_setting(setting_stanza_path=path)
                    if normalized_setting == None:
                        logger.error('Unable to process setting at path %s, ignoring ...', path)
                        is_all_import_success = False
                        continue

                    if normalized_setting.get('_key') in BLACK_LIST:
                        continue

                    try:
                        # Since importing of settings is only expected once on DA installation,
                        # only add settings that dont already exist
                        object_of_type = instantiate_object(
                            self.session_key,
                            'nobody',
                            setting_name,
                            logger=logger
                        )
                        if normalized_setting.get('_immutable') is None:
                            normalized_setting['_immutable'] = 1
                        if object_of_type.get(owner, normalized_setting.get('_key', '')) is None:
                            object_of_type.create(owner, normalized_setting)
                        else:
                            if setting_name not in self.skip_setting_update:
                                logger.info(
                                    'Setting for %s with key %s already exists, updating it.',
                                    setting_name,
                                    normalized_setting['_key']
                                )
                                # In case of version upgrade, if setting changes, we need to update it
                                object_of_type.update(owner, normalized_setting.get('_key'), normalized_setting)
                            else:
                                # No need to update kpi threshold template setting if it already exists in kvstore.
                                # This is done to mitigate resetting of adaptive thresholds for KPIs which use
                                # threshold templates (ITOA-10536).
                                logger.info(
                                    'Setting for %s with key %s already exists, skip updating the object.',
                                    setting_name,
                                    normalized_setting['_key']
                                )
                    except Exception:
                        logger.exception('Unable to import setting: %s of type %s, ignoring',
                                normalized_setting.get('_key', 'Unknown'), setting_name)
                        is_all_import_success = False

        return is_all_import_success

    def _get_splunk_host_port(self):
        uri = '/services/server/settings'
        params = {
                "output_mode":"json"
            }

        try:
            res, contents = rest.simpleRequest(uri,
                                        method='GET',
                                        sessionKey=self.session_key,
                                        getargs=params)
            if res.status == 200:
                settings = json.loads(contents)
                entity = settings["entry"]
                host = '127.0.0.1'
                port = entity[0].get('content').get('mgmtHostPort')

                if not port:
                    port = 8089
                return (host, port)

        except Exception as e:
            return ("localhost", 8089)

    def import_team_setting(self, owner, from_conf=True):
        """
        Imports the just the team setting from conf or hardcoded setting

        @type owner: string
        @param owner: owner of the object

        @type from_conf: boolean
        @param from_conf: if user wants to import the setting from conf file

        @rtype: boolean
        @return: indicates if import succeeded (True) or had one or more failures (False)
        """
        import_status = True
        setting_name = 'team'
        if from_conf:
            (host, port) = self._get_splunk_host_port()
            team_setting_url = \
                'https://' + host + ':' + str(port) + '/servicesNS/nobody/SA-ITOA/properties/itsi_team/default_itsi_security_group'
            normalized_setting = self.get_itsi_setting(setting_stanza_path=team_setting_url)
        else:
            normalized_setting = {
                'description': 'Default team for ITSI',
                'title': 'global',
                '_immutable': 0,
                '_key': 'default_itsi_security_group',
                'acl': {
                    'read': ['itoa_admin', 'itoa_analyst', 'itoa_user'],
                    'delete': ['itoa_admin'],
                    'write': ['itoa_admin'],
                    'owner': 'nobody'
                }
            }
        try:
            object_of_type = instantiate_object(
                self.session_key,
                'nobody',
                setting_name,
                logger=logger
            )
            if normalized_setting.get('_immutable') is None:
                normalized_setting['_immutable'] = 1
            if object_of_type.get(owner, normalized_setting.get('_key', '')) is None:
                object_of_type.create(owner, normalized_setting)
            else:
                logger.info('Team setting already exists. No need to override team setting.')
        except Exception as e:
            logger.error('Unable to import team setting: {}'.format(str(e)))
            import_status = False

        return import_status

