#!/usr/bin/env python
import json
import logging
import math

import splunk
from mad_lib.mad_util import MADRESTException, discover_jvm, check_valid_uuid, check_allowed_params, check_arrays, get_field
from mad_lib.mad_splunk_util import setup_logging, get_user_capabilities
from mad_lib.mad_kv import MADKVStoreManager
from mad_lib.mad_savedsearches import MADSavedSearchManager
from mad_lib.mad_conf import MADConfManager
from mad_lib.mad_dom import MADContext, MADInstance

APP_ID = "SA-ITSI-MetricAD"

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

import splunk.rest.external

splunk.rest.external.__path__.insert(0, make_splunkhome_path(['etc', 'apps', APP_ID, 'lib']))
from splunklib import client, binding

logger = setup_logging('mad_rest.log', 'mad_rest', level=logging.DEBUG)

CONTEXT_KVCOLLECTION_NAME = "service_context"
INSTANCE_KVCOLLECTION_NAME = "instance_config"
HOST_URL = "%s://%s:%s/servicesNS" % (splunk.getDefault('protocol'), splunk.getDefault('host'), splunk.getDefault('port'))
WRITE_CAPABLE = 'write_metric_ad'
READ_CAPABLE = 'read_metric_ad'

REST_BASE_PART = ["services", "metric_ad"]

splunk.setDefault("namespace", binding.namespace("global", "nobody", APP_ID))


class MADRequestResponse(object):
    def __init__(self, status_code, json_msg):
        self.status_code = status_code
        self.json_msg = json_msg


class MADRestHandler(splunk.rest.BaseRestHandler):
    def __init__(self, method, requestInfo, responseInfo, sessionKey):
        super(MADRestHandler, self).__init__(method, requestInfo, responseInfo, sessionKey)

    @staticmethod
    def get_valid_bulk_delete(args):
        check_allowed_params(args, ['instanceIds'])
        accepted_params = {}
        try:
            accepted_params["instanceIds"] = json.loads(get_field(args, "instanceIds"))
        except:
            raise MADRESTException("invalid json format", logging.ERROR, status_code=400)
        check_arrays(accepted_params, ["instanceIds"])
        for instanceId in accepted_params["instanceIds"]:
            check_valid_uuid(instanceId)
        return accepted_params

    @staticmethod
    def get_valid_url_params(args):
        accepted_params = {}

        if "limit" in args:
            accepted_params["limit"] = args["limit"]
        if "skip" in args:
            accepted_params["skip"] = args["skip"]
        return accepted_params

    # ---------------------------- Context Related Logic -----------------------------
    @staticmethod
    def get_context(kv_mgr, context_name):
        context_kv_json = kv_mgr.get(CONTEXT_KVCOLLECTION_NAME, context_name, params=[])
        return MADContext.from_kv_json(context_kv_json)

    @staticmethod
    def handle_context_update(kv_mgr, saved_search_mgr, context_name, new_args):
        old_context = MADRestHandler.get_context(kv_mgr, context_name)
        new_context = old_context.update(new_args)
        # Check if it's actually changed
        if old_context != new_context and old_context.managed_saved_search:
            # In the current implementation, ANY change to context requires us to restart the search
            saved_search_mgr.update(new_context)

        kv_mgr.update(CONTEXT_KVCOLLECTION_NAME, old_context.name, new_context.to_kv_json())
        return new_context.to_json()

    @staticmethod
    def handle_context_delete(kv_mgr, saved_search_mgr, context_name):
        old_context = MADRestHandler.get_context(kv_mgr, context_name)
        if old_context.managed_saved_search:
            # delete saved search
            saved_search_mgr.delete(old_context.name)

        # delete all instances
        instances = kv_mgr.get_all(INSTANCE_KVCOLLECTION_NAME, {"query": json.dumps({"contextName": old_context.name})})
        for i in instances:
            kv_mgr.delete(INSTANCE_KVCOLLECTION_NAME, i["_key"])

        # we return nothing from delete
        kv_mgr.delete(CONTEXT_KVCOLLECTION_NAME, old_context.name)
        return None

    @staticmethod
    def handle_context_create(kv_mgr, saved_search_mgr, args):
        # validate the incoming request params
        new_context = MADContext.from_args(args)
        try:
            old_context = MADRestHandler.get_context(kv_mgr, new_context.name)
            if old_context:
                raise MADRESTException("context [%s] already exists" % new_context.name, logging.ERROR, status_code=400)
        except MADRESTException as e:
            if e.status_code == 404:
                pass
            else:
                raise e

        if new_context.managed_saved_search:
            # create an all-time real-time saved search with the params
            saved_search_mgr.create(new_context)

        kv_mgr.create(CONTEXT_KVCOLLECTION_NAME, new_context.to_kv_json())
        return new_context.to_json()

    @staticmethod
    def handle_context_get_all(kv_mgr, args):
        # check to see if we have 'limit' or 'skip', they are supported by kv store REST API, can be passed on
        extra_params = MADRestHandler.get_valid_url_params(args)
        results = kv_mgr.get_all(CONTEXT_KVCOLLECTION_NAME, extra_params)
        for idx, item in enumerate(results):
            results[idx] = MADContext.from_kv_json(item).to_json()
        return results

    # ------------------------------- Instance Related Logic ----------------------------
    @staticmethod
    def get_instance(conf_mgr, kv_mgr, instance_id):
        res = kv_mgr.get(INSTANCE_KVCOLLECTION_NAME, instance_id, params={})
        instance = MADInstance.from_kv_json(conf_mgr, res)
        return instance

    @staticmethod
    def handle_instance_bulk_delete(kv_mgr, args):
        params = MADRestHandler.get_valid_bulk_delete(args)
        removed = []
        for instance in params["instanceIds"]:
            kv_mgr.delete(INSTANCE_KVCOLLECTION_NAME, instance)
            removed.append(instance)
        return removed

    @staticmethod
    def handle_instance_delete(conf_mgr, kv_mgr, instance_id):
        MADRestHandler.get_instance(conf_mgr, kv_mgr, instance_id)
        kv_mgr.delete(INSTANCE_KVCOLLECTION_NAME, instance_id)
        return None

    @staticmethod
    def handle_instance_update(conf_mgr, kv_mgr, instance_id, args):
        old_instance = MADRestHandler.get_instance(conf_mgr, kv_mgr, instance_id)
        new_instance = old_instance.update(args, conf_mgr)
        kv_mgr.update(INSTANCE_KVCOLLECTION_NAME, instance_id, new_instance.to_kv_json())
        return new_instance.to_json()

    @staticmethod
    def handle_instance_create(conf_mgr, kv_mgr, context_name, args):
        new_instance = MADInstance.from_args(conf_mgr, args, context_name)
        kv_mgr.create(INSTANCE_KVCOLLECTION_NAME, new_instance.to_kv_json())
        return new_instance.to_json()

    @staticmethod
    def handle_instance_bulk_create(conf_mgr, kv_mgr, context_name, args):
        try:
            json_args = json.loads(args['data'])
        except Exception:
            err_msg = 'Bulk creation of instances requires data list to be passed in the form' \
                  ' of encoded json. Expected data input form = \'{{"data" : <data_list>}}\'.'
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=400)

        if not isinstance(json_args, list):
            err_msg = 'Bulk creation of instances requires input data to be in the form of list.'
            raise MADRESTException(err_msg, logging.ERROR, status_code=400)

        if len(json_args) == 0:
            logger.warning('Empty array passed for bulk creation of instances. No operation required.')
            return []

        instance_list = []
        for instance in json_args:
            new_instance = MADInstance.from_args(conf_mgr, instance, context_name)
            instance_list.append(new_instance.to_kv_json())
        response = kv_mgr.create_bulk(INSTANCE_KVCOLLECTION_NAME, instance_list)
        return response

    @staticmethod
    def handle_instance_get_all(conf_mgr, kv_mgr, context_name, args):
        mongoQuery = {"contextName": context_name}
        if "kv_query" in args:
            mongoQuery.update(json.loads(args["kv_query"]))
        extra_params = {"query": json.dumps(mongoQuery)}
        extra_params.update(MADRestHandler.get_valid_url_params(args))
        results = kv_mgr.get_all(INSTANCE_KVCOLLECTION_NAME, extra_params)
        for idx, item in enumerate(results):
            results[idx] = MADInstance.from_kv_json(conf_mgr, item).to_json()
        return results

    @classmethod
    def process_request(cls, request_type, session_key, path_parts, args):

        url_parts = path_parts[len(REST_BASE_PART):]
        url_parts_length = len(url_parts)

        # special endpoint /services/metric_ad/jvm
        if url_parts[0] == "jvm" and len(url_parts) == 1:
            return discover_jvm()

        # all other endpoints requires additional connection to splunk
        try:
            splunk_service = client.connect(host=splunk.getDefault('host'),
                                            port=splunk.getDefault('port'),
                                            scheme=splunk.getDefault('protocol'),
                                            owner=None,
                                            sharing="app",
                                            app=APP_ID,
                                            token=session_key)
        except Exception:
            err_msg = "Unable to connect to splunk"
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=500)

        saved_search_mgr = MADSavedSearchManager(splunk_service)
        conf_mgr = MADConfManager(splunk_service)
        kv_mgr = MADKVStoreManager(HOST_URL, APP_ID, session_key)

        # handles /services/metric_ad/contexts/*
        if 1 <= url_parts_length <= 2 and url_parts[0] == "contexts":
            # handles /context/{name}
            if url_parts_length == 2:
                context_name = MADContext.check_name(url_parts[1])
                if request_type == "GET":
                    return MADRestHandler.get_context(kv_mgr, context_name).to_json()
                if request_type == "POST":
                    return MADRestHandler.handle_context_update(kv_mgr, saved_search_mgr, context_name, args)
                if request_type == "DELETE":
                    return MADRestHandler.handle_context_delete(kv_mgr, saved_search_mgr, context_name)

            # handles /context
            else:
                if request_type == "GET":
                    return MADRestHandler.handle_context_get_all(kv_mgr, args)
                if request_type == "POST":
                    return MADRestHandler.handle_context_create(kv_mgr, saved_search_mgr, args)

        # handles /contexts/{context_name}/instances/*
        elif 3 <= url_parts_length <= 5 and url_parts[2] == "instances":

            # try to get the context to see if it exists, but the context itself is not being used here
            context_name = MADContext.check_name(url_parts[1])
            MADRestHandler.get_context(kv_mgr, context_name)

            # handles /contexts/{context_id}/instances/{instance_id or bulk-delete or bulk-create}
            if url_parts_length >= 4:

                # Update an instance of the given MAD Service Context.
                instance_or_command = url_parts[3]
                if instance_or_command == "bulk-delete":
                    if request_type == "POST":
                        return MADRestHandler.handle_instance_bulk_delete(kv_mgr, args)
                if instance_or_command == "bulk-create":
                    if request_type == "POST":
                        return MADRestHandler.handle_instance_bulk_create(conf_mgr, kv_mgr, context_name, args)
                else:
                    instance_id = check_valid_uuid(instance_or_command)
                    # handles /contexts/{context_name}/instances/{instance_id}/sensitivity
                    if url_parts_length == 5:
                        config_type = url_parts[4]
                        if config_type == "sensitivity":
                            instance = MADRestHandler.get_instance(conf_mgr, kv_mgr, instance_id)

                            if request_type == "POST":
                                if "action" in args:
                                    if args["action"] == "up": # sensitivity "up" = decrease Naccum
                                        new_sensitivity = instance.sensitivity + 1
                                    elif args["action"] == "down": # sensitivity "down" = increase Naccum
                                        new_sensitivity = instance.sensitivity - 1
                                    else:
                                        raise MADRESTException("invalid 'action' parameter: '%s'" % args["action"], logging.ERROR, status_code=400)

                                    return MADRestHandler.handle_instance_update(conf_mgr, kv_mgr, instance.instance_id, {"sensitivity": new_sensitivity})
                                else:
                                    raise MADRESTException("'action' parameter is required", logging.ERROR, status_code=400)

                    else:
                        if request_type == "GET":
                            return MADRestHandler.get_instance(conf_mgr, kv_mgr, instance_id).to_json()
                        if request_type == "POST":
                            return MADRestHandler.handle_instance_update(conf_mgr, kv_mgr, instance_id, args)
                        if request_type == "DELETE":
                            return MADRestHandler.handle_instance_delete(conf_mgr, kv_mgr, instance_id)


            # handles /contexts/{context_name}/instances
            else:
                if request_type == "GET":
                    return MADRestHandler.handle_instance_get_all(conf_mgr, kv_mgr, context_name, args)
                if request_type == "POST":
                    return MADRestHandler.handle_instance_create(conf_mgr, kv_mgr, context_name, args)

        else:
            # unsupported URL & request type all get here
            raise MADRESTException("requested URL does not exist", logging.ERROR, status_code=404)

    def handle_request(self, request_type, *capabilities):

        splunk.setDefault('sessionKey', self.sessionKey)
        current_user = self.request['userName']

        try:
            self._is_authorized(current_user, *capabilities)
            json_response = MADRestHandler.process_request(request_type, self.sessionKey, self.pathParts, self.args)
            response = MADRequestResponse(200, json_response)
        except MADRESTException as e:
            response = MADRequestResponse(e.status_code, e.to_json())
        except Exception as e:
            logger.exception("Unknown exception")
            mad_e = MADRESTException(str(e), logging.ERROR, status_code=500)
            response = MADRequestResponse(mad_e.status_code, mad_e.to_json())

        self.response.setStatus(response.status_code)
        # content of response purposely set to None for blank response in DELETE etc.
        if response.json_msg is not None:
            self.response.setHeader('content-type', 'application/json')
            self.response.write(json.dumps(response.json_msg))
        else:
            self.response.write("")

    def _is_authorized(self, user, *capabilities):

        user_capabilities = get_user_capabilities(user)

        authorized = False
        if len(capabilities) > 0:
            authorized = all(capability in user_capabilities for capability in capabilities)
        if not authorized:
            raise MADRESTException("insufficient capabilities to complete this action", logging.ERROR, status_code=401)

        return authorized

    def handle_GET(self):
        self.handle_request("GET", READ_CAPABLE)
        return

    def handle_POST(self):
        self.handle_request("POST", READ_CAPABLE, WRITE_CAPABLE)
        return

    def handle_DELETE(self):
        self.handle_request("DELETE", READ_CAPABLE, WRITE_CAPABLE)
        return
