# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

'''
CherryPy / Splunkweb endpoints for Deep Dive contexts or Unnamed Deepdives
'''

import sys
import json
import copy

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.rest as rest

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.searches import itsi_filter
from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import NormalizeRESTRequestForSharedObjects, handle_json_in, ITOAError, load_validate_json
from itsi.objects.itsi_deep_dive import ItsiDeepDive
from itsi.objects.itsi_service import ItsiService
from itsi.objects.itsi_entity import ItsiEntity

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

REST_ROOT_PATH = "/services"
DEEP_DIVE_ENDPOINT = '/en-US/app/itsi/deep_dive?savedDeepDiveID={}'

# Set default as empty string as state store does not handle None value very well.
# Note focus_id has to be defined before creating it.
# Otherwise state store will save "None" value as "{ $undefined : true }"
NEW_DEEP_DIVE = {"mod_time": "",
                 "focus_id": None,
                 "title": "",
                 "description": "",
                 "is_named": False,
                 "latest_time": None,
                 "earliest_time": None,
                 "lane_settings_collection": [],
                 "acl": {"can_write": True, "can_share_global": True, "can_change_perms": True, "can_share_user": True,
                         "can_share_app": True, "owner": "nobody", "sharing": "app", "perms": {"write": [], "read": []},
                         "modifiable": True}
                 }

logger = setup_logging("itsi.log", "itsi.controllers.deep_dive_services")
logger.debug("Initialized itoa services log...")

# Multi-inheritance prevents the custom controller grafting from intermittently failing with multiple controllers in the app
class deep_dive_services(ITOABaseController, controllers.BaseController):
    """
    deep_dive_redirect handles complex redirection requests for drilldowns into deep dive
    """

    splunk_url = ''

    def __init__(self):
        """
        initializes the storage interface
        @param self: The self reference
        """
        super(deep_dive_services, self).__init__()

    def _compute_splunk_url(self, session_key):
        """
        Utility method to compute Splunk UR
        (http|https)://localhost:8089
        @param session_key: splunkd session_key
        """
        endpoint_uri = '/services/server/settings?output_mode=json'
        response, content = rest.simpleRequest(
            endpoint_uri,
            method='GET',
            sessionKey=session_key,
            raiseAllErrors=True
        )

        splunk_url = ''

        if response.status == 200:
            result_as_json = json.loads(content)
            logger.debug("result_as_json: \n" + json.dumps(result_as_json))
            entry = result_as_json['entry']

            for entry_0 in entry:
                server_settings = entry_0
                logger.debug(
                        "++++ Splunk server settings ++++\n " + \
                        "host: " + \
                        server_settings['content']['host'] + \
                        "httpport: " + \
                        str(server_settings['content']['httpport']) + \
                        "enableSplunkWebSSL: " + \
                        str(server_settings['content']['enableSplunkWebSSL'])
                        )

                if server_settings['content']['enableSplunkWebSSL'] is True:
                    splunk_url += 'https://'
                else:
                    splunk_url += 'http://'

                splunk_url += server_settings['content']['host'] + ':' + str(server_settings['content']['httpport'])
                # Entry 0 is the one containing server settings. Nothing more to do; break.
                break
        else:
            logger.error("Unable to compute splunk url. Response: %s", str(response.status))

        return splunk_url

    def get_deep_dive_full_url(self, owner, session_key, context_id, include_all_kpi=True):
        """
        Compute a deep dive URL
        @param self: The self reference
        @param context_id: <service id>
        @param include_all_kpi: boolean, if true any KPI's associated with the context_id will be added as lanes
        @return deep_dive_url:
            ex: https://johndoe-splunk.splunk.com:8000/en-US/app/itsi/deep_dive?savedDeepDiveID=54922051bf71ca54ba00f921
        @rval string
        """
        response_as_json = self.get_deep_dive_id(
            owner,
            session_key,
            context_id=context_id,
            include_all_kpi=include_all_kpi
        )
        deep_dive_id = response_as_json['_key']

        # get Splunk Web URL
        if not deep_dive_services.splunk_url:
            deep_dive_services.splunk_url = self._compute_splunk_url(session_key)

        deep_dive_url = deep_dive_services.splunk_url + DEEP_DIVE_ENDPOINT.format(deep_dive_id)
        return deep_dive_url

    def get_deep_dive_id(self, owner, local_session_key, **kwargs):
        """
        Compute a deep dive ID if none exists and return it to caller.
        @param self: The self reference
        @param owner: expected, 'none'
        @param local_session_key: splunkd sessionKey
        @param **kwargs: Key word arguments extracted from the POST body
            Generally expected kwargs are:
                _key: the deep dive to redirect to
                context_id: <service id>
                lane_settings_collection: array of <lane settings>
                include_all_kpi: boolean, if true any KPIs associated with the context_id will be added as lanes
        @return: deep dive id
        @rval: json string
        """
        LOG_PREFIX = '[get_deep_dive_id] '
        context_id = kwargs.get("context_id", None)

        response = {}

        if context_id is not None:
            kpis_lane_settings = []
            if kwargs.get("include_all_kpi", False):
                kpis_lane_settings = self._get_kpi_lane_settings(owner, context_id, local_session_key)
            # Try to load some old context
            filter_data = {"focus_id": context_id, "is_named": False}
            deep_dive_object = ItsiDeepDive(local_session_key, 'unknown')
            all_objects = deep_dive_object.get_bulk(owner=owner, filter_data=filter_data)
            logger.debug("all objects %s", all_objects)
            if len(all_objects) == 0:
                service_object = ItsiService(local_session_key, 'nobody')
                context = service_object.get("nobody", context_id)
                # Create a new unnamed deep_dive for this context
                unnamed = copy.deepcopy(NEW_DEEP_DIVE)
                unnamed["lane_settings_collection"] = load_validate_json(kwargs.get("lane_settings_collection", "[]")) + kpis_lane_settings
                unnamed["focus_id"] = context_id
                if context is None:
                    unnamed["focus_title"] = "UNNAMED_CONTEXT"
                else:
                    unnamed["focus_title"] = context.get("title", "UNNAMED_CONTEXT")
                response = deep_dive_object.create(owner, unnamed)
                logger.debug("create response=%s", response)
            else:
                # Pull it, enhance it and send it along
                response = all_objects[0]
                if kwargs.get("earliest", None) is not None:
                    response["earliest_time"] = kwargs.get("earliest")
                if kwargs.get("latest", None) is not None:
                    response["latest_time"] = kwargs.get("latest")
                request_args_lane_settings = load_validate_json(kwargs.get("lane_settings_collection", "[]"))
                #Check duplicate
                response["lane_settings_collection"] = self._merge_duplicate_lane_settings(response.get("lane_settings_collection", []), request_args_lane_settings, kpis_lane_settings)
                # Must remove the ID property from the edit request or it will 404 (it should 400, but whatever)
                obj_id = response.get("_key")
                del response["_key"]
                response = deep_dive_object.update(
                    owner,
                    obj_id,
                    response,
                    is_partial_data=kwargs.get('is_partial_data', False)
                )
                logger.debug("edit response=%s", response)
        else:
            response["lane_settings_collection"] = kwargs.get("lane_settings_collection", []);
        logger.debug("post response=%s", response)

        return response

    def _get_deep_dive_url(self, **kwargs):
        """ convenience wrapper to make_url() """
        return self.make_url(["app", "itsi", "deep_dive"], kwargs)

    def _get_kpi_lane_settings(self, owner, context_id, local_session_key):
        """
            Get kpis associated with service id and return lane settings for kpis
            @param context_id: string service id
            @param local_session_key: splunk session key

            @return: list of kpis lane settings
        """
        kpis_settings = []
        service_object = ItsiService(local_session_key, 'nobody')
        service = service_object.get("nobody", context_id)
        service_name = service["title"]
        logger.debug("service=%s for service_id=%s", service, context_id)
        kpis = service.get("kpis", [])
        if len(kpis) == 0:
            logger.warning("service=%s has no kpis", service_name)
        for kpi in kpis:
            kpis_settings.append(
                {"searchSource": "kpi", "laneType": "kpi", "kpiServiceId": context_id, "kpiId": kpi["_key"],
                 "title": kpi["title"], "subtitle": service_name, "thresholdIndicationEnabled": "enabled",
                 "thresholdIndicationType": "stateIndication"})
        return kpis_settings

    def _check_duplicate_based_upon_kpi(self, existing_lane_settings, new_kpis_lane_settings):
        """
            Check if new kpis are already existed in lane settings
            @param existing_lane_settings: list of existing lane settings of deep dive
            @param new_kpis_lane_settings: list list of kpis which need to be checked

            @return: list - list of kpis lane setting which does not exist in deep dive
        """
        uni_kpi_lane_settings = []
        for kpi in new_kpis_lane_settings:
            is_existed = False
            for existing in existing_lane_settings:
                # Note we do not check for title and subtitle
                if existing.get("searchSource", None) == "kpi" and existing.get("laneType", None) == "kpi" and existing.get("kpiId", None) == kpi.get("kpiId", "") and existing.get("kpiServiceId", None) == kpi.get("kpiServiceId", ""):
                    logger.debug("kpis already existed in kpi_lane_settings=%s", kpi)
                    is_existed = True
                    break
            if not is_existed:
                uni_kpi_lane_settings.append(kpi)
        return uni_kpi_lane_settings

    def _check_duplicate_adhoc_search(self, existing_lane_settings, new_adhoc_lane_settings):
        """
            Check if search already existed
            @param existing_lane_settings: list of existing lane settings of deep dive
            @param new_adhoc_lane_settings: list of new search settings

            @return: list of adhoc lane setting which does not exist in deep dive
        """
        uni_adhoc_lane_settings = []
        for new in new_adhoc_lane_settings:
            is_existed = False
            for old in existing_lane_settings:
                # Note, do not check based upon title or subtitle
                if old.get("search", None) == new.get("search", ""):
                    logger.debug("adhoc search already existed, search_lane_settings=%s", new)
                    is_existed = True
                    break
            if not is_existed:
                uni_adhoc_lane_settings.append(new)
        return uni_adhoc_lane_settings

    def _merge_duplicate_lane_settings(self, existing_lane_settings, new_adhoc_lane_settings, new_kpis_lane_settings):
        """
            Check and merge duplicate lane settings
            @param existing_lane_settings:  list    already existed lane settings of deep dive
            @param new_adhoc_lane_settings: list    new parameterized lane settings
            @param new_kpis_lane_settings:  list    kpi based lane settings

            @return: list - merged value of old and new lane settings
        """
        return existing_lane_settings + self._check_duplicate_adhoc_search(existing_lane_settings,
                                                                           new_adhoc_lane_settings) + self._check_duplicate_based_upon_kpi(
            existing_lane_settings, new_kpis_lane_settings)

    ###############################################################################
    # Endpoints
    ###############################################################################
    @route('/:action=redirect/:owner')
    @expose_page(must_login=True, methods=['POST', 'GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='deep_dive_context', logger=logger)
    @NormalizeRESTRequestForSharedObjects(logger=logger)
    def redirect(self, action, owner, **kwargs):
        """
        Allow the posting of complex data to redirect to a deep dive

        @param self: The self reference
        @param **kwargs: Key word arguments extracted from the POST body
            Generally expected kwargs are:
                _key: the deep dive to redirect to
                context_id: <service id>
                lane_settings_collection: Array of <lane settings>
                include_all_kpi: boolean, if true any KPI's associated with the context_id will be added as lanes

        @return: 303 to the proper deep dive on GET, 200 with JSON of _key on POST
        @rval: json string
        """
        LOG_PREFIX = '[redirect] '
        method = cherrypy.request.method
        logger.debug("request_args=%s", kwargs)
        if method == 'GET':
            redirect_params = {}
            _id = kwargs.get("_key", None)
            if _id is not None:
                redirect_params["savedDeepDiveID"] = _id
            # Add latest and earliest time
            if kwargs.get("earliest", None) is not None and kwargs.get("latest", None) is not None:
                redirect_params['earliest'] = kwargs.get("earliest", None)
                redirect_params['latest'] = kwargs.get("latest", None)
            redirect_params["laneSettingsCollection"] = load_validate_json(kwargs.get("lane_settings_collection", "[]"))
            logger.debug("redirecting with redirect_params=%s", redirect_params)
            raise cherrypy.HTTPRedirect(self._get_deep_dive_url(**redirect_params), 303)
        elif method == 'POST':
            session_key = cherrypy.session["sessionKey"]
            response = self.get_deep_dive_id(owner, session_key, **kwargs)
            return self.render_json(response)
        else:
            raise ITOAError(status="400", message=_("Unsupported HTTP method"))

    @route('/:action=entity_drilldown/:retrieve')
    @expose_page(must_login=True, methods=['POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='deep_dive_context', logger=logger)
    def entity_drilldown_retrieve_filtered_entities(self, action, retrieve, **kwargs):
        """
        Get an entity rule specficiation and a list of entity titles and return the entities with those titles that
        match the entity rule. The return comes as an array with objects holding the drilldown_name and array of
        entities.

        Note that the non-kwarg args to this method are worthless but required by the route decorator

        @param self: The self reference
        @param **kwargs: Key word arguments extracted from the POST body
            Generally expected kwargs are:
                drilldowns: JSON list of with fields drilldown_name, (unique name of the drilldown)
                    entities (list of entity titles), and rule (entity rule specifcation)

        @return: all the drilldowns with the list of entities they can apply to
        @rval: json string
        """
        LOG_PREFIX = '[entity_drilldown] '
        try:
            logger.info("retrieval kwargs: %s", kwargs)
            # Get our drilldowns array
            drilldowns = kwargs.get("drilldowns", None)
            if drilldowns is None:
                raise ITOAError(status="400", message=_("Required parameter drilldowns missing."))
            drilldowns = load_validate_json(drilldowns)
            local_session_key = cherrypy.session["sessionKey"]

            # Set up a list to put our processed drilldowns in
            processed_drilldowns = []

            for drilldown in drilldowns:
                logger.debug("drilldown is %s", drilldown)
                drilldown_name = drilldown.get("drilldown_name")
                entities = drilldown.get("entities", [])
                rule = drilldown.get("rule", "all")

                processed_drilldown = {"drilldown_name": drilldown_name, "entities": []}

                if len(entities) == 0:
                    logger.debug("someone tried to see if a drilldown would work on no entities, it doesn't.")
                    processed_drilldowns.append(processed_drilldown)
                    continue
                else:
                    entity_title_or = {"$or": [{"title": entity_title} for entity_title in entities]}

                entity_object = ItsiEntity(local_session_key, 'nobody')
                if rule == "all":
                    logger.debug("All entities are valid for this drilldown, simply retrieve the entities")
                    entity_filter = entity_title_or
                else:
                    # PARSE ENTITY RULE
                    rule_filter = itsi_filter.ItsiFilter(rule).generate_kvstore_filter()
                    if rule_filter is not None:
                        entity_filter = {"$and": [entity_title_or, rule_filter]}
                    else:
                        logger.error("Rule configured for entity drilldown is invalid, returning no entities as a result.")
                        processed_drilldowns.append(processed_drilldown)
                        continue

                logger.debug("entity filter is %s", entity_filter)
                valid_entities = entity_object.get_bulk("nobody", filter_data=entity_filter)
                logger.debug("retrieved entities: %s", valid_entities)
                processed_drilldown["entities"] = valid_entities
                if len(valid_entities) > 0:
                    processed_drilldowns.append(processed_drilldown)

            return self.render_json(processed_drilldowns)
        except ValueError as e:
            logger.exception(e)
            raise ITOAError(status="400", message=_("Drilldowns object passed to deep dive services was invalid."))
        except TypeError as e:
            logger.exception(e)
            raise ITOAError(status="400", message=_("Drilldowns object passed to deep dive services was invalid."))
        except Exception as e:
            logger.exception(e)
            raise



