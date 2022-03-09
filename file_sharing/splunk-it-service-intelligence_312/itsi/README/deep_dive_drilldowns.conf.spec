# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
#
# This file contains all possible options for an deep_dive_drilldowns.conf file.  Use this file to configure
# drilldown options for lanes in deep dive.
#
# A unique drilldown options is represented by a stanza in this file. The name of the stanza is the name that will
# appear in the UI. Default values are provided for most attributes and are defined in the default stanza of the conf
# file.
#
# Some more complex drilldown options are not defined here as they are only represented in the code of deep dive, they
# cannot be disabled.
#
# To learn more about configuration files (including precedence) please see the documentation
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#


[<name>]
# Properties for all types of drilldowns
type = uri|search
	* Represents if this drilldown is meant to go to a new URI or open a search
	* Required

replace_tokens = true|false
	* If true the search or URI will be token replaced by properties of the drilldown
	* Token replacement works similar to token replacement in simplexml, tokens are represented in tokenized strings as
	  some sub-string key surrounded by $.
		* EG search=index=_internal | stats count | where count>$value$
	* Tokens available for replacement by default are as follows
		* lane_title - the title of the lane
		* lane_subtitle - the subtitle of the lane
		* lane_search - the search that powered the primary graph in the lane
		* earliest - the earliest epoch time stamp of the entire lane
		* latest - the latest epoch time stamp of the entire lane
		* bucket_earliest - the earliest epoch time stamp of the time bucket clicked
		* bucket_latest - the latest epoch time stamp of the time bucket clicked
	* Tokens available for KPI lanes only are as follows
		* kpi.service_id - the id of the service to which the kpi belongs
		* kpi.service_title - the tite of the service to which the kpi belongs
		* kpi.kpi_id - the id of the kpi represented in the lane
		* kpi.kpi_title - the title of the kpi represented in the lane
		* kpi.single_value_search - the raw data alert search for the kpi
		* kpi.timeseries_search - the raw data time series search for the kpi
		* kpi.base_search - the event gathering/filtering search for the kpi

metric_lane_enabled = true|false
	* If true drilldown option will be available on metric lanes, if false it will be unavailable on metric lanes
	* Optional

kpi_lane_enabled = true|false
	* If true drilldown option will be available on kpi lanes, if false it will be unavailable on kpi lanes
	* Optional

event_lane_enabled = true|false
	* If true drilldown option will be available on event lanes, if false it will be unavailable on event lanes
	* Optional


# Entity based features are only available on kpi lanes, as they are the only ones that understand entities. Note that
# kpi must also have entity breakdown enabled.
entity_level_only = true|false
	* If true drilldown option will only be available on lanes that surface entity level information, if false drilldown
	  is available on all lanes
	* Entity level drilldowns make additional tokens and information available based on the entities clicked. See
	  entity_tokens for more details
	* Optional

entity_tokens = <csv of entity attributes to include on a drilldown>
	* Only defiend entities will be available on entity level drilldowns, pseudo-entities will be ignored
	* If replace_tokens is true then this will generate additional token replacements.
	* Attributes can be either info fields or aliases
	* If payload on URI set to json these entity attributes will be added to the payload per entity
	* Tokens from the first entity will be replaced, if there are multiple entities they will all appear in a json payload
	* Tokens will have the format entity.<attribute name>
	* If any entity tokens are set at all (required to make it work), entity.id and entity.title will be always be available as tokens
	* Optional

entity_activation_rules = <json of entity rules>|all
	* If set to all, all entities are considered valid for the drilldown
	* If set to a json of entity rules, entities will be tested for compliance with those rules, if none match, drilldown
	  option will not be available, if some/all match, only those matching will be passed down to drilldown
	* Optional

# Properties for search type drilldowns
search = <tokenized search string>
	* The search to use in new lane or to use on the search page
	* Will be token replaced by properties from the drilldown itself if replace_tokens is true
	* Required for search type drilldowns

add_lane_enabled = true|false
	* If true users will be able to activate the drilldown as a search
	* Required for search type drilldowns

use_bucket_timerange = true|false
	* If true and redirected to the search page uses the clicked bucket's time range instead of the whole search timerange
	* Optional

new_lane_settings = <tokenized JSON for lane settings properties>
	* Model to be used for new lane, will have the search property overridden by the search property in this stanza
	* Default lane settings will be applied if values are not specified
	* Will be token replaced by properties from the drilldown itself if replace_tokens is true
	* Required only for search type drilldowns with add_lane_enabled as true

# Properties for URI type drilldowns
uri = <str>
	* The uri to redirect to on the drilldown.
	* Will be string replaced by tokens if replace_tokens is true and uri_payload_type is simple
	* Follows the format of an href, therefore:
		* a leading protocol will allow a change in domain
		* a leading slash will change the full path on the same domain
		* any other string will only replace the last segment of the URI with that string

uri_payload_type = simple|json
	* If simple, token replacement will be performed on the URI as if it were a search
	* If json, no token replacement will be performed and a query string parameter drilldown_payload will be appended
	  to the URI with a json representation of the context of a drilldown this payload. This payload will always contain
	  the context portion of the json, which contains the basic properties.
	  If it is entity level and the entity properties of the drilldown are specified
	  then the entities portion will exist and consistent of the entity id and title as well as all attributes specified
	  in as entity_tokens. A json payload format will look like (assumes entity_tokens was host,family):
		{
			"context": {
				"earliest": <earliest time of full lane>,
				"latest": <latest time of full lane>,
				"bucket_earliest": <earliest time of bucket clicked>,
				"bucket_latest": <latest time of the bucket clicked>,
				"return_url": <URI of the current deep dive>,
				"service_id": "158bdaf4-6b0c-433e-9c24-c3a36c0e8eea",
				"kpi_id": "65ec30c5e1dd5046ac5416f5",
				"service_title": "Production Webservers",
				"kpi_title": "Total Request Latency (ms)"
			},
			"entities": [
				{
					"id": "5303377f-162c-45cc-809a-d1e3254ea4a1",
					"title": "Host Title 1",
					"host": "Host1",
					"family": "Linux"
				},
				{
					"id": "7aefd044-0f46-4ba4-ab13-f31e5797a3bf",
					"title": "Host Title 2",
					"host": "Host2",
					"family": "Linux"
				}
			]
		}