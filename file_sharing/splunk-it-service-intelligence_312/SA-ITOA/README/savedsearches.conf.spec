# Ping
action.itsi_sample_event_action_ping.param.host = <string>
* Field in the event indicating the host to ping.
* Mandatory - If no value is provided, no host will be pinged.
* Set to $result.host$ or $result.server$ etc...

# Event generator event settings

action.itsi_event_generator = [0|1]
* Enable ITSI alert

action.itsi_event_generator.param.title = <string>
* Title for notable event
* Optional - If title is not provided then search name will be become title

action.itsi_event_generator.param.description = <string>
* Description for notable event
* Optional - If description is not provided then search description will become event description

action.itsi_event_generator.param.owner = <string>
* Owner for notable event
* Optional - if owner is not provided then default_owner is being assigned

action.itsi_event_generator.param.status = <string>
* Event status
* Optional - if status is not provided then default_status is being assigned

action.itsi_event_generator.param.severity = <string>
* Optional - if status is not provided then default_severity is being assigned

action.itsi_event_generator.param.drilldown_search_title = <string>
* Optional - Drill down search title

action.itsi_event_generator.param.drilldown_search_search= <string>
* Optional - Drill down search string

action.itsi_event_generator.param.drilldown_search_latest_offset = <string>
* Optional - Drill down search latest offset. This offset is absolute time in sec. This offset will be added to event
* time

action.itsi_event_generator.param.drilldown_search_earliest_offset = <string>
* Optional - Drill down search earliest offset. This offset is absolute time in sec. This offset will be subtracted from
* event time

action.itsi_event_generator.param.drilldown_title = <string>
* Optional - Drill down title

action.itsi_event_generator.param.drilldown_uri = <string>
* Optional - Drill down uri

action.itsi_event_generator.param.event_identifier_fields = <string>
* Optional - Comma separated list of fields which can be used to identify a notable is unique. It is useful for identify
* if given notable event is already present. We normally build hash using these set of fields

action.itsi_event_generator.param.service_ids = <string>
* Optional - Comma separated list of service id

action.itsi_event_generator.param.entity_lookup_field = <string>
* Optional - Entity lookup field

action.itsi_event_generator.param.search_type =  <string>
* Optional - search type (default value is custom)

action.itsi_event_generator.param.meta_data =  <string>
* Optional - any meta data stored need to given search type

action.itsi_event_generator.param.is_ad_at =  <0|1>
* Optional - only set if this correlation created by AT/AD enablement of KPIs or Service

action.itsi_event_generator.param.ad_at_kpi_ids = <string>
* Optional - list of KPI where AT/AD was enabled
