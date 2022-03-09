[<stanza name>]
* stanza name should be custom alert name which user wants to include

disabled = 0|1
* Disabled, set this flag to 1 if we do not want to include the alert

type = <string>
* Supported values are = 'external_ticket'

is_bulk_compatible = 0|1
* Set this to 1 if you want this action to be available for events selected in bulk

is_group_compatible = 0|1
* Set this to 1 if you want this action to be available for grouped events

execute_in_sync = 0|1
* 0 by default.
* Set this to 1 if you want to execute this action synchronously.
* For external ticket being created via splunk custom search command or mod
* alert, it is recommended to set this to 1.

execute_once_per_group = 0|1
* 0 by default.
* Set this to 1 if you want to execute this action exactly
* once in case of a bulk action.
* In special cases like if this action has `external_ticket` set to 1,
* the result of a refresh will be associated with all the events in the group.

* Following k-vs are applicable only when `type` is `external_ticket`
ticket_system_name = <string>
* Name of the ticket system

relative_refresh_uri = <string>
* a relative URI for the same search head where ITSI is installed.
* https://localhost:8089/ or something like it is prepended to the URI

correlation_key = <string>
* query param (if any) to be appended to refresh_uri

correlation_value = <string>
* given a notable event, the key in the raw event whose value needs to be
* attached to the refresh uri. If a correlation_key exists, we will attach this
* value to it, else we will append to the uri

correlation_value_for_group = <string>
* When operating on a Notable Event group, we will use the value corresponding to `itsi_group_id`
* as the correlation_id. Similar to correlation_value mentioned above.

refresh_response_json_path = <string>
* path within the json response which has all the useful information for us

refresh_response_ticket_id_key = <string>
* after traversing the path and fetching what would be a json blob, the key
* which corresponds to the external ticket id

refresh_response_ticket_url_key = <string>
* after traversing the path and fetching what would be a json blob, the key
* which corresponds to the external ticket URL.

black_list_field_names = <string>
* List of field names in notable event whose value are discarded
* from consideration for event correlation by ACE framework

text_field_names = <string>
* List of field names in notable events that usually represent textual content
* of event data

threshold_distinct_value_perc = <int>
* Threshold value for considering a NE fields as categorical field

min_distinct_value_perc = <int>
max_count_perc = <int>
* Threshold value for considering a NE fields as categorical field
* If the cumulative event sum of first min_distinct_value_perc of distinct
* count is contained in max_count_perc of count, the field is considered as categorical field

threshold_event_coverage_perc = <int>
* Threshold value to consider the field as text field