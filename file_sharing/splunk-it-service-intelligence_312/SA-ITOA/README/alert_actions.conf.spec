[itsi_event_generator]
param.http_token_name = <string token name>
* (Optional) http token name - we obtain one token using below parameters

param.index = <string>
* (Conditional Required)index name. It is required when http auth token is not provided

param.sourcetype = <string>
* sourcetype name. It is used when http auth token is not provided

param.event_identifier_fields = <string>
* Comma separated list of field which is used to identify event duplication

param.search_type = <string>
* Search type. Default value is custom

param.is_use_event_time = <0|1>
* set to 1 to use actual event time.

[itsi_sample_event_action_ping]
param.host_to_ping = <string token name>
* This param defaults to %orig_host%, which means that when executing the alert
* action, we will extract the value corresponding to the key `orig_host` from
* event data and try pinging it.
* If the param is set to a value which does not begin with and 
* end with `%s`, we consider this to be the value to ping. No
* extractions will be done in such a case.

[itsi_event_action_link_ticket]
param.ticket_system = <string>
* Defaults to empty string. Required to create/update/delete a ticket.
param.ticket_id = <string>
* Defaults to empty string. Required to create/update/delete a ticket.
param.ticket_url = <string>
* Defaults to empty string. Required to create/update a ticket.
param.operation = <string>
* Defaults to empty string. Specifies the type of operation on ticket: upsert or delete.
param.kwargs = <string>
* Defaults to empty string. It is an optional param to pass additional fields to the ticket.
* It should be in dictionary format.
