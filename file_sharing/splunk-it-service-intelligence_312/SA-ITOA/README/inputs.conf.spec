[itsi_user_access_init://<name>]
* A modular input that will be run once during startup (or at user request) to
* register its capabilities with the SA-UserAccess module

log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input. Defaults to WARN

app_name = <value>
* Indicates name of the app which has these capabilities. Ex: itsi, es ...
* Defaults to itsi

registered_capabilities = [true|false]
* Indicates whether or not capabilities have been registered

[configure_itsi://<name>]
* A configuration tool that will be run once (or at user request) to
* pull entities from the conf file system into the statestore

log_level = <DEBUG|INFO|WARN|ERROR>
*The logging level of the modular input.  Defaults to WARN

is_configured = ""
* Left it for backwards compatibility

[itsi_csv_import://<name>]
* A modular input that periodically uploads csv data into your entity database
* The csv file must contain headers for the import to work properly

log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to WARN

import_from_search = <bool>
* REQUIRED: import csv data via search if True; import csv data from csv_location otherwise.

csv_location = <value>
* Required if import_from_search is False. The location on disk of the csv file to import

search_string = <value>
* Required if import_from_search is True. Search string that would generate the csv data which can be imported.

service_security_group = <value>
* REQUIRED: Team the imported service will be associated with.

index_earliest = <value>
* Required if we have a search string i.e. import_from_search is True. If no value is provided. We will default to -15m

index_latest = <value>
* Required if we have a search string i.e. import_from_search is True. If no value is provided. We will default to now.

entity_title_field = <value>
* The field to import the entity title from.  This will be the informal identifier of the entity

entity_relationship_spec = <value>
* A dict that specify how entity_title_field associate with other field in what relationship
* For example,
* {"hosts": "vm1, vm2", "hostedBy": "host_id"}, or
* {"hosts": ["vm1", "vm2"], "hostedBy": "host_id"}.
* For a record that has values for fields: vm1, vm2, host_id, <field for entity_title_field>,
* there will be three relationships extracted:
* <field value for entity_title_field> hosts <field value for vm1>
* <field value for entity_title_field> hosts <field value for vm2>
* <field value for entity_title_field> hostedBy <field value for host_id>

selected_services = <value>
* A comma separated list of existing services to automatically associate the entities to

service_rel = <value>
* A comma separated list of existing service relationships

service_dependents = <value>
* A comma separated list of service dependencies

entity_service_columns = <value>
* A comma separated list of services found in the CSV file itself that are to be associated with the entity for the row

entity_identifier_fields = <value>
* A comma separated list of the fields in the csv to import.  These fields are used to identify the entity.

entity_description_column = <value>
* A comma separated list of the fields in the csv to import.  These fields are used to describe the entity.

entity_informational_fields = <value>
* A comma separated list of the fields in the csv to import.  These are non-identifying fields for the entity.

entity_field_mapping = <value>
* A key value mapping of fields which you wish to be remapped to other fields in your data.  Follows a <csv field>= <splunk search field> format.  E.g. ip1=dest,ip2=dest,storage_type=volume

service_title_field = <value>
* The field to import the service title from. This will be the informal identifier of the service

service_description_column = <value>
* A comma separated list of fields in CSV to import. These fields are used to describe the service

service_enabled = <value>
* The boolean that determines whether imported services are enabled.

service_template_field = <value>
* the field that determines which service template the service should link to.

template = <value>
* the entity rule to service template mappings.

backfill_enabled = <value>
* The boolean that determines whether to enabled backfill on all KPIs in linked service templates.

update_type = <APPEND|UPSERT|REPLACE>
* REQUIRED: When uploading entities, the type of updating/insertion behavior that will happen
* APPEND: No attempt is made to identify commonalities between entities.  All information is appended to the table
* UPSERT: New entries are appended.  Existing entries (based on the value found in the title_field) will have additional information appended to the existing record
* REPLACE: New entries are appended.  Existing entries (based on the value found in the title_field) will be replaced by the new record value

interval = <value>
* The field that determines how often the mod input runs (in seconds)

[itsi_async_csv_loader://<name>]
* A modular input that periodically uploads csv data into your entity database
* The csv file must contain headers for the import to work properly

log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to WARN

import_from_search = <bool>
* REQUIRED: import csv data via search if True; import csv data from csv_location otherwise.

csv_location = <value>
* Required if import_from_search is False. The location on disk of the csv file to import

search_string = <value>
* Required if import_from_search is True. Search string that would generate the csv data which can be imported.

index_earliest = <value>
* Required if we have a search string i.e. import_from_search is True. If no value is provided. We will default to -15m

index_latest = <value>
* Required if we have a search string i.e. import_from_search is True. If no value is provided. We will default to now.

entity_title_field = <value>
* The field to import the entity title from.  This will be the informal identifier of the entity

entity_relationship_spec = <value>
* A dict that specify how entity_title_field associate with other field in what relationship
* For example,
* {"hosts": "vm1, vm2", "hostedBy": "host_id"}, or
* {"hosts": ["vm1", "vm2"], "hostedBy": "host_id"}.
* For a record that has values for fields: vm1, vm2, host_id, <field for entity_title_field>,
* there will be three relationships extracted:
* <field value for entity_title_field> hosts <field value for vm1>
* <field value for entity_title_field> hosts <field value for vm2>
* <field value for entity_title_field> hostedBy <field value for host_id>

selected_services = <value>
* A comma separated list of existing services to automatically associate the entities to

service_rel = <value>
* A comma separated list of existing service relationships

service_dependents = <value>
* A comma separated list of service dependencies

entity_service_columns = <value>
* A comma separated list of services found in the CSV file itself that are to be associated with the entity for the row

entity_identifier_fields = <value>
* A comma separated list of the fields in the csv to import.  These fields are used to identify the entity.

entity_description_column = <value>
* A comma separated list of the fields in the csv to import.  These fields are used to describe the entity.

entity_informational_fields = <value>
* A comma separated list of the fields in the csv to import.  These are non-identifying fields for the entity.

entity_field_mapping = <value>
* A key value mapping of fields which you wish to be remapped to other fields in your data.  Follows a <csv field>= <splunk search field> format.  E.g. ip1=dest,ip2=dest,storage_type=volume

service_title_field = <value>
* The field to import the service title from. This will be the informal identifier of the service

service_description_column = <value>
* A comma separated list of fields in CSV to import. These fields are used to describe the service
update_type = <APPEND|UPSERT|REPLACE>
* REQUIRED: When uploading entities, the type of updating/insertion behavior that will happen
* APPEND: No attempt is made to identify commonalities between entities.  All information is appended to the table
* UPSERT: New entries are appended.  Existing entries (based on the value found in the title_field) will have additional information appended to the existing record
* REPLACE: New entries are appended.  Existing entries (based on the value found in the title_field) will be replaced by the new record value

[itsi_upgrade://<name>]
* A modular input which check version and perform migration whenever Splunk starts
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to DEBUG

[itsi_refresher://<name>]
* A modular input that processes deferred methods using a single queue processor 
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to INFO

[itsi_consumer://<name>]
* A modular input that processes deferred methods using multiple queues across the splunk environment
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to INFO

[itsi_backup_restore://<name>]
* A modular input which is responsible for performing backup and restore operations by managing backup/restore jobs
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to INFO

[itsi_scheduled_backup_caller://<name>]
* A modular input which is to management the backup schedules
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input. Defaults to INFO

[itsi_service_template_update_scheduler://<name>]
* A modular input which is to perform scheduled sync from service templates to services
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input. Defaults to INFO

[itsi_backfill://<name>]
* A modular input which is responsible for managing KPI backfill jobs
log_level = <DEBUG|INFO|WARN|ERROR>
* The logging level of the modular input.  Defaults to DEBUG

[itsi_notable_event_archive://<name>]
* A modular input which move notable events from kv store collection to index
* Splunk can't read modular name unless any parameter is specify. Hence I am passing owner
owner = <string>

[maintenance_minder://<name>]
* A modular input which populates the operative maintenance log based on configured maintenance windows
* Splunk mandates at least one parameter for module inputs, using log_level as placeholder.
log_level = <DEBUG|INFO|WARN|ERROR>

[itsi_default_aggregation_policy_loader://<name>]
* A modular input which load default policy
log_level = <DEBUG|INFO|WARN|ERROR>

[itsi_default_correlation_search_acl_loader://<name>]
* A modular input which load default acl
log_level = <DEBUG|INFO|WARN|ERROR>

[itsi_notable_event_hec_init://<name>]
* A modular input which initializes HEC client on a Search Head, by creating and
* chowing pertinent HEC tokens.
log_level = <DEBUG|INFO|WARN|ERROR>

[itsi_notable_event_actions_queue_consumer://name]
* A modular input which acts as a consumer of the queue for executing actions
* Primarily used by the Rules Engine

exec_delay_time = <value> in seconds
* OPTIONAL: Delay execution by this value in seconds. Defaults to 0 seconds.

timeout = <value> in seconds
* OPTIONAL: timeout value which is used when already expired job re-claimed by consumer. Default is 2 hour

batch_size = <value>
* OPTIONAL: number of jobs to pickup in one request from the queue. Default value is 5


