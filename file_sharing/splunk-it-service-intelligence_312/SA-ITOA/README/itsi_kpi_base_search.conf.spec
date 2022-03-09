[<name>]
description = <value>
* The description of the KPI base search

title = <value>
* The title of the KPI base search

_owner = <value>
* The owner of this KPI base search
* Defaults to itsi

base_search = <value>
* The search to execute in the KPI base search. This search is the source for the fields defined in metrics.

metrics = <value>
* A JSON blob that specifies the array of metrics to be collected.
* Example item in the blob:
* {
*     "unit": "%",
*     "title": "CPU Utilization: %",
*     "entity_statop": "avg",
*     "aggregate_statop": "avg",
*     "_key": "620b26a6f286a508fd356d94",
*     "threshold_field": "cpu_load_percent"
*  }
* The threshold_field in the item corresponds to a field from the base searcg

is_entity_breakdown = <bool>
* Flag indicating the metrics should be broken down by entities for threshold calculations.

is_service_entity_filter = <bool>
* Flag indicating the metrics should filter out entities not in service

entity_id_fields = <value>
* The field in the base search to be used to lookup the corresponding entity to filter KPI
* Examples can be host, ip, etc.
* Only needed if is_service_entity_filter is true

entity_breakdown_id_fields = <value>
* The field in the base search to be used to lookup the corresponding entity to split KPI
* Examples can be host, ip, etc.
* Only needed if is_entity_breakdown is true

entity_alias_filtering_fields = <value>
* An optional comma-separated list of alias attributes to be used to filter out entities not in the service
* Only needed if is_service_entity_filter is true

alert_period = <value>
* Specifies the frequency of running the search, in minutes

search_alert_earliest = <value>
* Specifies the time window over which to evaluate the metrics, in minutes

alert_lag = <value>
* Specifies the time, in seconds, to push back the metric evaluation
* This corresponds to the data indexing lag
* Defaults to 30 secs

metric_qualifier = <value>
* The field in the base search used to further split metrics by
* This setting cannot be modified in UI, use with caution

source_itsi_da = <value>
* The ITSI Module which is the source defining this KPI base search
