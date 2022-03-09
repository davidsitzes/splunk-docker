[indicator]
inline = [1|0]
   * Specifies whether the summary index search command will run as part
     of the scheduled search or as a follow-on action. This is useful
     when the results of the scheduled search are expected to be large.
    * Defaults to 1 (true).

_name = <string>
    * The name of the summary index where Splunk will write the events.
    * Defaults to "itsi_summary".

## per core implementation of summaryindex alert action in $SPLUNK_HOME/etc/system/default/alert_actions.conf

_itsi_kpi_id  = <string>
    * kpi id (MUST)
    * Defaults to None

_itsi_service_id = <string>
    * Service Id (MUST)
    * Defaults to None
