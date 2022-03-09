* WARNING:  Manual editing this file is not recommended.  Proceed with caution.
[<view_name>]
* View name is the name of the Deep Dive drilldown view within the ITSI module
tabs = <string>
* Comma separated list of tab IDs that will be included in this drilldown view
<tabId>.control_token = <string>
* Used to fire off all the panel searches in a given tab
* When the tab is shown, a list of search tokens are retrieved, the search tokens for
* all inactive tabs are removed from the list, and the search token for the active tab
* is added to the list.  This guarantees that only the shown tab's panels are displayed
<tabId>.title = <string>
* Title of the tab.  Displayed on the tab in the UI
<tabId>.row.<int> = <string>
* Panels that are displayed on each row on a tab.  This is a comma separated list of
* panels formatted as <module_name>:<panel_name>.
* These keys start at row.0 and go up to any number of rows that is needed for a tab.
* EX: row.0  = DA-ITSI-OS:panel1,DA-ITSI-LB:panel2
<tabId>.extendable_tab = <bool>
* Flag that determines whether the tab is considered an extendable tab.  This is for
* user-created tabs so that a delete button will appear on the tab in the UI.  Any
* tabs that ship with the module default to false.
<tabId>.activation_rule = <string>
* Comma separated list of KPI elements that are associated with a given tab so that
* context aware drilldown is enabled based on the selected KPI from Deep Dive.
* Each element here is defined as the content from the "target_field" parameter from each
* selected KPI from the file itsi_kpi_template.conf
entity_search_filter = <string>
* Set of entity rules in json format, used for filtering entities for entity dropdown.
requested_entity_tokens - <string>
* Comma separated list of entity attributes that are submitted as tokens.