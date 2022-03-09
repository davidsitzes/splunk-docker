require.config({
    paths: {
        "app": "../app",
        "currentApp": "../app/DA-ITSI-VIRTUALIZATION"
    }
});

require([
    'jquery',
    'underscore',
    'splunk.util',
    'splunkjs/mvc',
    'splunkjs/mvc/utils',
    'splunkjs/mvc/searchmanager',
    'currentApp/EntityDrilldownUtils',
    'splunkjs/mvc/simplexml/ready!'
], function(
    $,
    _,
    splunkUtil,
    mvc,
    splunkjsUtils,
    SearchManager,
    EntityDrilldownUtils
) {

    // Fill entitySearchResult object from itsi_entity lookup table.
    // Which is used to find clicked entity is exist in lookup or not. If not, new drill down view will not open.
    var moduleSavedSearch = 'DA-ITSI-VIRTUALIZATION-Virtualization_Entity_Search';
    var entityFilterPhrase = '| WHERE itsi_role="virtualization" AND (type="hypervisor" OR type="virtualmachine")';
    var entityIdSearch=EntityDrilldownUtils.createEntitySearchManager(moduleSavedSearch,entityFilterPhrase);
    EntityDrilldownUtils.fetchEntityFromSearchManager(entityIdSearch);

    //Prepare configuration object to link table with other entity drill down or entity detail view
    var link_configurations = [{
          "table_panel_id": "dshypervisortable_panel_dshypervisortable",
          "table_columns": [{"column_name": "Hypervisor Id","link_type": "entity_view","entity_title_column":"Hypervisor Id"},
                            {"column_name": "Hypervisor Name","link_type": "drill_down","entity_title_column":"Hypervisor Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-Hypervisor_Entity_View","fields_to_add": {"hypervisor_id": "Hypervisor Id","hypervisor_name": "Hypervisor Name"}}]
        },{
          "table_panel_id": "dsvmtable_panel_dsvmtable",
          "table_columns": [{"column_name": "VM Id","link_type": "entity_view","entity_title_column":"VM Id"},
                            {"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        }];

    EntityDrilldownUtils.renderTableLinks(link_configurations);

 });