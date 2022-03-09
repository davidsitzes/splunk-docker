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
    var entityFilterPhrase = '| WHERE itsi_role="virtualization" AND (type="datastore" OR type="virtualmachine")';
    var entityIdSearch=EntityDrilldownUtils.createEntitySearchManager(moduleSavedSearch,entityFilterPhrase);
    EntityDrilldownUtils.fetchEntityFromSearchManager(entityIdSearch);

    //Prepare configuration object to link table with other entity drill down or entity detail view
    var link_configurations = [{
          "table_panel_id": "hypervisordstable_panel_hypervisordstable",
          "table_columns": [{"column_name": "Datastore Id","link_type": "entity_view","entity_title_column":"Datastore Id"},
                            {"column_name": "Datastore Name","link_type": "drill_down","entity_title_column":"Datastore Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-Datastore_Entity_View","fields_to_add": {"datastore_id": "Datastore Id","datastore_name": "Datastore Name"}}]
        },{
          "table_panel_id": "hypervisorvmtable_panel_hypervisorvmtable",
          "table_columns": [{"column_name": "VM Id","link_type": "entity_view","entity_title_column":"VM Id"},
                            {"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmcpudemandtable_panel_vmcpudemandtable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmcpupercenttable_panel_vmcpupercenttable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmhighlatencytable_panel_vmhighlatencytable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmmemprovisiontable_panel_vmmemprovisiontable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmmemreservedtable_panel_vmmemreservedtable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmmemusepcnttable_panel_vmmemusepcnttable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmnetworkusagetable_panel_vmnetworkusagetable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        },{
          "table_panel_id": "vmstorageusagetable_panel_vmstorageusagetable",
          "table_columns": [{"column_name": "VM Name","link_type": "drill_down","entity_title_column":"VM Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-VirtualMachine_Entity_View","fields_to_add": {"vm_id": "VM Id","vm_name": "VM Name"}}]
        }];

    EntityDrilldownUtils.renderTableLinks(link_configurations);

});
