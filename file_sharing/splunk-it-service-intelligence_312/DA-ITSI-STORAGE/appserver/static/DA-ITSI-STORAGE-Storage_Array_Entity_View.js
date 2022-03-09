require.config({
    paths: {
        "app": "../app",
        "currentApp": "../app/DA-ITSI-STORAGE"
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
    var moduleSavedSearch = 'DA-ITSI-STORAGE-Storage_System_Entity_Search';
    var entityFilterPhrase ='| WHERE itsi_role="storagesystem" ';
    var entityIdSearch=EntityDrilldownUtils.createEntitySearchManager(moduleSavedSearch,entityFilterPhrase);
    
	EntityDrilldownUtils.fetchEntityFromSearchManager(entityIdSearch);

    //Prepare configuration object to link table with other entity drill down or entity detail view
    var link_configurations = [{
          "table_panel_id": "storagearraysptable_panel_storagearraysptable",
          "table_columns": [{"column_name": "Storage Pool Id","link_type": "entity_view","entity_title_column":"Storage Pool Id"},
                            {"column_name": "Name","link_type": "drill_down","entity_title_column":"Storage Pool Id",
                            "view_name":"/DA-ITSI-STORAGE-Storage_Pool_Entity_View","fields_to_add": {"pool_id": "Storage Pool Id","pool_name": "Name"}}]
        },{
          "table_panel_id": "storagearraydisktable_panel_storagearraydisktable",
          "table_columns": [{"column_name": "Disk Id","link_type": "entity_view","entity_title_column":"Disk Id"},
                            {"column_name": "Name","link_type": "drill_down","entity_title_column":"Disk Id",
                            "view_name":"/DA-ITSI-STORAGE-Disk_Entity_View","fields_to_add": {"disk_id": "Disk Id","disk_name": "Name"}}]
        },{
          "table_panel_id": "storagearrayvolumetable_panel_storagearrayvolumetable",
          "table_columns": [{"column_name": "Volume Id","link_type": "entity_view","entity_title_column":"Volume Id"},
                            {"column_name": "Name","link_type": "drill_down","entity_title_column":"Volume Id",
                            "view_name":"/DA-ITSI-STORAGE-Volume_Entity_View","fields_to_add": {"volume_id": "Volume Id","volume_name": "Name"}}]
        },{
          "table_panel_id": "storagearrayluntable_panel_storagearrayluntable",
          "table_columns": [{"column_name": "LUN Id","link_type": "entity_view","entity_title_column":"LUN Id"},
                            {"column_name": "Name","link_type": "drill_down","entity_title_column":"LUN Id",
                            "view_name":"/DA-ITSI-STORAGE-LUN_Entity_View","fields_to_add": {"lun_id": "LUN Id","lun_name": "Name"}}]
        }];

    EntityDrilldownUtils.renderTableLinks(link_configurations);

});
