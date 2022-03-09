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
    var entityFilterPhrase = '| WHERE itsi_role="virtualization" AND (type="datastore" OR type="hypervisor")';
    var entityIdSearch=EntityDrilldownUtils.createEntitySearchManager(moduleSavedSearch,entityFilterPhrase);
    EntityDrilldownUtils.fetchEntityFromSearchManager(entityIdSearch);

    //Prepare configuration object to link table with other entity drill down or entity detail view
    var link_configurations = [{
          "table_panel_id": "vmdstable_panel_vmdstable",
          "table_columns": [{"column_name": "Datastore Id","link_type": "entity_view","entity_title_column":"Datastore Id"},
                            {"column_name": "Datastore Name","link_type": "drill_down","entity_title_column":"Datastore Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-Datastore_Entity_View","fields_to_add": {"datastore_id": "Datastore Id","datastore_name": "Datastore Name"}}]
        }];

    EntityDrilldownUtils.renderTableLinks(link_configurations);

    // Link Hypervisor Id in inventory context panel to Hypervisor Drill Down view
    //(View link in inventory poupup)
    $("body").on("entity-fields-change-event", "#inventory-fields-modal", function(e, entity_info) {
        if (!_.isUndefined(entity_info)){

            var hypervisor_id_value = entity_info["Hypervisor Id"];
            var hypervisor_name_value = entity_info["Hypervisor Name"];
            var fieldsToAdd = {};
            if(hypervisor_id_value != "" && hypervisor_name_value != ""){
                fieldsToAdd["hypervisor_id"] = hypervisor_id_value;
                fieldsToAdd["hypervisor_name"] = hypervisor_name_value;
            }

            if(hypervisor_id_value != "" && hypervisor_name_value != ""){
                $("#inventory-fields-modal label:contains('Hypervisor Name:')").html("Hypervisor Name: <a class='vmds-drilldown external' id='hypervisorLink_model'>"+hypervisor_name_value+"</a>");
                $( "#hypervisorLink_model" ).click(function() {
                    var url = EntityDrilldownUtils.getOtherEntityDrilldownUrl(hypervisor_id_value, '/DA-ITSI-VIRTUALIZATION-Hypervisor_Entity_View', fieldsToAdd);
                    splunkjsUtils.redirect(url, true);
                });
            }
        }
    });
    // (View link in inventory context panel on header of dashboard)
    $("body").on("entity-fields-change-event", "#entity-context-panel-entity-info", function(e, entity_info) {
        if (!_.isUndefined(entity_info)){

            var hypervisor_id_value = entity_info["Hypervisor Id"];
            var hypervisor_name_value = entity_info["Hypervisor Name"];
            var fieldsToAdd = {};
            if(hypervisor_id_value != "" && hypervisor_name_value != ""){
                fieldsToAdd["hypervisor_id"] = hypervisor_id_value;
                fieldsToAdd["hypervisor_name"] = hypervisor_name_value;
            }

            if(hypervisor_id_value != "" && hypervisor_name_value != ""){
                $("#entity-context-panel-entity-info span:contains("+hypervisor_name_value+")").html("<a class='vmds-drilldown external' id='hypervisorLink_context'>"+hypervisor_name_value+"</a>");
                $( "#hypervisorLink_context" ).click(function() {
                    var url = EntityDrilldownUtils.getOtherEntityDrilldownUrl(hypervisor_id_value, '/DA-ITSI-VIRTUALIZATION-Hypervisor_Entity_View', fieldsToAdd);
                    splunkjsUtils.redirect(url, true);
                });
            }
        }
    });

});

