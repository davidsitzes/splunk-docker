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

	// Link STORAGE ARRAY Id in inventory context panel to STORAGE ARRAY Drill Down view
    //(View link in inventory poupup)
    $("body").on("entity-fields-change-event", "#inventory-fields-modal", function(e, entity_info) {
        if (!_.isUndefined(entity_info)){
            var array_id_value = entity_info["Storage Array Id"];
            var fieldsToAdd = {};
            if(_.isString(array_id_value) && array_id_value.length > 0 ){
                fieldsToAdd["array_id"] = array_id_value;
            }

            if(_.isString(array_id_value) && array_id_value.length > 0 ){
                $("#inventory-fields-modal label:contains('Storage Array Id:')").html("Storage Array Id: <a class='vmds-drilldown external' id='storageArrayLink_model'>" + array_id_value + "</a>");
                $( "#storageArrayLink_model" ).click(function() {
                    var url = EntityDrilldownUtils.getOtherEntityDrilldownUrl(array_id_value, '/DA-ITSI-STORAGE-Storage_Array_Entity_View', fieldsToAdd);
                    splunkjsUtils.redirect(url, true);
                });
            }
        }
    });

    // (View link in inventory context panel on header of dashboard)
    $("body").on("entity-fields-change-event", "#entity-context-panel-entity-info", function(e, entity_info) {
        if (!_.isUndefined(entity_info)){
            var array_id_value = entity_info["Storage Array Id"];
            var fieldsToAdd = {};
            if(_.isString(array_id_value) && array_id_value.length > 0 ){
                fieldsToAdd["array_id"] = array_id_value;
            }

            if(_.isString(array_id_value) && array_id_value.length > 0 ){
                $("#entity-context-panel-entity-info span:contains('" + array_id_value + "')").filter(function(){
                    if($(this).text() === array_id_value){
                        $(this).html("<a class='vmds-drilldown external' id='storageArrayLink_context'>" + array_id_value + "</a>");
                        $( "#storageArrayLink_context" ).click(function() {
                            var url = EntityDrilldownUtils.getOtherEntityDrilldownUrl(array_id_value, '/DA-ITSI-STORAGE-Storage_Array_Entity_View', fieldsToAdd);
                            splunkjsUtils.redirect(url, true);
                        });
                    }
                });
            }
        }
    });
	
});
