define(function (require) {
    var $ = require('jquery');
    var _ = require('underscore');
    var mvc = require('splunkjs/mvc');
    var TableView = require('splunkjs/mvc/tableview');
    var splunkjsUtils = require('splunkjs/mvc/utils');
    var SearchManager = require('splunkjs/mvc/searchmanager');

    //Entity information dictionary object which will contain itsi entity id, entity title, service id and service title
    var entitySearchResult = {};

    /**
     * EntityDrilldownUtils contains common utils which can be used to get entity drilldown link in module drilldown views.
     * @module EntityDrilldownUtils
     * @type {{
         * getOtherEntityDrilldownUrl: Function,
         * getDrillDownPayloadURL: Function,
         * getDrillDownSimpleURL: Function,
         * getEntityDetailUrl: Function,
         * createEntitySearchManager: Function,
         * fetchEntityFromSearchManager: Function,
         * renderTableLinks: Function,
         * searchResultsToDictionary: Function,
         * getCurrentLocationPathName: Function,
         * getCurrentLocationOrigin: Function,
         * getCurrentLocationSearch: Function
         * redirectURL: Function}}
     */

    var EntityDrilldownUtils = {

        /**
         * Get entity drilldown url by update entity title, entity id, service title and service id in the drilldown_payload of current uri.
         *
         * @param {string} newEntityTitle  -- New value of entity title field
         * @param {string} newViewName -- View name which need to redirect from table
         * @param {string} fieldsToAdd -- [Optional parameter] Extra fields need to pass with paylod.entities id and title. If no other fields to pass leave it blank as '{}'
         * @returns {string} -- Updated drilldown_payload json URL or simple URL
         */
        getOtherEntityDrilldownUrl: function (newEntityTitle, newViewName, fieldsToAdd) {

            // Try to get new entity details from entity search result
            var entityDetails = _.first(_.where(entitySearchResult, {entity_title: newEntityTitle}));
            if (_.isUndefined(entityDetails)) {
                throw new Error("Failed to retrieve drilldown url because no such entity id in the kvstore.");
            }

            var searchString = '?';

            // Try to get drilldown_payload from query parameters first
            var queryParams = {};
            _.each(this.getCurrentLocationSearch().substring(1).split("&"), function (kvp) {
                var pairs = kvp.split('=');
                queryParams[pairs[0]] = decodeURIComponent(pairs[1]);
            });

            if (!_.isEmpty(queryParams['drilldown_payload'])) {
                searchString += this.getDrillDownPayloadURL(queryParams, entityDetails, newEntityTitle, fieldsToAdd);
            }
            else if (!_.isEmpty(queryParams['entity.id']) && !_.isEmpty(queryParams['entity.title'])) {
                searchString += this.getDrillDownSimpleURL(queryParams, entityDetails, newEntityTitle, fieldsToAdd);
            }
            else {
                throw new Error("Failed to retrieve drilldown url because no drilldown_payload or simple type URL found in current URL.");
            }

            if (searchString === '?') {
                throw new Error("Failed to retrieve drilldown url.");
            }

            var pathName = this.getCurrentLocationPathName();
            var url = this.getCurrentLocationOrigin() + pathName.substr(0, pathName.lastIndexOf('/')) + newViewName + searchString;

            return url;
        },

        /**
         * Get entity drilldown url by update entity title, entity id, service title and service id in current uri.
         *
         * @param {string} queryParams -- Parameter list of current URL
         * @param {string} newEntityTitle  -- New value of entity title field
         * @param {string} entityDetails -- entity details from kvstore
         * @param {string} fieldsToAdd -- [Optional parameter] Extra fields need to pass with paylod.entities id and title. If no other fields to pass leave it blank as '{}'
         * @returns {string} -- Updated drilldown_payload json parameters
         */
        getDrillDownPayloadURL: function (queryParams, entityDetails, newEntityTitle, fieldsToAdd) {

            var searchString = '';
            var payload = JSON.parse(queryParams['drilldown_payload']);

            //Now Update payload entity and service details
            if (!_.isUndefined(payload.entities)) {

                //Created updated entity object
                updatedEntity = {};
                updatedEntity['title'] = newEntityTitle;
                updatedEntity['id'] = entityDetails['entity_key'];

                //Add extra fields in entity if any
                if (!_.isUndefined(fieldsToAdd)) {
                    _.each(fieldsToAdd, function (value, key) {
                        updatedEntity[key] = value;
                    });
                }

                //Create new entities array object for payload
                payload.entities = [];
                payload.entities.push(updatedEntity);

                //Update curent service id
                if (!_.isEmpty(entityDetails['service_key'])) {

                    //Update first service id and title if an entity has more than one service
                    if(Array.isArray(entityDetails['service_key'])){
                        payload.context.service_id = entityDetails['service_key'][0];
                        payload.context.service_title = entityDetails['service_title'][0];
                    }
                    else{
                        payload.context.service_id = entityDetails['service_key'];
                        payload.context.service_title = entityDetails['service_title'];
                    }
                }else{
                    throw new Error("Failed to find service for selected entity.");
                }

            }else{
                throw new Error("Failed to find the entity key in the payload JSON.");
            }

            // Now generate drilldown_payload, query paramters and final url
            queryParams.drilldown_payload = JSON.stringify(payload);

            searchString += _.map(queryParams, function (value, key) {
                return key + '=' + encodeURIComponent(value);
            }).join('&');

            return searchString;
        },

        /**
         * Get entity drilldown url by update entity title, entity id, service title and service id in the current uri.
         *
         * @param {string} queryParams -- Parameter list of current URL
         * @param {string} newEntityTitle  -- New value of entity title field
         * @param {string} entityDetails -- entity details from kvstore
         * @param {string} fieldsToAdd -- [Optional parameter] Extra fields need to pass with paylod.entities id and title. If no other fields to pass leave it blank as '{}'
         * @returns {string} -- Updated drilldown_payload simple URL parameters
         */
        getDrillDownSimpleURL: function (queryParams, entityDetails, newEntityTitle, fieldsToAdd) {

            var searchString = '';
            var newQueryParams = {};

            if (!_.isEmpty(entityDetails['service_key'])) {

                //Update curent service id. If an entity has more than one service, update first service id and title.
                if(Array.isArray(entityDetails['service_key'])){
                    newQueryParams['service_id'] = entityDetails['service_key'][0];
                    newQueryParams['service_title'] = entityDetails['service_title'][0];
                }
                else{
                    newQueryParams['service_id'] = entityDetails['service_key'];
                    newQueryParams['service_title'] = entityDetails['service_title'];
                }

                //Update entity id and title for new drill down
                newQueryParams['entity.id'] = entityDetails['entity_key'];
                newQueryParams['entity.title'] = newEntityTitle;

                //Add extra fields in entity if any
                if (!_.isUndefined(fieldsToAdd)) {
                    _.each(fieldsToAdd, function (value, key) {
                        newQueryParams['entity.'+key] = value;
                    });
                }

                // Get required params from queryParams
                var requiredParams = ['kpi_id','kpi_title','earliest','latest'];
                _.each(requiredParams, function (value, index) {
                    if (!_.isEmpty(queryParams[value])) {
                      newQueryParams[value] = queryParams[value];
                    }
                });

                serialize = function(obj) {
                      var str = [];
                      for(var p in obj)
                        if (obj.hasOwnProperty(p)) {
                          str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
                        }
                      return str.join("&");
                    }
                searchString = serialize(newQueryParams);
            }

            return searchString;
        },

        /**
         * Get Entity detail URL (To View Entity Health)
         *
         * @param {string} entity  -- Current entity title for which user want to show Entity Health
         * @returns {string} -- Entity Detail URL
         */
        getEntityDetailUrl: function (entityTitle) {
            // Try to get new entity details from entity search result
            var entityDetails = _.first(_.where(entitySearchResult, {entity_title: entityTitle}));
            if (_.isUndefined(entityDetails)) {
                throw new Error("Failed to retrieve entity detail url because no such entity id in the kvstore.");
            }

            var searchString = '?';
            if (!_.isEmpty(entityDetails['entity_key'])){
                searchString += 'entity_key=' + entityDetails['entity_key'];
            }

            if (searchString === '?') {
                throw new Error("Failed to retrieve entity detail url.");
            }

            var pathName = this.getCurrentLocationPathName();
            var url = this.getCurrentLocationOrigin() + pathName.substr(0, pathName.lastIndexOf('/')) + '/entity_detail' + searchString;

            return url;
        },

        ///**
        // * Create a search manager for itsi entity lookup.
        // * It can be called from Drill Down view based on view related filters.
        // *
        // * @param {string} moduleSavedSearch  -- module saved search for entity
        // * @param {string} entityFilterPhrase  -- additional filter phase for entity, for example, only entity types that are for drilldown links.
        // * @returns {object} -- search manager
        // */
        createEntitySearchManager: function (moduleSavedSearch, entityFilterPhrase) {
            return new SearchManager({
                id: 'entity-id-search',
                search: mvc.tokenSafe('| savedsearch ' + moduleSavedSearch + ' | lookup itsi_entities title as entity_title OUTPUT _key as entity_key, services._key as service_key | lookup alarm_console_lookup _key as service_key output title as service_title ' + entityFilterPhrase + ' | fields + entity_key,entity_title,service_key,service_title'),
                'auto_cancel': 90,
                'preview': true,
                'wait': 0,
                'runOnSubmit': true,
                'cache': false
            });
        },

        ///**
        // * Fetch entity information using passed search manager.
        // * It is used to fill up global object "entitySearchResult" which will used in getOtherEntityDrilldownUrl to find clicked entity details from this object.
        // * The search manager can be created using createEntitySearchManager, or directly from Drill Down view.
        // * The result of search must include fields: entity_key,entity_title,service_key,service_title.
        // *
        // * @param {object} entityIdSearch  -- search manager for entity.
        // */
        fetchEntityFromSearchManager: function (entityIdSearch) {
            var entityIdSearchResults = entityIdSearch.data('results', {count: 0});
            var that = this;
            entityIdSearchResults.on('data', function() {
                if (!_.isUndefined(entityIdSearchResults.data())){
                        entitySearchResult = that.searchResultsToDictionary(entityIdSearchResults.data().rows,
                            entityIdSearchResults.data().fields);
                }
            });
        },

        /**
         * Add customization to table. Use the BaseCellRenderer class to create a custom table cell renderer
         *
         * @param {Object} link_configurations - configuration object to link table with other entity drill down or entity detail view
         * One example:
         * link_configurations = [{
          "table_panel_id": "vmdstable_panel_vmdstable",
          "table_columns": [{"column_name": "Datastore Id","link_type": "entity_view","entity_title_column":"Datastore Id"},
                            {"column_name": "Datastore Name","link_type": "drill_down","entity_title_column":"Datastore Id",
                            "view_name":"/DA-ITSI-VIRTUALIZATION-Datastore_Entity_View","fields_to_add": {"datastore_id": "Datastore Id","datastore_name": "Datastore Name"}}]
            }];
         */
        renderTableLinks: function (link_configurations) {
            var that = this;
            _.each(link_configurations, function (table_value, table_key) {
                var table_panel_id = table_value['table_panel_id'];
                var table_columns = table_value['table_columns'];

                var link_table = [];
                mvc.Components.get(table_panel_id).getVisualization(function(table) {
                    link_table[table_key] = table;

                    // Add link on table cell value
                    _.each(table_columns, function (value, key) {
                        var CustomCellRenderer = TableView.BaseCellRenderer.extend({
                            canRender: function(cellData) {
                                return cellData.field === value['column_name'];
                            },
                            // This render function only works when canRender returns 'true'
                            render: function($td, cellData) {
                                $td.html(that._linkTemplate({
                                    name: cellData.value
                                }));
                            }
                        });
                        link_table[table_key].addCellRenderer(new CustomCellRenderer());
                    });

                    // Bind link when user click on value
                    _.each(table_columns, function (value, key) {
                        link_table[table_key].on("click:cell", function (e) {
                            var url = "";

                            if (e.key === value['column_name'] && value['link_type'] === "entity_view") {
                                e.preventDefault();

                                url = that.getEntityDetailUrl(e.data["row."+value['entity_title_column']+""]);
                            }
                            else if (e.key === value['column_name'] && value['link_type'] === "drill_down") {
                                e.preventDefault();

                                var fieldsToAdd = {};
                                _.each(value['fields_to_add'], function (field_value, field_key) {
                                    fieldsToAdd[field_key] = e.data["row."+field_value+""];
                                });

                                url = that.getOtherEntityDrilldownUrl(e.data["row."+value['entity_title_column']+""], value['view_name'], fieldsToAdd);
                            }

                            that.redirectURL(url);
                        });
                    });
                });
            });
        },

        /**
         * Convert Splunk search result rows into a dictionary
         *
         * @param {Array} rows
         * @param {Array} fields
         * @returns {Object}
         */
        searchResultsToDictionary: function (rows, fields) {
            var rowItems = {};

            _.each(rows, function (row, index) {
                var rowItem = {};
                _.each(row, function (item, index) {
                    rowItem[fields[index]] = item;
                });
                rowItems[index] = rowItem;
            });

            return rowItems;
        },

        /**
         * Redirect url if not empty
         *
         * @param {string} url to direct
         */
        redirectURL: function (url) {
            if (!_.isEmpty(url)) {
                splunkjsUtils.redirect(url, true);
            }
        },

        /**
         * Get current window location pathname.
         *
         * @returns {string} -- current window location pathname.
         */
        getCurrentLocationPathName: function () {
            return window.location.pathname;
        },

        /**
         * Get current window location origin.
         *
         * @returns {string} -- current window location origin.
         */
        getCurrentLocationOrigin: function () {
            return window.location.origin;
        },

        /**
         * Get current window location search.
         *
         * @returns {string} -- current window location search string.
         */
        getCurrentLocationSearch: function () {
            return window.location.search;
        },

        _linkTemplate: _.template('<a class="external"><%- name %></a>')

    };

    return EntityDrilldownUtils;
});