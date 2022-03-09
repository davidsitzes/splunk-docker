/*global define */
define(function(require) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    var splunkUtil = require('splunk.util');
    var SearchManager = require('splunkjs/mvc/searchmanager');

    var BASE_URL = 'configs/conf-itsi_module_viz';
    // compile regex string to get row keys under a tab
    var regexForRow = /row\.\d/;

    // Polyfill for String.prototype.endsWith()
    if (!String.prototype.endsWith) {
        String.prototype.endsWith = function(searchString, position) {
            var subjectString = this.toString();
            if (typeof position !== 'number' || !isFinite(position) || Math.floor(position) !== position || position > subjectString.length) {
                position = subjectString.length;
            }
            position -= searchString.length;
            var lastIndex = subjectString.lastIndexOf(searchString, position);
            return lastIndex !== -1 && lastIndex === position;
        };
    }

    var Tab = Backbone.Model.extend({
        defaults: {
            control_token : '',
            title : '',
            rowsAndPanels: [],
            extendable_tab: false,
            tabId: ""
        },
        baseUrl: BASE_URL,
        parsedFields: ['control_token', 'title', 'extendable_tab', 'tabId'],

        /**
          * Initializes the model for each tab.
          * @constructor
          * @param {object} options
        **/
        initialize: function(attributes, options) {
            // Passed in defined service from collection to model
            this.splunkService = options.splunkService;
        },

        /**
          * The object that is returned from the server when querying the conf-tabs
          * endpoint ends up providing more information than necessary.  This parse
          * function is to only pull the necessary information required for the model
          * @override
          * @params {object} response
        **/
        parse: function(tabObj) {

            /* Determine whether this is an extendable tab or not
             * extendable_tab value gets stored as '0' or '1' in conf file
             */
            var isExtendable = (tabObj.extendable_tab === '1');

            var rowKeys = this._pickRowKeys(tabObj);

            /* Now, generate the array object by mapping its values and keys
             * This can be done with mapObject, but again only supported in 1.8.x
             * Currently a workaround using 1.6.0
            */
            var rowsAndPanels = [];
            _.each(rowKeys, function(value, key) {
                var keyIndex = parseInt(key.split('.')[1]);

                rowsAndPanels[keyIndex] = _.map(value.split(','), function(panel) {
                    var panelAndAppName = panel.split(':');
                    // JIRA SPL-119833 workaround: Find the corresponding panel object and search manager
                    // by virtue of the fact that the panel name and search share the same
                    // panel id name as a prefix. e.g. 'panel6' search manager will be 'panel6_search<some number>'
                    // If a panel is given an id, then the panel will be 'panel_name' and the corresponding
                    // search manager will be 'panel_name_search<some number>'
                    // There are likely scenarios where this will not work, but it should only be the case
                    // for 1 or 2 panels
                    var panelObject = _.chain(mvc.Components.pairs()).filter(function(attribute) {
                        return attribute[1].model &&
                            attribute[1].model.panel &&
                            attribute[1].model.panel.id &&
                            attribute[1].model.panel.id.indexOf(panelAndAppName[0]) > -1 &&
                            attribute[1].model.panel.id.endsWith('panels/' + panelAndAppName[1]);
                    }).first().value();

                    var panelSearch = _.chain(mvc.Components.pairs()).filter(function(attribute) {
                        return attribute[0].indexOf(panelObject[0] + '_search') === 0;
                    }).first().value();

                    return {
                        appName: panelAndAppName[0],
                        panelName: panelAndAppName[1],
                        panelObject: panelObject ? panelObject[1] : null,
                        panelSearchManager: panelSearch ? panelSearch[1] : null
                    };
                });
            });

            /* Even if the managed fields above are listed in
             * parsedFields, this works because extend() will override
             * them with the contents of the second object.
            */
            return _.extend({}, _.pick(tabObj, this.parsedFields), {
                rowsAndPanels: rowsAndPanels,
                extendable_tab: isExtendable
            });
        },

        /**
          * Saves the tab information for the given tab model. This can be used to both
          * create and update the tab
          * @override
        **/
        transformRawDataToObj: function() {

            var rowStrings = this._pickRowKeys(this.attributes);
            // Original tab information to post
            var postData = _.extend({}, _.pick(this.attributes, this.parsedFields), rowStrings);
            var tabId = postData.tabId;
            // remove tabId attribute since it's not written into conf file
            postData = _.omit(postData,'tabId');
            // prefix each key with tabId to match the format of itsi_module_viz file
            return this._prefixIdForTabAttributes(postData, tabId);
        },

        /**
         * Prefix tab ID to each tab attributes to be consistent with
         * itsi_module_viz.conf format. 
         * @param  {object} tabObj key:value pair object for given tab
         * @paran  {string} tabId  id for the given tab
         * @return {object}        key:value pair object for given tab with tab id prefixed
         */
        _prefixIdForTabAttributes: function(tabObj, tabId){
          var keyAddedTabObj = {};
          _.each(tabObj, function(value,key){
              keyAddedTabObj[tabId+'.'+key] = value;
          });
          return keyAddedTabObj;
        },

        /**
          * First, pick all of the keys from the stanza that have "row" in it
          * This can be done with _.pick, but only supported in Underscore 1.8.3
          * Currently a workaround using 1.6.0
          * @param {object} object
        **/

        _pickRowKeys: function(object) {
            return _.reduce(object, function(rowKeysObj, value, key){
              if (regexForRow.test(key) && !_.isEmpty(value.trim())) {
                rowKeysObj[key] = value;
              }
              return rowKeysObj;
            }, {});
        }
    });

    var TabCollection = Backbone.Collection.extend({
        model: Tab,
        baseUrl: BASE_URL,

        /**
          * Initializes the collection of tabs.  Within this collection, a new service is
          * instantiated so that calls with appropriate authorizations can be made to the
          * conf endpoints (regular GET/POST operations using Ajax won't work due to lack of
          * auth.  App context also gets set here
          * @constructor
          * @params {object} options
        **/
        initialize: function(models, options) {
            _.bindAll(this, 'fetch');

            // Creates an authenticated service to be able to communicate with REST endpoints
            this.splunkService = mvc.createService();
            this.splunkService['app'] = options.app;
            this.splunkService['owner'] = options.owner;
        },

        /**
          * Refreshes the XML view by hitting the custom REST endpoint that has been defined
          * to repopulate the XML view based on panel configuration information
        **/
        refreshXml: function(dash_script, dash_stylesheet) {
            return this.splunkService.post('xml/generate_xml/create', {
                title: _.first(document.title.split('|')).trim(),
                view_name: _.last(window.location.pathname.split('/')),
                app_name: this.splunkService['app'],
                dash_script: dash_script,
                dash_stylesheet: dash_stylesheet
            });
        },

        /** 
          * Returns an object that maps each panel name to an app name
          * @params {object} response
        **/
        mapPanelsToApps: function(response) {
            var panelAppMapping = {};

            // Make sure panels do exist beforehand, before parsing
            var responseObj = JSON.parse(response);

            if (_.isUndefined(responseObj['entry']) || _.isEmpty(responseObj['entry'])) {
                throw new Error("There were no existing prebuilt panels.");
            }

            _.each(responseObj['entry'], function(panel) {

                // FOR NOW, ONLY ALLOWING PANELS WITH CURRENT MODULE CONTEXT
                if (panel['acl']['app'] === this.splunkService['app']) {
                    panelAppMapping[panel['name']] = panel['acl']['app'];
                }
            }, this);

            return panelAppMapping;
        },

        /**
          * Populates a list of prebuilt panels by hitting the data/ui/panels endpoint
        **/
        getPrebuiltPanels: function() {

            // Bind map method to this object so can be used to call inside promise
            var mapPanelsToApps = _.bind(this.mapPanelsToApps, this);

            // Figured the parsing and structure of prebuilt panels object done on this end
            return this.splunkService.get('data/ui/panels', { count: 0 })
                .then(function(response) {
                    return mapPanelsToApps(response);
                });
        },

        /**
          * Gets the name of the view to get conf information to
          * Utility function
        **/
        getViewUrl: function(viewName) {
            viewName = viewName === undefined? _.last(window.location.pathname.split('/')) : viewName;
            if (_.isEmpty(viewName) || viewName === null) {
                throw new Error ('Please pass a valid view name!');
            }
            return this.baseUrl + '/' + encodeURIComponent(viewName);
        },

        /**
          * Parses the response object from making a fetch() call. Then group each tab's 
          * information into an object and return a list of tab objects
          * @override
          * params {object} response
        **/
        parse: function(response) {
            var responseObj = {};

            try {
              responseObj = JSON.parse(response);
            }
            catch(e) {
              console.error("Failed to parse the response.  Make sure it is valid JSON");
              throw e;
            }

            // Make sure response is well-formed so data can be extracted
            if (_.isUndefined(responseObj.entry) || _.isUndefined(_.first(responseObj.entry))||
                _.isUndefined(_.first(responseObj.entry).content)) {

                throw new Error("Failed to retrieve tab ordering.  Data was malformed");
            }

            // All tab information is under content 
            var content = _.first(responseObj.entry).content;
            // return a list of objects that contain each tab's information 
            return this._groupTabFromContent(content);
        },

        /**
          * Utility method used to take the data structure of rows and panels (array of arrays)
          * and transform it into the conf file format of "row.(x) = app:panel,app:panel"
        **/
        convertRowsPanelsToKeys: function() {
            return _.map(this.toJSON(), function(tab) {
                var rowsPanelsKeys = {};
                _.each(tab.rowsAndPanels, function(row, index) {
                    rowsPanelsKeys["row." + index] = _.map(row, function(panel) {
                        return panel.appName + ":" + panel.panelName;
                    }).join(',');
                });
                delete tab.rowsAndPanels;

                return _.extend({}, tab, rowsPanelsKeys);
            });
        },

        /**
          * Gets the string to POST to the view stanza of the tabs id
        **/
        getTabIdString: function(rawTabInfo) {
            return _.map(_.pluck(rawTabInfo, 'tabId'), function(tab) {
                return tab.replace(/\s/g, '_');
            }).join(",");
        },

        emptyCollectionIfFilled: function() {
            if (this.length > 0) {
                this.reset();
            }
        },

        /**
          * Fetches the view endpoint to get content in itsi_module_viz.conf and   
          * set tab collection. If the collection is already populated, reset
          * the collection and re-fetch
          * @override
        **/
        fetch: function() {

            /* If collection already populated, empty it out on a fresh fetch
             * Ideally should just leave collection be, but in case change made in another tab,
             * this is good practice
             * Future: leave collection be, allow refresh button to update tabs in same page without
             * full page reload?
             */
            this.emptyCollectionIfFilled();
            var baseViewUrl = this.getViewUrl();
            // Fetch all tab information under view stanza, parse through it 
            // and set to collection
            var getTabCollection = _.bind(function(response) {
                var tabList = this.parse(response);
                var sortedModels = [];
                // Iterate through list of tab object and push each object 
                // into array after parsing it
                var tabModelList = _.map(tabList, function(tab, index){
                  var tempTabModel = new this.model(null, {
                        splunkService : this.splunkService
                  });
                  var parsedTabModel = tempTabModel.parse(tab);
                  sortedModels.push(parsedTabModel);
                }, this);

                var setCollection = this.set(sortedModels);

                // JIRA SPL-119833 workaround: payload control token into the search
                this.each(function(tab) {
                  _.chain(tab.get('rowsAndPanels'))
                    .flatten()
                    .pluck('panelSearchManager')
                    .compact()
                    .each(function(searchManager) {
                      var newSearch = splunkUtil.sprintf('$%s$ %s',
                          tab.get('control_token'),
                          searchManager.attributes.search);
                      searchManager.settings.set('search', mvc.tokenSafe(newSearch));
                    });
                });

                return setCollection;
            }, this);
            return this.splunkService.get(baseViewUrl).then(getTabCollection);
        },

        /** Saves the tab information for both newly created and existing tabs.  This doubles
          * to function as both creating new tabs and conf information as well as updating the
          * information for the existing tabs.
          * @override
        **/
        save: function() {
            /* Build the ordering of tabs string to save
             * First, take rowsAndPanels and create keys instead
            */
            var rawTabInfo = this.convertRowsPanelsToKeys();

            // The tabIdString is built from taking tabId
            var tabIdString = this.getTabIdString(rawTabInfo);

            var baseViewUrl = this.getViewUrl();

            var promise = new $.Deferred();
            var allTabs = _.zip(tabIdString.split(','), rawTabInfo);
            var newTabModel = new this.model(null, {
                    splunkService: this.splunkService
                });
            newTabModel.set(_.last(allTabs)[1]);
            var postData = _.extend({tabs:tabIdString},newTabModel.transformRawDataToObj());
            return this.splunkService.post(baseViewUrl, postData).done(function(){
              promise.resolve();
            });
        },

        /**
         * This function groups information related to the same tab into a tab object 
         * by its identifier (in this case tabId), which will be later on set to a tab model.
         * @param  {JSON object} content JSON object that contains all information under view stanza in itsi_module_viz file
         * @return {list}                List of key:value pair tab objects 
         */
        _groupTabFromContent: function(content) {
            var tabIds = content.tabs.replace(/\s+/g, '').split(',');
            var tabInfo = _.chain(content)
                    .map(function(v, k) { return [k.split('.'), v]; })
                    .filter(function(cp) { return cp[0].length > 1; }) /* Tab tokens have a period, filter for that */
                    .groupBy(function(cp) { return cp[0][0]; })        /* Tab IDs are the first element of the token */
                    .value();
            return _.map(tabIds, function(tabId) {
                return _.extend({tabId: tabId}, _.object(_.map(tabInfo[tabId], function(cp) {
                    return [cp[0].slice(1).join('.'), cp[1]];
                })));
            });
        }
    });

    return TabCollection;
});
