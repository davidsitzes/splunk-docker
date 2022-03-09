define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    var SearchManager = require('splunkjs/mvc/searchmanager');

    var EntityContextPanelModel = Backbone.Model.extend({
        defaults: function () {
            return {
                entity_info_search_manager: null,
                requested_entity_tokens: [],
                entities: [],
                current_entity: {},
                current_entity_info: {},

                // Context preview chart models
                context_charts: [],

                // Used to render context link at top of panel
                context_content_title: '',
                context_content_value: '',
                context_content_link: ''
            };
        },

        /**
         * Initializes the model
         *
         * @param {Object} attributes
         * @param {Object} options
         * @public
         */
        initialize: function (attributes, options) {
            Backbone.Model.prototype.initialize.apply(this, arguments);

            if (_.isEmpty(this.get('entities'))) {
                var entityFilter = {entity_filter:JSON.stringify(this.get('entity_search_filter'))};
                var baseUrl = Splunk.util.make_url([
                            'custom',
                            'SA-ITOA',
                            'itoa_interface',
                            'get_entity_filter',
                            'nobody'
                            ].join('/'));
                $.ajax({
                    url: baseUrl,
                    type: 'GET',
                    dataType: 'json',
                    async: true,
                    data: entityFilter
                }).done(_.bind(this._setEntities,this));

            } else {
                this.set('current_entity', _.first(this.get('entities')));
            }
            this._runEntityInfoSearch();
        },

        /**
         * Does nothing.
         *
         * @public
         */
        fetch: function () {
            return new $.Deferred().resolve();
        },

        /**
          * Runs the entity info search
          * This works well with lookups
          *
          * @private
          */
        _runEntityInfoSearch: function() {
            this.entityInfoSearchManager = mvc.Components.get(this.get('entity_info_search_manager'));
            if (this.entityInfoSearchManager instanceof SearchManager) {
                this.entityInfoSearchResults = this.entityInfoSearchManager.data('results');
                this.entityInfoSearchResults.on('data', this._setEntityInfo, this);
            } else {
                throw 'No entity_info_search_manager provided.';
            }
        },

        /**
         * Converts entity REST call results into a dictionary 
         * and set entities fields based on where it's navigating from
         *
         * @private
         */
        _setEntities: function(results) {
            var isFromEntityDetails = this.get('is_from_entity_details');
            if (!_.isUndefined(isFromEntityDetails) && isFromEntityDetails === true){
                // filter entities by key and title if navigating from entity details
                this.set('entities',
                    _.filter(results, function(result){
                        return result._key === this.get('current_entity').id &&
                               result.title === this.get('current_entity').title;
                    }, this));
            }
            else {
                // filter entities by service id if navigating from deep dive
                var filteredEntities = _.filter(results, function(result){
                            return _.any(result.services, function(service) {
                                return service._key === this.get('service_id');
                            },this);
                        }, this);

                var currentEntityIncluded = _.any(filteredEntities,function(entity){
                                                return entity._key === this.get('current_entity').id;
                                            },this);

                // merge filteredEntities with current_entity if current_entity
                // is not included
                if (!currentEntityIncluded)
                    filteredEntities.push(this.get('current_entity'));

                // sort entities by title
                filteredEntities.sort(this._sortByAlphabet('title'));
                this.set('entities', filteredEntities);
            }
        },

        /**
         * Converts entity info search results into a dictionary
         *
         * @private
         */
        _setEntityInfo: function() {
            if (!_.isUndefined(this.entityInfoSearchResults.data())){
                this.set('current_entity_info',
                this._rowToDictionary(
                    _.first(this.entityInfoSearchResults.data().rows),
                     this.entityInfoSearchResults.data().fields));
            }
        },

        /**
         * Convert a Splunk search result row into a dictionary
         *
         * @param {Array} row
         * @param {Array} fields
         * @returns {Object}
         * @private
         */
        _rowToDictionary: function(row, fields) {
            var rowItem = {};
            _.each(row, function(item, index) {
                rowItem[fields[index]] = item;
            });

            return rowItem;
        },

        /**
         * Sort the array of objects by property name in an alphabetical manner
         * @param {propName} property of object by which we want to sort alphabetically
         */
        _sortByAlphabet: function (propName) {
            return function (obj1, obj2) {
                return obj1[propName].localeCompare(obj2[propName]);
            };
        }
    });

    return EntityContextPanelModel;
});