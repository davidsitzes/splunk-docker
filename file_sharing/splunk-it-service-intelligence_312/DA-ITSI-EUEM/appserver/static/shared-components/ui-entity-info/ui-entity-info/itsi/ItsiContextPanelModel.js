/*global define */
define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    var splunkUtil = require('splunk.util');
    var SearchManager = require('splunkjs/mvc/searchmanager');
    var EntityContextPanelModel = require('./../base/EntityContextPanelModel');
    var TokenUtils = require('./../base/EntityContextPanelTokenUtils');
    var ServiceModelCollectionStub = require('./ServiceModelCollectionStub');

    var ItsiContextPanelModel = EntityContextPanelModel.extend({
        defaults: function () {
            return _.extend(EntityContextPanelModel.prototype.defaults(), {
                service_id: '',
                kpi_id: '',
                service_title: '',
                service_url: '',
                service_detail_url: '',
                kpi_title: '',
                kpi_url: '',
                entity_search_filter: '',
                is_from_entity_details: null
            });
        },

        serviceCollection: null,

        /**
         * Based on page tokens, fetches service and KPI data from ITSI and
         * fulfills promise after model is filled in
         * URL parameters can be in 2 forms: simple and json mode
         * Json mode (data is provided through a JSON payload in the query parameters):
         *   Query params:
         *     drilldown_payload - the JSON payload:
         *   Payload sample structure:
         *   {
         *     "context": {
         *       "earliest": <earliest time of full lane>,
         *       "latest": <latest time of full lane>,
         *       "bucket_earliest": <earliest time of bucket clicked>,
         *       "bucket_latest": <latest time of the bucket clicked>,
         *       "service_id": "158bdaf4-6b0c-433e-9c24-c3a36c0e8eea",
         *       "kpi_id": "65ec30c5e1dd5046ac5416f5",
         *       "service_title": "Production Webservers",
         *       "kpi_title": "Total Request Latency (ms)"
         *     },
         *     "entities": [
         *       {
         *         "id": "5303377f-162c-45cc-809a-d1e3254ea4a1",
         *         "title": "Host Title 1",
         *         "host": "Host1",
         *         "family": "Linux"
         *       },
         *       {
         *         "id": "7aefd044-0f46-4ba4-ab13-f31e5797a3bf",
         *         "title": "Host Title 2",
         *         "host": "Host2",
         *         "family": "Linux"
         *       }
         *     ]
         *   }
         * Simple mode (data is provided as direct query parameters):
         *   service_id - the service ID
         *   service_title - the service title
         *   kpi_id - the KPI ID in the service
         *   kpi_title - the KPI title
         *   Entities can be specified as follows:
         *     entity.<idx>.<attribute name>=<attribute_value>
         *   Example:
         *     entity.0.id=5303377f-162c-45cc-809a-d1e3254ea4a1&
         *     entity.0.host=Host1&
         *     entity.0.family=Linux
         *
         * @param {Object} attributes
         * @param {Object} options
         * @public
         */
        initialize: function (attributes, options) {
            var tokens = mvc.Components.getInstance('default');
            var tokensToSubmit = {};
            var context = {};

            var contextFields = ['service_id', 'service_title', 'kpi_id', 'kpi_title'];
            var fromPayload = function(payload) {
                return {
                    fields: _.pick(payload.context, contextFields),
                    entities: payload.entities
                };
            };

            if (_.isEmpty(tokens.get('drilldown_payload'))) {
                context = {
                    fields: tokens.pick(contextFields),
                    entities: _.reduce(tokens.attributes, function (memo, value, key) {
                        var parts = key.split('.');
                        if (parts[0] === 'entity') {
                            memo[0] = memo[0] || {};
                            memo[0][parts[1]] = value;
                        }
                        return memo;
                    }, [])
                };

                if (_.isEmpty(tokens.get('earliest')) || _.isEmpty(tokens.get('latest'))) {
                    tokensToSubmit.earliest = '-24h';
                    tokensToSubmit.latest = 'now';
                } else {
                    tokensToSubmit.earliest = tokens.get('earliest');
                    tokensToSubmit.latest = tokens.get('latest');
                }

            } else {
                var payload = JSON.parse(tokens.get('drilldown_payload'));
                context = fromPayload(payload);
                if (_.isEmpty(tokens.get('earliest')) || _.isEmpty(tokens.get('latest'))) {
                    if (payload.context.earliest !== undefined && payload.context.latest !== undefined){
                        tokensToSubmit.earliest = payload.context.earliest;
                        tokensToSubmit.latest = payload.context.latest;
                    } else {
                        tokensToSubmit.earliest = '-24h';
                        tokensToSubmit.latest = 'now';
                    }
                }
            }

            this.set(_.extend(context.fields, {
                'current_entity': _.first(context.entities),
                'is_from_entity_details': document.referrer.indexOf('entity_detail') > -1
            }));
            
            // Set tokens for the first entity on the page
            _.each(this.get('current_entity'), function (value, token) {
                tokensToSubmit[token] = value;
            }, this);

            TokenUtils.submitTokens(tokensToSubmit);

            EntityContextPanelModel.prototype.initialize.apply(this, arguments);
        },

        /**
         * Fetches service data from ITSI
         *
         * @param {Object} options
         * @returns {XHR} the fetch XHR
         * @public
         */
        fetch: function (options) {
            var promise = $.Deferred();

            if (this._isFetchPossible()) {
                if (this._isFetchRequired()) {
                    var deferreds = [];
                    deferreds.push(this._fetchServiceCollection());

                    $.when.apply($, deferreds).then(
                        // Success
                        _.bind(function () {
                            if (this.serviceCollection.length < 1) {
                                promise.reject(null, _('Service not found').t(), options);
                            }

                            var serviceModel = this.serviceCollection.first();
                            var kpiModel = _.first(_.where(serviceModel.get('kpis'), {_key: this.get('kpi_id')}));
                            if (_.isUndefined(kpiModel)) {
                                promise.reject(null, _('KPI not found').t(), options);
                            }

                            this.set('service_title', serviceModel.get('title'));
                            this.set('kpi_title', kpiModel.title);
                        }, this),
                        // Failure
                        _.bind(function () {
                            promise.reject(null, _('Error fetching ITSI services').t(), options);
                        }, this)
                    );
                }

                this.set('service_url', this._getServiceUrl(this.get('service_id')));
                this.set('kpi_url', this._getKpisUrl(this.get('service_id')));
                this.set('service_detail_url', this._getServiceDetailUrl(this.get('service_id')));

                this.set('context_content_title', _('Service').t());
                this.set('context_content_value', this.get('service_title'));
                this.set('context_content_link', this.get('service_detail_url'));
            }
            promise.resolve(this, _('Success').t(), options);
            return promise;
        },

        /**
         * Validates the model
         *
         * @param {Object} attributes
         * @param {Object} options
         * @returns {Boolean}
         * @public
         */
        validate: function (attributes, options) {
            return EntityContextPanelModel.prototype.validate.apply(this, arguments);
        },

        /**
         * Checks internal fields to determine if a fetch is required
         *
         * @returns {Boolean}
         */
        _isFetchRequired: function () {
            if (this.get('is_from_entity_details')){
                return false;
            } else{
                return (_.isEmpty(this.get('service_title')) ||
                        _.isEmpty(this.get('kpi_title')));
            }
        },

        /**
         * Checks internal fields to determine if a fetch is possible
         *
         * @returns {Boolean}
         */
        _isFetchPossible: function () {
            if (this.get('is_from_entity_details')){
                return true;
            } else{
                return !(_.isEmpty(this.get('service_id')) ||
                         _.isEmpty(this.get('kpi_id')));
            }
        },

        /**
         * Invokes the ITSI service REST endpoint for the service collection
         *
         * @returns {Deferred}
         */
        _fetchServiceCollection: function () {
            this.serviceCollection = new ServiceModelCollectionStub();
            this.serviceCollection.setServiceFilter(this.get('service_id'));
            return this.serviceCollection.fetch();
        },

        /**
         * Gets the url for service detail page given a service id.
         *
        **/
        _getServiceDetailUrl: function (serviceId) {
            return splunkUtil.make_url([
                'app',
                'itsi',
                'service_detail?serviceId=' + serviceId
            ].join('/'));
        },

        // Taken from ServiceModel in ITSI
        _getServiceUrl: function (serviceId) {
            return splunkUtil.make_url([
                'app',
                'itsi',
                'service_definition#' + serviceId + '/info'
            ].join('/'));
        },

        // Taken from ServiceModel in ITSI
        _getKpisUrl: function (serviceId) {
            return this._getServiceUrl(serviceId) + '&section=kpis';
        }
    });

    return ItsiContextPanelModel;
});
