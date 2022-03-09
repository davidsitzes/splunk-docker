/*global define */
define(function(require) {
    var _ = require('underscore');
    var $ = require('jquery');
    var Backbone = require('backbone');
    var sdk = require('splunkjs/splunk');
    var mvc = require('splunkjs/mvc');
    var ItsiContextModel = require('../itsi/ItsiContextPanelModel');

    /** 
     * Fetches KPI information so that the session information can be
     * related to a data model field.  Deep Dive Lane information is
     * fragile and customizable from session to session; the underlying
     * datamodel information is not.
     **/
    
    return Backbone.Model.extend({

        /**
          * Initializes the model
          * @constructor
          * @param {object} options
        **/
        initialize: function(attributes, options) {
            Backbone.Model.prototype.initialize.apply(this, arguments);

            // Passed in defined service from collection to model
            this._kpi_title = null;
            this.itsiContext = options.itsiContext;
        },

        /** 
          * Given the fetch is complete and the page has loaded, this
          * returns the data model field name (actually, the threshold
          * field name, which is the long form for data model objects,
          * and can be associated with other objects) associated with
          * the referring JSON payload.
         **/

        choice: function() {
            return this.get(this._kpi_title);
        },

        /** 
          * Given a list of allocated fieldnames, (activation rule
          * tokens already in the tabs.conf file, for example), return
          * a record of {KPI_Title: Fieldname} pairs for use in the
          * dynamic tab display.
         **/

        unallocated: function(allocated) {
            var inversion = this.invert();
            return _.invert(_.pick(inversion, _.difference(_.keys(inversion), allocated)));
        },

        fetch: function() {
            // service_id is set from the payload when itsiContextPanelModel is initialized. 
            // Therefore, it should be available here
            var baseUrl = Splunk.util.make_url([
                            'custom',
                            'SA-ITOA',
                            'itoa_interface',
                            'nobody',
                            'service',
                            this.itsiContext.get('service_id')
                            ].join('/'));

            var xhr = $.ajax({
              url: baseUrl,
              dataType: 'json'
            });
            
            var select_kpis_that_have_owner_field = _.partial(_.filter, _, function(kpi_entry) {
                return ((_.has(kpi_entry, 'datamodel')) &&
                        (_.has(kpi_entry.datamodel, 'owner_field')) &&
                        (!_.isEmpty(kpi_entry.datamodel.owner_field)));
            });

            var map_kpi_titles_to_fieldnames = _.partial(_.map, _, function(kpi_entry) {
                    return [kpi_entry.title, kpi_entry.datamodel.owner_field];
            });

            var dfd = $.Deferred();
                
            // Compose's order is backwards. Read from the bottom
            // to the top.
            var map_kpi_properties = _.compose(
                _.object,
                map_kpi_titles_to_fieldnames,
                select_kpis_that_have_owner_field,
                _.flatten);

            var fetch_resolve = _.bind(function(response) {
                this.serviceObj = response[0];
                this.set(map_kpi_properties(this.serviceObj.kpis));
                this._kpi_title = this.itsiContext.get('kpi_title');
                dfd.resolve();
            }, this);

            $.when.call(this, xhr, this.itsiContext.fetch())
                .then(fetch_resolve, function() {
                    console.log("Failure:", arguments);
                    dfd.reject();
                });

            return dfd;
        }
    });
});
