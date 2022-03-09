/*global define */
define(function(require) {
    var _ = require('underscore');
    var $ = require('jquery');
    var Backbone = require('backbone');
    var TabCollection = require('./Tabs');
    var TabsView = require('./TabsView');

    var Tab = TabCollection.prototype.model;

    var SelectedTab = Tab.extend({
        defaults: _.extend({}, Tab.prototype.defaults, {'activation_rule': ''}),
        parsedFields: Tab.prototype.parsedFields.concat(['activation_rule']),
        
        /**
          *  Given a datamodel field, asserts whether or not this Tab would be the active tab.
         **/

        isActive: function(fieldName) {
            if (!this.get('activation_rule')) {
                return false;
            }
            var trim = function(s) { return s.trim(); };
            var rule = _.map(this.get('activation_rule').split(','), trim);
            return _.contains(rule, fieldName);
        }
    });

    var SelectedTabCollection = TabCollection.extend({
        model: SelectedTab,

        /** 
          * Given a datamodel fieldname, returns the first tab for
          * which an activation rule matches.
         **/

        getActive: function(field_name) {
            return _.first(this.filter(function(model) { return model.isActive(field_name); }));
        },

        /**
          * Returns a list of all the current activation rules 
          * associated with this tab collection.
         **/

        getAllActivationRules: function() {
            var clean_allocated = _.compose(
                _.partial(_.filter, _, function(a) { return a !== ""; }),
                _.partial(_.map, _, function(a) { return a.trim(); }),
                _.flatten,
                _.partial(_.map, _, function(s) { return s.split(','); })
            );
            return clean_allocated(this.pluck('activation_rule'));
        }
    });

    var SelectedTabsView = TabsView.extend({
        
        initialize: function(options) {
            Backbone.View.prototype.initialize.apply(this, options);
            this.collection = options.collection;
            this.tabSelector = options.tabSelector;

            var promises = [this.collection.fetch()];
            if (this.tabSelector) {
                promises.push(this.tabSelector.fetch());
            }

            $.when.apply($, promises)
                .done(_.bind(this.render, this))
                .fail(function() {
                    console.error("Failed to load tabs from conf file.");
                });
        },

        assignActiveTab: function() {
            var chosenTab = null, activeTab = null;
            if (this.tabSelector) {
                chosenTab = this.collection.getActive(this.tabSelector.choice());
                if (chosenTab && chosenTab.has('control_token')) {
                    activeTab = $('#tabs-container > li > a[data-token=' + chosenTab.get('control_token') + ']').closest('li');
                }
            }

            if ((!activeTab) || (activeTab.length === 0)) {
                activeTab = $('#tabs-container > li:first');
            }

            activeTab.addClass("active");
            return this;
        }
    });

    return {TabsView: SelectedTabsView, TabCollection: SelectedTabCollection};
});
        
        
