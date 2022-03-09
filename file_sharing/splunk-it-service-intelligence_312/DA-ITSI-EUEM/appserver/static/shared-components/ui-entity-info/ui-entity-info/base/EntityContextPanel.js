/*global define */
define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    var splunk_util = require('splunk.util');
    var TimeRangeInput = require('splunkjs/mvc/timerangeview');
    var DropdownView = require('splunkjs/mvc/dropdownview');
    var SearchManager = require('splunkjs/mvc/searchmanager');
    var MiniChart = require('./MiniChart');
    var TokenUtils = require('./EntityContextPanelTokenUtils');
    var MaintenanceModeBannerView = require('./MaintenanceModeBannerView');
    require('css!./EntityContextPanel.css');
    require('css!./MaintenanceModeBannerView.css');

    var insertTimePicker = function() {
        var timePickerInsertionPriority = [
            'div.dashboard-header div.edit-menu.splunkjs-mvc-simplexml-editdashboard-menuview', // Splunk 6.4 and prior
            'div.dashboard-header span.dashboard-view-controls', // Splunk 6.5
            '#context' //default
        ];
        
        var insertionSelector = _.find(timePickerInsertionPriority, function(selector) {
            return $(selector).length > 0;
        });
        
        $(insertionSelector)
            .append('<div class="input-timerangepicker pull-right" style="padding-left: 8px;" id="entity-context-panel-time-picker"></div>');
        
        var timePicker = new TimeRangeInput({
            'id': 'entity-context-panel-time-picker',
            'searchWhenChanged': true,
            'earliest_time': '$earliest$',
            'latest_time': '$latest$',
            'el': $('#entity-context-panel-time-picker')
        }, {tokens: true}).render();

        timePicker.on('change', function (newValue) {
            TokenUtils.submitTokens({
                earliest: newValue.earliest_time,
                latest: newValue.latest_time
            });
        });
    };

    var restoreTimePickerAsNeeded = function() {
        /* In Splunk 6.5, the edit feature adds the banner object and cycles it during
         * edit/view.  Earlier versions are less destructive and leave the TimePicker in
         * place, so restoring it isn't necessary.
         */
        var banners = $('header[role="banner"]');
        if (banners.length === 0) {
            return;
        }
        
        /* Defer places the operation at the end of the stack of processes the JS engine
         * will call, ensuring that this operation happens after the view restoration is
         * complete.
         */
        var headerObserver = new window.MutationObserver(function(mutations) {
            _.defer(function() {
                if ($('header .edit-cancel').length === 0) {
                    var oldTimepicker = mvc.Components.getInstance('entity-context-panel-time-picker');
                    if (oldTimepicker) {
                        oldTimepicker.remove();
                        mvc.Components.revokeInstance('entity-context-panel-time-picker');
                    }
                    insertTimePicker();
                }
            });
        });

        headerObserver.observe(banners.get(0), {
            attributes: false, characterData: false, childList: true
        });
    };


    var EntityContextPanel = Backbone.View.extend({
        /* Describes the endpoint to get all entities and determine whether they are in maintenance mode */
        MAINTENANCE_CALENDAR_ENDPOINT: splunk_util.make_url(
            '/custom/SA-ITOA/maintenance_services_interface/nobody/maintenance_calendar'),
        events: {
            'click #open-inventory-modal' : function(e) {
                $('#inventory-fields-modal').modal('show');
            }
        },
        /**
         * Initialize the view
         *
         * @param {Object} options
         * @public
         */
        initialize: function (options) {
            Backbone.View.prototype.initialize.apply(this, arguments);
            this.contextChartInfo = this.model.get('context_charts');

            // Generate IDs for each chart element
            _.each(this.contextChartInfo, function (chartInfo) {
                chartInfo.el = 'entity-context-chart-' + chartInfo.id;
            }, this);

            this.miniCharts = [];

            // Hook up all model listeners
            this.listenTo(this.model, {
                'change:entities': this._updateEntityList,
                'change:current_entity_info': this._updateEntityInfoView,
                'change:context_content_title': this._updateContextView
            }, this);

            /* Event handler registers only after search completes,
             * this guarantees that this.entities gets populated no matter what
             */
            this._updateEntityList();

            if (_.isEmpty(this.model.get('current_entity'))) {
                this.currentEntityTitle = _('Select an entity').t();
            } else {
                this.currentEntityTitle = this.model.get('current_entity').title;
            }
        },

        /**
          * Gets the current entity's key
          *
        **/
        _getCurrentEntityKey: function() {
            return (this.model.get('current_entity').id || this.model.get('current_entity')._key);
        },

        /**
          * Gets the url for entity detail page based on the selected entity
          *
        **/
        _getEntityDetailUrl: function() {
            /* On initial drilldown load, current_entity gets picked up from payload with entity key
             * stored in a field called "id".  On entity change, the entity key is picked up from the
             * list of entities that were returned from the search, and this field is now stored in
             * "_key".
             */
            return (splunk_util.make_url(['app', 'itsi', 'entity_detail'].join('/')) +
                    '?entity_key=' + this._getCurrentEntityKey());
        },

        /**
         * Render the timepicker, context views and the mini charts
         *
         * @public
         */
        render: function () {
            // Fetch from model for model specific context info
            this.model.fetch().done(_.bind(function () {
                var context_title = '';
                if (!this.model.get('is_from_entity_details')){
                    context_title = this.model.get('context_content_title');
                }
                this.$el.html(this._template({
                    context_title: context_title,
                    context_value: this.model.get('context_content_value'),
                    context_url: this.model.get('context_content_link'),
                    context_chart_info: this.contextChartInfo
                }));
                _.each(this.contextChartInfo, function (chart) {
                    var miniChart = new MiniChart({
                        id: chart.id,
                        managerid: chart.managerid,
                        title: chart.title,
                        chartType: chart.chartType,
                        subtitleField: chart.subtitleField,
                        additionalChartOptions: chart.additionalChartOptions,
                        el: $('#' + chart.el)
                    });

                    this.miniCharts.push(miniChart);
                }, this);

                /* HACK:
                 * As per the UI requirements, this appends the timepicker object to the
                 * top-right corner along with the edit dropdown and "More info" dropdown
                 * Since the classes and structure of the page has changed across
                 * releases, best option is to try each one until we find a suitable
                 * location. The last default option will always work.
                 */
                insertTimePicker();

                /* SECONDARY HACK 
                 * Restore the timePicker whenever the edit header indicates it is no
                 * longer in EDIT mode.  This is safe as previous timePickers stop
                 * eventing, and the current one is just putting time ranges onto the
                 * token bus.
                 */
                restoreTimePickerAsNeeded();

                var entityPicker = new DropdownView({
                    'id': 'entity-context-panel-entity-dropdown',
                    'choices': this.entities,
                    'labelField': 'title',
                    'valueField': 'title',
                    'showClearButton': false,
                    'default': this.currentEntityTitle,
                    'el': $('#entity-context-panel-entity-picker')
                }).render();

                entityPicker.on('change', function (evt) {
                    if (evt !== undefined) {
                        this.currentEntityTitle = evt;
                        var entity = _.find(this.entities, function(item) {
                            return item.value === evt;
                        });

                        // Update the model
                        this.model.set('current_entity', _.find(this.model.get('entities'), function(item) {
                            return item.title === evt;
                        }));

                        var tokens = _.pick(entity.data, this.model.get('requested_entity_tokens'));
                        TokenUtils.submitTokens(tokens);
                        this._clearEntityInfoView();
                    }
                }, this);
            }, this));
        },

        /**
         * Updates the entity list for the dropdown view
         *
         * @private
         */
        _updateEntityList: function() {
            this.entities = _.map(this.model.get('entities'), function(item) {
                var rowItem = {};
                rowItem['label'] = item['title'];
                rowItem['value'] = item['title'];
                rowItem['data'] = item;
                return rowItem;
            });

            var dropdown = mvc.Components.get('entity-context-panel-entity-dropdown');
            if (dropdown) {
                dropdown.settings.set('choices', this.entities);
            }
        },

        /**
         * Updates the context view when the base page model changes
         *
         * @private
         */
        _updateContextView: function () {
            $('#entity-context-panel-contextLink').attr('href', this.model.get('context_content_link'));
            $('#entity-context-panel-contextLink').text(this.model.get('context_content_value'));
        },

        /**
         * Does a lookup of the entity given its key against the REST endpoint
         * containing all the entities that have a maintenance window, and determines
         * whether given the current time, the entity is still in a maintenance window
         *
         * @private
         *
         * @params {object} maintenance_calendars
        **/
        _isEntityInMaintenanceWindow: function(maintenance_calendars) {
            var current_entity_key = this._getCurrentEntityKey();
            // getTime() returns value in milliseconds, so needs to be adjusted to seconds
            var current_time = new Date().getTime() / 1000;
            return _.some(maintenance_calendars, function(calendar) {
                return _.some(calendar['objects'], function(element) {
                    return element['object_type'] === 'entity' && element['_key'] === current_entity_key &&
                        current_time > calendar['start_time'] && current_time < calendar['end_time'];
                });
            });
        },

        /**
          * Clears all banners inside the maintenance-mode container.  This will be called when
          * a new banner gets rendered for maintenance mode, or if the entity was switched from
          * one that was in maintenance mode to one that isn't.
        **/
        _clearMaintenanceWindowBanner: function() {
            $(".maintenance-mode").empty();
        },

        /**
         * Renders the maintenance window banner if the selected entity in the dropdown
         * is in maintenance mode
         *
         * @private
        **/
        _renderMaintenanceWindowBanner: function() {
            // Clear any banners that were previously there, that were closed.
            this._clearMaintenanceWindowBanner();

            var maintenanceBanner = new MaintenanceModeBannerView({
                el : $('.maintenance-mode'),
                message: 'This Entity is currently in maintenance, data on this page may not be accurate'
            });
            maintenanceBanner.render();
            maintenanceBanner.show();
        },

        /**
         * Updates the entity info view when the model's entity info get populated
         *
         * @private
         */
        _updateEntityInfoView: function () {
            // Clears all of the inventory fields that had been displayed here
            $('.inventory-field').remove();

            $('#entity-context-panel-entity-info').append(this._entityInfoTemplate({
                entity_title: this.currentEntityTitle,
                data: this.model.get('current_entity_info'),
                entity_detail_url: this._getEntityDetailUrl()
            })).triggerHandler("entity-fields-change-event");

            // Append the modal view to context panel with all fields described
            $('#inventory-fields-modal').html(this._showAllInventoryFieldsModal({
                data: this.model.get('current_entity_info'),
                entity_detail_url: this._getEntityDetailUrl()
            })).triggerHandler("entity-fields-change-event");

            // Adapted from @ksternberg's UI logic on Entity Detail page
            _.defer(_.bind(function() {
                $('#show-more-fields').remove();
                var MAX_LOCATION = $('#minicharts').position().left;
                var extra = 0;
                _.each($('.wrapped-item.inventory-field'), function(item) {
                    if($(item).position().left + $(item).width() > MAX_LOCATION) {
                        $(item).remove();
                        extra++;
                    }
                });

                if (extra > 0) {
                    $('#entity-context-panel-entity-info').append(this._showMoreFieldsTemplate({
                        extra: extra
                    }));

                    // Make sure the "Show X more" modal link is in same column as final field shown
                     if ($('#show-more-fields').position().left !== $('.wrapped-item.inventory-field').last().position().left) {
                        $('.wrapped-item.inventory-field').last().remove();
                        $('#show-more-fields > #open-inventory-modal > .scanning').text('Show ' + (extra + 1) + ' more');
                    }
                }
            }, this));

            /* Fetches the existing maintenance windows from the REST endpoint, and determines
             * whether the selected entity is in one of those windows
             */
            $.get(this.MAINTENANCE_CALENDAR_ENDPOINT)
                .done(_.bind(function(maintenance_calendars) {
                    if (this._isEntityInMaintenanceWindow(maintenance_calendars)) {
                        this._renderMaintenanceWindowBanner();
                    }
                    else {
                        this._clearMaintenanceWindowBanner();
                    }
            }, this))
                .fail(function() {
                    console.error('Failed to retrieve maintenance calendars.');
            });
        },

        _clearEntityInfoView: function() {
            // This discernment is necessary because there's an 'if' in the
            // template.
            var maybeContext = $('#entity-context-panel-contextLink');
            var entityPicker = $('#entity-context-panel-entity-picker');
            var lastUnchanging = (maybeContext.length ? maybeContext : entityPicker)
                    .closest('label');
            lastUnchanging.nextAll('label.wrapped-item').remove();
        },

        _template: _.template([
            '<div id="context">',
            '    <div id="entity-context-panel-entity-info" class="wrapped-layout">',
            '        <label class="wrapped-item">',
            '            <span>' + _('Entity').t() + '</span>',
            '            <div class="input-dropdown scanning" id="entity-context-panel-entity-picker" style="margin-top: -9px; height: 0px;"></div>',
            '        </label>',
            '        <% if (context_title) { %>',
            '        <label class="wrapped-item">',
            '            <span><%- context_title %></span>',
            '            <span>',
            '                <a id=entity-context-panel-contextLink href="<%- context_url%>"><%- context_value%></a>',
            '            </span>',
            '        </label>',
            '        <% } %>',
            '    </div>',
            '    <div class="modal fade" id="inventory-fields-modal" tabindex="-1" role="dialog"></div>',
            '    <div id="minicharts">',
            '        <% _.each(context_chart_info, function(chartInfo) { %>',
            '            <div id="<%= chartInfo.el%>"></div>',
            '        <% }); %>',
            '    </div>',
            '</div>',
            '<div class="maintenance-mode"></div>'].join('\n')),
        _showMoreFieldsTemplate: _.template([
            '<label class="wrapped-item" id="show-more-fields">',
            '    <a id="open-inventory-modal" href="#">',
            '        <span class="scanning">' + _('Show ').t() + '<%= extra%>' + _(' more').t() + '</span>',
            '    </a>',
            '</label>'
        ].join('\n')),
        _entityInfoTemplate: _.template([
            '<% if(data) { %>',
            '    <% _.each(data, function(value, key) { %>',
            '        <label class="wrapped-item inventory-field">',
            '            <span><%= key%></span>',
            '            <span><%= value ? value : "Not Found"%></span>',
            '        </label>',
            '    <% }); %>',
            '    <label class="wrapped-item inventory-field">',
            '        <a href="<%= entity_detail_url%>" target="_blank" class="icon-external icon-no-underline">',
            '            <span class="scanning">' + _('View Entity Health').t() + '</span>',
            '        </a>',
            '    </label>',
            '<% } else { %>',
            '    <label>' + _('No data available.').t() + '</label>',
            '<% } %>'].join('\n')),
        _showAllInventoryFieldsModal: _.template([
            '<div class="modal-dialog modal-sm">',
            '    <div class="modal-content">',
            '        <div class="modal-header">',
            '            <button type="button" class="close" data-dismiss="modal">&times;</button>',
            '            <h4 class="modal-title">' + _('All Inventory Fields').t() + '</h4>',
            '        </div>',
            '        <div class="modal-body scrollable">',
            '            <% _.each(data, function(value, field) { %>',
            '                <label><%= field%>: <%= value%></label>',
            '            <% }); %>',
            '            <label>',
            '                <a href="<%= entity_detail_url%>" target="_blank" class="icon-external icon-no-underline">',
            '                    <span class="scanning">' + _('View Entity Health').t() + '</span>',
            '                </a>',
            '            </label>',
            '        </div>',
            '        <div class="modal-footer">',
            '            <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>',
            '        </div>',
            '    </div>',
            '</div>'
        ].join('\n'))
    });

    return EntityContextPanel;
});
