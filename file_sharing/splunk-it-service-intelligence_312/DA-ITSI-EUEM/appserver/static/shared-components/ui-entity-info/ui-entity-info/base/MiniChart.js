define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    var SimpleSplunkView = require('splunkjs/mvc/simplesplunkview');

    // Supported views
    var ChartView = require('splunkjs/mvc/chartview');
    // var FlexCharts = require('shared-components/ui-charts-flexible/ui-charts-flexible');

    /**
     * The minichart is a view that contains the following:
     * title - bold text for the name of mini chat
     * subtitle - text, usually derived from a search, that acts as non-visual representation
     *     The value is specified as a field that's uniformly available in all events
     * chart - the chart that is a visual representation
     */
    var MiniChart = SimpleSplunkView.extend({
        moduleId: module.id,
        className: 'minichart-viz',
        outputMode: 'json',
        options: {
            managerid: null,
            data: 'preview',
            title: '',
            chartType: '',
            subtitleField: '',
            additionalChartOptions: {}
        },

        events: {
            'click a': function (e) {
                // Disable drilldowns from chart
                e.preventDefault();
            }
        },

        defaultChartOptions: {
            'markerGauge': {
                'charting.chart': 'markerGauge',
                'resizable': false,
                'charting.legend.placement': 'none',
                'charting.chart.style': 'minimal',
                'charting.chart.showValue': false,
                'charting.chart.orientation': 'x',
                'height': 105
            },
            'column': {
                'charting.chart': 'column',
                'resizable': false,
                'charting.legend.placement': 'none',
                'height': 105,
                'charting.axisTitleX.visibility': 'collapsed',
                'charting.axisTitleY.visibility': 'collapsed',
                'charting.axisTitleY2.visibility': 'collapsed',
                'charting.axisLabelsX.majorLabelVisibility': 'hide',
                'charting.chart.showDataLabels': 'none'
            },
            'line': {
                'charting.chart': 'line',
                'resizable': false,
                'charting.legend.placement': 'none',
                'height': 105,
                'charting.axisTitleX.visibility': 'collapsed',
                'charting.axisTitleY.visibility': 'collapsed',
                'charting.axisTitleY2.visibility': 'collapsed',
                'charting.axisLabelsX.majorLabelVisibility': 'hide',
                'charting.chart.showDataLabels': 'none'
            },
            'area': {
                'charting.chart': 'area',
                'resizable': false,
                'charting.legend.placement': 'none',
                'height': 105,
                'charting.axisTitleX.visibility': 'collapsed',
                'charting.axisTitleY.visibility': 'collapsed',
                'charting.axisTitleY2.visibility': 'collapsed',
                'charting.axisLabelsX.majorLabelVisibility': 'hide',
                'charting.chart.showDataLabels': 'none'
            }
        },

        defaultStyles: {
            'markerGauge': 'width: 125px',
            'column': 'width: 220px',
            'line': 'width: 220px',
            'area': 'width: 220px'
        },

        /**
         * Initialize the view
         *
         * @param {Object} options
         * @public
         */
        initialize: function (options) {
            SimpleSplunkView.prototype.initialize.apply(this, arguments);
            this.vizId = ['mini-chart', this.settings.get('chartType'), this.id].join('-');
        },

        /**
         * Creates the mini chart
         *
         * @public
         */
        createView: function () {
            if (!this.defaultChartOptions[this.settings.get('chartType')]) {
                this.$el.html('Invalid chart type');
                return null;
            }

            this.$el.html(this._template({
                chart_title: this.settings.get('title'),
                viz_id: this.vizId,
            }));

            // Override default options with the additional options
            var finalOptions = _.extend({},
                this.defaultChartOptions[this.settings.get('chartType')],
                this.settings.get('additionalChartOptions'),
                {
                    'id': this.vizId,
                    'managerid': this.settings.get('managerid'),
                    'el': $('#' + this.vizId)
                });

            return new ChartView(finalOptions, {tokens: true, tokenNamespace: 'submitted', replace: true}).render();
        },

        /**
         * Updates the view when data arrives
         *
         * @param {Object} viz
         * @param {Object} data
         * @public
         */
        updateView: function (viz, data) {
            var row = _.first(data);
            if (!_.isEmpty(this.settings.get('subtitleField')) && !_.isEmpty(row) && !_.isEmpty(row[this.settings.get('subtitleField')])) {
                $('#' + this.vizId + '-subtitle').text(row[this.settings.get('subtitleField')]);
            } else {
                $('#' + this.vizId + '-subtitle').text('N/A');
            }

            return true;
        },

        // This template does not include the container div since that's supplied by
        // the parent
        _template: _.template([
            '<label><b><%- chart_title%></b></label>',
            '<label id="<%- viz_id%>-subtitle"></label>',
            '<div id="<%- viz_id%>" style="background-color: rgba(0,0,0,0)">',
            '</div>'].join('\n'))
    });

    return MiniChart;
});
