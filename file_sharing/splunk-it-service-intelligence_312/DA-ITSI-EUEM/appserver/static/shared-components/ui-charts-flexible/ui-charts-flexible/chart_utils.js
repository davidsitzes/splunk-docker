/**
 * default options for charts, can be overriden
 * @module  ui-charts-flexible/chart_utils
 */
define([
    "underscore",
    "highcharts"
], function (
    _,
    Highcharts
) {

  // naive pad function that format hours/minutes to 2-dig format
  var pad = function (num) {
    return ('0' + num).slice(-2);
  };

  // abbreviate numbers for yAxis formatter
  var abbreviateNumber = function (value) {
    var newValue = value;
    if (value >= 1000) {
        var suffixes = ["", "k", "m", "b","t"];
        var suffixNum = Math.floor( (""+value).length/3 );
        var shortValue = '';
        for (var precision = 2; precision >= 1; precision--) {
            shortValue = parseFloat( (suffixNum !== 0 ? (value / Math.pow(1000,suffixNum) ) : value).toPrecision(precision));
            var dotLessShortValue = (shortValue + '').replace(/[^a-zA-Z 0-9]+/g,'');
            if (dotLessShortValue.length <= 2) { break; }
        }
        if (shortValue % 1 !== 0)  shortNum = shortValue.toFixed(1);
        newValue = shortValue+suffixes[suffixNum];
    }
    return newValue;
  };

  // Duration formatter in order to avoid using moment.js
  var durationFormatter = function (value, format) {
    var date = new Date(value);
    var time = pad(date.getUTCMinutes()) +":"+
               pad(date.getUTCSeconds());

    if (value > 3600000) {
      time = pad(date.getUTCHours()) + ":" + time;
    }

    return time;
  };

  var defaultXAxisFormatter = function(view) { // Properties for this: axis, chart, isFirst, isLast
    return Highcharts.dateFormat(view.dateFormat, this.value);
  };

  var defaultYAxisFormatter = function(view) { // Properties for this: axis, chart, isFirst, isLast
    if (view.options.durationResult) {
      return durationFormatter(this.value);
    } else {
      return abbreviateNumber(this.value);
    }
  };

  var defaultTooltipPointFormatter = function(view) { // Properties for this: point
    if (view.options.durationResult) {
      return this.point.point.label;
    } else {
      return this.point.y;
    }
  };

  var defaultTooltipKeyFormatter = function(view) { // Properties for this: x
    return Highcharts.dateFormat(view.dateFormat, this.x);
  };

  var defaultTooltipFormatter = function(view) {    // Properties for this: points, x
    var x = this.x, y,
    tooltip = view.options.chartOptions.tooltip.keyFormatter.call({x: this.x});

    _.chain(this.points)
    .sortBy(function(point){ return -point.y; })
    .each(function(point) {
      y = view.options.chartOptions.tooltip.pointFormatter.call({point: point});
      tooltip += '<br/><b style="color: ' + point.series.color + '">' + point.series.name + '</b>' + ': ' + y;
    });

    return tooltip;
  };

  var defaultChartOptions = {
    chart: {
      type: 'areaspline',
      marginTop: 10,
      // zoomType: 'xy',
      // resetZoomButton: {
      //   position: {
      //       align: 'left',
      //       x: 0,
      //       y: 0
      //   }
      // },
      panning: true,
      animation: true,
      panKey: 'shift'
    },
    xAxis: {
      lineColor: '#eeeeee',
      tickColor: '#eeeeee',
      type: "datetime",
      labels: {
        step:2,
        align: 'center',
        y:20,
        style:{
          fontSize:'10px',
          color:'#777777'
        },
        formatter: defaultXAxisFormatter
      }
    },
    colors: Highcharts.getOptions().colors,
    yAxis: {
      min: 0,
      title: false,
      gridLineColor: '#eeeeee',
      // endOnTick: false,
      maxPadding: 0.2,
      labels: {
        style:{
          color:'#777777'
        },
        formatter: defaultYAxisFormatter
      }
    },
    tooltip: {
      enabled: true,
      borderWidth: 0,
      backgroundColor:"rgba(0,0,0, 0.9)",
      borderRadius: 0,
      shared: true,
      shadow: false,
      style:{
        color:'#ffffff',
        font: '11px Roboto, Helvetica-Neue, Helvetica, Arial, sans-serif'
      },
      pointFormatter: defaultTooltipPointFormatter,
      keyFormatter: defaultTooltipKeyFormatter,
      formatter: defaultTooltipFormatter
    },
    plotOptions: {
      series: {
        fillOpacity: 0.3,
        marker: {
          symbol:'circle',
          enabled: true,
          hover:{
            enabled: true
          }
        }
      }
    },
    series: [],
    legend: {
      enabled: false
    },
    exporting: {
      enabled: false
    },
    labels: false,
    credits: false,
    title: {text: null}
  };


  return /** @alias module:ui-charts-flexible/chart_utils */ {
    /** abbreviation for numbers */
    abbreviateNumber: abbreviateNumber,
    /** duration format */
    durationFormatter: durationFormatter,
    /** default x axis format */
    defaultXAxisFormatter: defaultXAxisFormatter,
    /** default y axis format */
    defaultYAxisFormatter: defaultYAxisFormatter,
    /** tooltip point format */
    defaultTooltipPointFormatter: defaultTooltipPointFormatter,
    /** tooltip key format */
    defaultTooltipKeyFormatter: defaultTooltipKeyFormatter,
    /** tooltip format */
    defaultTooltipFormatter: defaultTooltipFormatter,
    /** other options */
    defaultChartOptions: defaultChartOptions
  };
});

