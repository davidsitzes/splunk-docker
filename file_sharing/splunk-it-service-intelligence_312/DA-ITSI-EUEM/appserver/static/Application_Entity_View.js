require.config({
    paths: {
        'app': '../app',
        'currentApp': '../app/DA-ITSI-EUEM',
        'shared-components': '../app/DA-ITSI-EUEM/shared-components',
        // HACK: needed to get ui-charts-flexible to load correctly
        'ui-charts-flexible': '../app/DA-ITSI-EUEM/shared-components/ui-charts-flexible/ui-charts-flexible'
    }
});

require([
    'jquery',
    'underscore',
    'splunk.util',
    'splunkjs/mvc',
    'splunkjs/mvc/utils',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/tokenforwarder',
    'shared-components/ui-entity-info/ui-entity-info',
    'shared-components/ui-entity-info/ui-entity-info/base/SelectedTabs',
    'shared-components/ui-entity-info/ui-entity-info/base/LaneTabRelationship',
    'splunkjs/mvc/simplexml/ready!'
], function (
    $,
    _,
    splunkUtil,
    mvc,
    splunkjsUtils,
    SearchManager,
    TokenForwarder,
    EntityContextPanel,
    SelectedTabs,
    LaneTabRelationship
) {
    var TabCollection = SelectedTabs.TabCollection;
    var TabsView = SelectedTabs.TabsView;

    // Inventory search
    var inventorySearch = new SearchManager({
        'id': 'inventory-search',
        'search': mvc.tokenSafe('| savedsearch DA-ITSI-EUEM_Application_Inventory application_id="$application_id$"'),
        'earliest_time': '-24h',
        'latest_time': 'now',
        'app': 'DA-ITSI-EUEM',
        'auto_cancel': 90,
        'preview': false,
        'wait': 0,
        'runOnSubmit': true
    });

    // NOTE: Leaving out mini charts for now
    // // Mini-chart Unique Users searches
    // var uniqueUsersSearch = new SearchManager({
    //     'id': 'mini-chart-unique-users-search',
    //     'search': mvc.tokenSafe('index=* tag=euem tag=performance application_id=$application_id$ | timechart dc(uuid) as "Unique Users"'),
    //     'earliest_time': mvc.tokenSafe('$earliest$'),
    //     'latest_time': mvc.tokenSafe('$latest$'),
    //     'app': 'DA-ITSI-EUEM',
    //     'auto_cancel': 90,
    //     'preview': true,
    //     'wait': 0,
    //     'runOnSubmit': true
    // });
    //
    // // Mini-chart Crash Rate searches
    // var crashRateSearch = new SearchManager({
    //     'id': 'mini-chart-crash-rate-search',
    //     'search': mvc.tokenSafe('index=* tag=euem tag=performance application_id=$application_id$ | timechart count(_time) as Total, count(eval(failed="true")) as ErrorCount | `euem_get-rate(ErrorCount,Total)` | rename percentage as "Crash Rate" | fields + _time, "Crash Rate"'),
    //     'earliest_time': mvc.tokenSafe('$earliest$'),
    //     'latest_time': mvc.tokenSafe('$latest$'),
    //     'app': 'DA-ITSI-EUEM',
    //     'auto_cancel': 90,
    //     'preview': true,
    //     'wait': 0,
    //     'runOnSubmit': true
    // });
    //
    // // Mini-chart Network Latency searches
    // var networkLatencySearch = new SearchManager({
    //     'id': 'mini-chart-network-latency-search',
    //     'search': mvc.tokenSafe('index=* tag=euem tag=performance application_id=$application_id$ | timechart avg(latency) as "Average Network latency"'),
    //     'earliest_time': mvc.tokenSafe('$earliest$'),
    //     'latest_time': mvc.tokenSafe('$latest$'),
    //     'app': 'DA-ITSI-EUEM',
    //     'auto_cancel': 90,
    //     'preview': true,
    //     'wait': 0,
    //     'runOnSubmit': true
    // });

    // JIRA TAG-9758: This is a HACK. It shouldn't be necessary, and
    // pages that refer to this page shouldn't be passing us empty
    // 'latest' fields.
    (function() {
        var queries = _.object(_.map(window.location.search.substring(1).split('&'), function (kvp) {
            var pairs = kvp.split('=');
            return [pairs[0], pairs.slice(1).join('=')];
        }));
        // Prevent event looping.
        if ((queries.hasOwnProperty('latest')) && (queries['latest'] === '')) {
            var mapper = function(v, k) {
                return ((k === 'latest') && (v === '') ? [k, 'now'] :
                        (k === 'earliest') && (v === '') ? [k, '-4h'] :
                        [k, v]).join('=');
            };
            window.location.search = '?' + _.map(queries, mapper).join('&');
        }
    })();

    var baseView = EntityContextPanel.createItsiContextPanel({
        model: {
            entity_search_filter: [
  {
    "rule_condition": "AND",
    "rule_items": [
                  {
                    "rule_type": "matches",
                    "field": "application_id",
                    "value": "*",
                    "field_type": "alias"
                  },
                  {
                    "rule_type": "matches",
                    "field": "itsi_role",
                    "value": "end_user_application",
                    "field_type": "info"
                  },
                  {
                    "field": "package_name",
                    "field_type": "info",
                    "value": "*",
                    "rule_type": "matches"
                  },
                  {
                    "field": "app_environment",
                    "field_type": "info",
                    "value": "*",
                    "rule_type": "matches"
                  },
                  {
                    "field": "platform",
                    "field_type": "info",
                    "value": "*",
                    "rule_type": "matches"
                  },
                  {
                    "rule_type": "matches",
                    "field": "application_id",
                    "value": "*",
                    "field_type": "alias"
                  }
                ]
              }
            ],
            entity_info_search_manager: 'inventory-search',
            requested_entity_tokens: ['application_id', 'platform', 'package_name', 'app_environment', 'itsi_role'],
            context_charts: [
            //   {
            //     id: 'unique-users',
            //     title: _('Unique Users Counts').t(),
            //     subtitle: _('(Over the time range)').t(),
            //     managerid: 'mini-chart-unique-users-search',
            //     chartType: 'line',
            //     subtitleField: '_uniques',
            //     additionalChartOptions: {
            //         'charting.axisY.minimumNumber': '0',
            //         'charting.axisY.includeZero': true,
            //         'charting.seriesColors': '["0x5379AF"]'
            //     }
            // },{
            //     id: 'crash-rate',
            //     title: _('Crash Rate').t(),
            //     subtitle: _('(Over the time range)').t(),
            //     managerid: 'mini-chart-crash-rate-search',
            //     chartType: 'line',
            //     subtitleField: '_percentage',
            //     additionalChartOptions: {
            //         'charting.axisY.minimumNumber': '0',
            //         'charting.axisY.includeZero': true,
            //         'charting.seriesColors': '["0x5379AF"]'
            //     }
            // },{
            //     id: 'network-latency',
            //     title: _('Average Network Latency').t(),
            //     subtitle: _('(Over the time range)').t(),
            //     managerid: 'mini-chart-network-latency-search',
            //     chartType: 'line',
            //     subtitleField: '_duration',
            //     additionalChartOptions: {
            //         'charting.axisY.minimumNumber': '0',
            //         'charting.axisY.includeZero': true,
            //         'charting.seriesColors': '["0x5379AF"]'
            //     }
            // }
            //
            ]
        },
        el: $('#context-panel')
    });

    baseView.render();

    // Render the tabs view
    var tabsView = new TabsView({
        dash_script: 'Application_Entity_View.js',
        dash_stylesheet: 'Application_Entity_View.css',
        allowedRoles:[],
        collection: new TabCollection(null, {
            app: 'DA-ITSI-EUEM',
            owner: 'nobody'
        }),
        tabSelector: new LaneTabRelationship({}, {
            splunkService: {
                app: 'DA-ITSI-EUEM',
                owner: 'nobody'
            },
            itsiContext: baseView.model
        })
    });

});
