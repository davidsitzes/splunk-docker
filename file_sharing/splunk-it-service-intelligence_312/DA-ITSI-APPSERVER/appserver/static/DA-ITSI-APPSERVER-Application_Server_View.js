require([
    'jquery',
    'underscore',
    'splunk.util',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function ($,
             _,
             splunkUtil,
             mvc) {

    mvc.Components.getInstance('submitted').on('change', function (event) {
        if (!(_.has(event, 'changed') && _.has(event.changed, 'control_storage'))) {
            return null;
        }

        var searchname = _.filter(mvc.Components.getInstanceNames(), function (name) {
            return name.match(/storage_volumes_most_used_search_base/);
        });
        if (searchname.length === 1) {
            var searchmanager = mvc.Components.getInstance(searchname[0]);
            var resultsModel = searchmanager.data('preview', {
                output_mode: 'json',
                offset: 0
            });
            resultsModel.on('data', function () {
                var free = 0;
                var used = 0;
                var title = '';
                _.forEach(resultsModel.data().results, function (result) {
                    if (!(_.has(result, 'Space') && _.has(result, 'Statistic'))) {
                        return;
                    }

                    if (result.Statistic.match(/^Free/i)) {
                        free = parseInt(result.Space, 10);
                        return;
                    }
                    var match = result.Statistic.match(/^Used.*?- (.*)/i);
                    if (match) {
                        used = parseInt(result.Space, 10);
                        title = match[1];
                    }
                });
                if ((free > 0) && (used > 0)) {
                    $('[data-panel-ref="storage_volumes_most_used"] .panel-head h3')
                        .text('Storage Free Space - ' + title + ' - ' + used + ' GB of ' + (used + free) + ' GB');
                }
            });
        }
        return null;
    });
});
