define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var splunkUtil = require('splunk.util');
    var ServiceModelStub = require('./ServiceModelStub');

    var ServiceModelCollectionStub = Backbone.Collection.extend({
        model: ServiceModelStub,

        setServiceFilter: function (serviceId) {
            this.url = splunkUtil.make_url([
                'custom',
                'SA-ITOA',
                'itoa_interface',
                'nobody',
                'service',
                serviceId
            ].join('/'));
        }
    });

    return ServiceModelCollectionStub;
});