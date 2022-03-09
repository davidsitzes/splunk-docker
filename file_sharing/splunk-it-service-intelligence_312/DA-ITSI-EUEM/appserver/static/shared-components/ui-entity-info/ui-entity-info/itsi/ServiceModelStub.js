define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');

    var ServiceModelStub = Backbone.Model.extend({
        idAttribute: '_key'
    });

    return ServiceModelStub;
});