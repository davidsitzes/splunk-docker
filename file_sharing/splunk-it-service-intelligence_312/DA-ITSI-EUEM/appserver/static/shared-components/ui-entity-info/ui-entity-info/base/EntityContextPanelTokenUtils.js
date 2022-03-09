define(function (require, module) {
    var $ = require('jquery');
    var _ = require('underscore');
    var mvc = require('splunkjs/mvc');

    var EntityContextPanelTokenUtils = {
        /**
         * Submits the given tokens to the appropriate token models
         *
         * @param {Object} tokens
         */
        submitTokens: _.debounce(function (tokens) {
            var defaultTokenModel = mvc.Components.getInstance('default', {create: true});
            defaultTokenModel.set(tokens);
            var submittedTokenModel = mvc.Components.getInstance('submitted');
            if (submittedTokenModel) {
                submittedTokenModel.set(defaultTokenModel.toJSON());
            }

            // For URL token model, only deploy the timepicker tokens
            var urlTokenModel = mvc.Components.getInstance('url');
            if (urlTokenModel) {
                urlTokenModel.save(_.pick(tokens, ['earliest', 'latest']));
            }
        }),
    };

    return EntityContextPanelTokenUtils;
});
