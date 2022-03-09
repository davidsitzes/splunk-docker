define(function(require) {

	var $ = require('jquery');
    var _ = require('underscore');
    var Backbone = require('backbone');
    var mvc = require('splunkjs/mvc');
    require('css!shared-components/ui-entity-info/ui-entity-info/base/MaintenanceModeBannerView.css');

    var MaintenanceModeBannerView = Backbone.View.extend({

    	events: {
    		'click .close-btn' : 'hide'
    	},

    	_bannerTemplate: [
    		'<div class="maintenance-mode-banner">',
    		'    <div class="info-icon">',
    		'        <i class="icon-info-circle"></i>',
    		'    </div>',
    		'    <div class="maintenance-mode-banner-text"><%= message %></div>',
    		'    <div class="close-btn">',
    		'        <i class="icon-x"></i>',
    		'    </div>',
    		'</div>'
    	].join('\n'),

    	initialize: function(options) {
			Backbone.View.prototype.initialize.apply(this, arguments);
    		this.message = options.message || _('Please enter a message for this banner.').t();
    		this.disableBanner = false;
    	},

		render: function() {
			var variables = {message: _.escape(this.message)};
			var compiledTemplate = _.template(this._bannerTemplate, variables);
			this.$el.append(compiledTemplate);
		},

		hide: function () {
			this.$('.maintenance-mode-banner').fadeOut('fast','swing');
			this.disableBanner = true;
		},

        show: function() {
			if (!this.disableBanner) {
				this.$('.maintenance-mode-banner').fadeIn('fast','swing');
				this._adjustBannerWidth();
		    }
		},

		_adjustBannerWidth: function () {
			var $textEl = this.$('.maintenance-mode-banner-text');
			if ($textEl.outerWidth() > 800) {
				var shortMessage = $textEl.text().substr(0,100).concat('...');
				$textEl.text(_.escape(shortMessage));
				$textEl.attr('title', _.escape(this.message));
				this.$('.maintenance-mode-banner').css({
					cursor: 'pointer'
				});
			}
			var textWidth = $textEl.outerWidth();
			var width = textWidth + 62;
			this.$('.maintenance-mode-banner').css({
				width: width
			});
		}
    });

    return MaintenanceModeBannerView;
});