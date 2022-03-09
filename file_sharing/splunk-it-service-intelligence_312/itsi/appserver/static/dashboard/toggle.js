require.config({
	paths: {
		'app': '../app'
	}
});
require(['splunkjs/mvc/simplexml/ready!'], function() {
	require(['jquery', 'splunkjs/ready!'], function($) {
		// The splunkjs/ready loader script will automatically instantiate all elements
		// declared in the dashboard's HTML.

		/**
		 * This function toggles the visibility and height of an element
		 * and is reusable.
		 * @param {object} button - the button
		 * @param {object} target - the target
		 */
		function toggle(button, target) {
			
			if (target.css('height') === '0px') {
				button.attr('src', '/static/app/itsi/dashboard/collapse.png');
				target.css({
					'height': 'auto',
					'overflow': 'visible'
				});
			} else {
				button.attr('src', '/static/app/itsi/dashboard/expand.png');
				target.css({
					'height': '0px',
					'overflow': 'hidden'
				});
			}
		}
			
		// Setup the click handlers for the toggle buttons
		$('#imgToggle1').click(function() {
			toggle($(this), $('#inputs'));
			toggle($(this), $('#shs_time'));
			toggle($(this), $('#shs_dist'));
			toggle($(this), $('#shs_fit'));
		});

		$('#imgToggle2').click(function() {
			toggle($(this), $('#inst'));
		});

		$('#imgToggle3').click(function() {
			toggle($(this), $('#test1'));
			toggle($(this), $('#test2'));
			toggle($(this), $('#test3'));
		});

	});
});
