define(function (require) {
    /**
     * Factory class to generate entity context panels
     * @exports EntityContextPanelFactory
     */
    var EntityContextPanelFactory;
    var $ = require('jquery');
    var _ = require('underscore');
    var EntityContextPanelModel = require('./base/EntityContextPanelModel');
    var EntityContextPanel = require('./base/EntityContextPanel');
    var ItsiContextPanelModel = require('./itsi/ItsiContextPanelModel');

    EntityContextPanelFactory = {
        /**
         * Creates a context panel for generic usage<br>
         * <br>
         * Supported attributes:<br>
         * - entity_search_manager: Splunk search to get a table of entities and attributes<br>
         * - requested_entity_tokens: for a selected entity, specifies which tokens to populate on the page<br>
         * - entity_info_search_manager: Splunk search to retrieved information about a particular entity<br>
         * &nbsp&nbsp- Should ideally use the tokens specified in the requested_entity_tokens attribute<br>
         * - context_content_title: the context section title<br>
         * - context_content_value: the value below the section title<br>
         * - context_content_link: a link (if applicable) to the appropriate context<br>
         * - context_charts: an array of context chart attributes. Array attributes:<br>
         * &nbsp&nbsp- id: the chart ID, must be unique<br>
         * &nbsp&nbsp- title: the title for the chart<br>
         * &nbsp&nbsp- managerid: the Splunk search manager to populate the chart<br>
         * &nbsp&nbsp- chartType: the kind of chart (anything supported by HighCharts)<br>
         * &nbsp&nbsp- subtitleField: the field in the search that acts as the subtitle<br>
         * &nbsp&nbsp- additionalChartOptions: any additional chart options or overrides other than the default<br>
         * - el: jQuery selector where the view should be rendered<br>
         *
         * @public
         */
        createGenericContextPanel: function (options) {
            if (!options.model) {
                throw new Error('model is a required attribute');
            }

            options.model = new EntityContextPanelModel(options.model);
            return this.createContextPanelFromModel(options);
        },

        /**
         * Creates a context panel for ITSI-specific scenario.<br>
         * Supports all of the same attributes as the generic context panel.<br>
         * The panel assumes that the page contains the tokens described in the README<br>
         * <br>
         * Additional required attributes:<br>
         *  - entity_search_filter: Splunk search snippet to filter entities<br>
         * @public
         */
        createItsiContextPanel: function (options) {
            if (!options.model) {
                throw new Error('model is a required attribute');
            }

            options.model = new ItsiContextPanelModel(options.model);
            return this.createContextPanelFromModel(options);
        },

        /**
         * Create a context panel from a custom model
         *
         * @public
         */
        createContextPanelFromModel: function (options) {
            if (!options.model instanceof EntityContextPanel) {
                throw new Error('Model attribute needs to be of type "EntityContextPanel"');
            }

            return new EntityContextPanel(options);
        },

        /**
         * The base model that can be used for creating custom extensions
         */
        BaseModel: EntityContextPanelModel,

        /**
         * The base ITSI model that can be used for creating custom extensions
         */
        ItsiModel: ItsiContextPanelModel

    };

    return EntityContextPanelFactory;
});