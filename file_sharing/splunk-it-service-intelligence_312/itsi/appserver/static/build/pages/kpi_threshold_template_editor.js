webpackJsonp([24],{0:function(e,t,i){var l,o;i.p=function(){function e(){for(var e,i,l="",o=0,s=arguments.length;o<s;o++)e=arguments[o].toString(),i=e.length,i>1&&"/"==e.charAt(i-1)&&(e=e.substring(0,i-1)),l+="/"!=e.charAt(0)?"/"+e:e;if("/"!=l){var r=l.split("/"),n=r[1];if("static"==n||"modules"==n){var a=l.substring(n.length+2,l.length);l="/"+n,window.$C.BUILD_NUMBER&&(l+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(l+="."+window.$C.BUILD_PUSH_NUMBER),"app"==r[2]&&(l+=":"+t("APP_BUILD",0)),l+="/"+a}}var h=t("MRSPARKLE_ROOT_PATH","/"),d=t("DJANGO_ROOT_PATH",""),p=t("LOCALE","en-US"),c="";return c=d&&l.substring(0,d.length)===d?l.replace(d,d+"/"+p.toLowerCase()):"/"+p+l,""==h||"/"==h?c:h+c}function t(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return e("/static/app/itsi/build/pages")+"/"}(),l=[i("require/underscore"),i("shim/jquery"),i(4),i(129),i(955),i(473),i(2565),i(2751)],o=function(e,t,i,l,o,s,r,n){var a=i(e("KPI Threshold Template").t());t("#app-main-layout").text(e("Loading...").t());var h=function(t){var i=new s({errorMessage:e("Could not fetch threshold template.").t(),htmlResponse:t});i.show()},d=function(){var i=function(i,l){if(!e.isArray(l)||!l[0].hasOwnProperty("is_capable"))throw h(""),"Could not fetch capabilities. is_capable schema may have changed";var s=i[0]._immutable,r=l[0].is_capable,a=!r;s&&(a=!0),n.loadView(a,function(e){t("#app-main-layout").html("");var i=new o({model:d,ContentView:e,readOnly:a});t("#app-main-layout").append(i.render().$el)})},s=a.defaultTokenModel.get("templateID");if(!s)throw"URL should have templateID parameter";var d=new r({_key:s}),p=t.when(d.fetch(),l.isUserCapable("kpi_threshold_template","write"));p.done(i).fail(h)};l.setupViewFromDefaultTokenModel(a,d,"templateID")}.apply(t,l),!(void 0!==o&&(e.exports=o))},2751:function(e,t,i){var l,o;l=[i(2752),i(2753)],o=function(e,t){var i=function(i,l){if(!l)throw"KpiThresholdTemplateEditorView expects a callback function";l(i?e:t)};return{loadView:i}}.apply(t,l),!(void 0!==o&&(e.exports=o))},2752:function(e,t,i){var l,o;l=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i("views/shared/controls/ControlGroup"),i(2495),i(237),i(2622),i(2753),i(2757),i(2758)],o=function(e,t,i,l,o,s,r,n,a){var h=n.extend({KpiTimeVariantThresholdingView:r,template:e.template(a,null,{variable:"vars"}),setupThresholdingControls:function(){this.childViews=this.childViews||{},this.childViews.securityGroupControl=new l({label:e("Team").t(),controlType:"Label",controlOptions:{defaultValue:s.GLOBAL_SECURITY_GROUP_TITLE}}),this.childViews.enableAdaptiveThresholdControl=new l({label:e("Enable Adaptive Thresholding").t(),controlType:"Label",controlOptions:{defaultValue:this._configSettingsModel.get("adaptive_thresholds_is_enabled")?e("Yes").t():e("No").t()}});var t=e.findWhere(o.KPI.kpiTimePresetsList,{value:this._configSettingsModel.get("adaptive_thresholding_training_window")}).label;this.childViews.kpiTrainingEarliestTimePicker=new l({label:e("Training Window").t(),controlType:"Label",controlOptions:{defaultValue:t}}),this.childViews.aggregateEntityControl=new l({label:e("Thresholding type").t(),controlType:"Label",controlOptions:{defaultValue:this._configSettingsModel.get("threshold_config_is_aggregate")?e("Aggregate Thresholds").t():e("Per Entity Thresholds").t()}})},renderThresholdingControls:function(){this.$(".threshold-template-info").html(""),this.$(".threshold-template-info").append(this.childViews.securityGroupControl.render().$el),this.$(".threshold-template-info").append(this.childViews.enableAdaptiveThresholdControl.render().$el),this.$(".threshold-template-info").append(this.childViews.kpiTrainingEarliestTimePicker.render().$el),this.$(".threshold-template-info").append(this.childViews.aggregateEntityControl.render().$el)}});return h}.apply(t,l),!(void 0!==o&&(e.exports=o))},2753:function(e,t,i){var l,o;l=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i("views/shared/controls/ControlGroup"),i(148),i(231),i(232),i(239),i(2495),i(237),i(2565),i(2567),i(1236),i(2754),i("shim/bootstrap.tooltip"),i(2755)],o=function(e,t,i,l,o,s,r,n,a,h,d,p,c,v){var g=i.View.extend({KpiTimeVariantThresholdingView:p,template:e.template(v,null,{variable:"vars"}),initialize:function(t){if(t=t||{},!t.model)throw"Must provide threshold template model";this.thresholdTemplateModel=t.model,this.childViews={},this._configSettingsModel=new i.Model({threshold_config_is_aggregate:!0,adaptive_thresholds_is_enabled:this.thresholdTemplateModel.get("adaptive_thresholds_is_enabled"),adaptive_thresholding_training_window:this.thresholdTemplateModel.get("adaptive_thresholding_training_window")}),this.childViews.aggregateEntityConfigureControl=new l({controlType:"SyntheticRadio",controlOptions:{modelAttribute:"threshold_config_is_aggregate",model:this._configSettingsModel,items:[{value:!0,label:e("Aggregate Thresholds").t()},{value:!1,label:e("Per Entity Thresholds").t()}],toggleClassName:"btn",popdownOptions:{attachDialogTo:"body"}}}),this.setupThresholdingControls(),this._serviceModel=null,this._kpiModel=null,this.previewModel=new i.Model({serviceId:"",kpiId:""}),this.listenTo(this.previewModel,"change:serviceId",this._onSelectService),this.listenTo(this.previewModel,"change:kpiId",this._onSelectKPI),this.listenTo(this._configSettingsModel,"change:adaptive_thresholds_is_enabled",function(){this.thresholdTemplateModel.set("adaptive_thresholds_is_enabled",this._configSettingsModel.get("adaptive_thresholds_is_enabled"))}.bind(this)),this.listenTo(this._configSettingsModel,"change:adaptive_thresholding_training_window",function(){this.thresholdTemplateModel.set("adaptive_thresholding_training_window",this._configSettingsModel.get("adaptive_thresholding_training_window"))}.bind(this)),this.listenTo(this.thresholdTemplateModel,"change:adaptive_thresholds_is_enabled",this.toggleTrainingWindowControl),i.View.prototype.initialize.call(this,t)},setupThresholdingControls:function(){this.childViews.securityGroupControl=new l({label:e("Team:").t(),controlType:"Label",controlOptions:{defaultValue:h.GLOBAL_SECURITY_GROUP_TITLE}}),this.childViews.enableAdaptiveThresholdControl=new l({controlType:"SyntheticRadio",controlOptions:{modelAttribute:"adaptive_thresholds_is_enabled",model:this._configSettingsModel,items:[{label:e("Yes").t(),value:!0},{label:e("No").t(),value:!1}]},label:e("Enable Adaptive Thresholding").t(),tooltip:e("Allow for time varying thresholds to update periodically").t()}),this.childViews.kpiTrainingEarliestTimePicker=new l({controlType:"SyntheticSelect",controlOptions:{className:"dropdown-toggle kpi-adaptive-training-time-picker",toggleClassName:"btn",items:a.KPI.kpiTimePresetsList,popdownOptions:{attachDialogTo:"body"},modelAttribute:"adaptive_thresholding_training_window",model:this._configSettingsModel},label:e("Training window").t(),tooltip:e("Select the time window over which the KPI adaptive thresholding training should run").t()})},render:function(){this.$el.html(this.template({_:e},{variable:"vars"})),this.renderThresholdingControls(),this.$(".threshold-template-aggregate-selector-container").html(""),this.$(".threshold-template-aggregate-selector-container").append(this.childViews.aggregateEntityConfigureControl.render().$el),this.toggleTrainingWindowControl(),this.serviceCollection=new s;var t="title,_key,kpis.title,kpis._key,kpis.kpi_threshold_template_id,kpis.type";return this.serviceObjects=this.serviceCollection.getSpecifiedFields({},t),this.serviceObjects.done(function(e){this.serviceObjects=e,this._populateServiceSelector(),this._renderAffectedKPIs()}.bind(this)),this},_renderAffectedKPIs:function(){for(var t=this.serviceObjects.map(function(e){for(var t=[],i=e.kpis,l=0;l<i.length;++l){var o=i[l];o.kpi_threshold_template_id===this.thresholdTemplateModel.id&&t.push(o.title)}return{serviceTitle:e.title,linkedKpis:t}}.bind(this)),i=0,l="",o=0;o<t.length;++o){i+=t[o].linkedKpis.length;for(var s=e.escape(t[o].serviceTitle),r=0;r<t[o].linkedKpis.length;++r)l+=s+"/"+e.escape(t[o].linkedKpis[r])+"<br/>"}this.$(".threshold-affected-kpis").css("display","inline-block"),this.$(".threshold-affected-kpis-count").text(i),this.$(".threshold-affected-kpis").tooltip({title:l,html:!0,container:"body"})},_populateServiceSelector:function(){for(var t=[],i=0;i<this.serviceObjects.length;++i){var o=this.serviceObjects[i];t.push({label:o.title,value:o._key})}this.childViews.serviceSelector=new l({label:e("Preview Service").t(),controlType:"SyntheticSelect",controlOptions:{model:this.previewModel,modelAttribute:"serviceId",popdownOptions:{attachDialogTo:"body"},items:t}}),t.length>0?(this.previewModel.set("serviceId",t[0].value),this.$(".threshold-template-preview-service").append(this.childViews.serviceSelector.render().$el)):this._renderNoServiceState()},toggleTrainingWindowControl:function(){this.thresholdTemplateModel.get("adaptive_thresholds_is_enabled")?this.childViews.kpiTrainingEarliestTimePicker.$el.show():this.childViews.kpiTrainingEarliestTimePicker.$el.hide()},renderThresholdingControls:function(){this.$(".sec-grp-control").html(""),this.$(".sec-grp-control").append(this.childViews.securityGroupControl.render().$el),this.$(".threshold-template-adaptive-enabled-control").html(""),this.$(".threshold-template-adaptive-enabled-control").append(this.childViews.enableAdaptiveThresholdControl.render().$el),this.$(".threshold-template-adaptive-training-window-control").html(""),this.$(".threshold-template-adaptive-training-window-control").append(this.childViews.kpiTrainingEarliestTimePicker.render().$el)},_clearTimeVariantThresholdingView:function(){this.childViews.timeVariantThresholdingView&&this.childViews.timeVariantThresholdingView.remove()},_renderNoServiceState:function(){this._clearTimeVariantThresholdingView(),this.$(".threshold-template-error-state").text(e("Create at least one service and KPI before editing thresholding templates.").t()),this.$(".threshold-template-error-state").show()},_renderNoKPIState:function(){this._clearTimeVariantThresholdingView(),this.$(".threshold-template-error-state").text(e("This service has no KPIs. Must have a sample KPI to configure thresholding templates.").t()),this.$(".threshold-template-error-state").show()},_onSelectService:function(){for(var t=this.previewModel.get("serviceId"),i=e.findWhere(this.serviceObjects,{_key:t}),s=i.kpis,r=[],n=0;n<s.length;++n){var a=s[n];a.type===o.ITSI_KPI_TYPE_PRIMARY&&r.push({label:a.title,value:a._key})}this.childViews.kpiSelector&&this.childViews.kpiSelector.remove(),this.childViews.kpiSelector=new l({label:e("Preview KPI").t(),controlType:"SyntheticSelect",controlOptions:{model:this.previewModel,modelAttribute:"kpiId",popdownOptions:{attachDialogTo:"body"},items:r}}),r.length>0?(this.previewModel.set("kpiId",r[0].value),this.$(".threshold-template-preview-kpi").html(""),this.$(".threshold-template-preview-kpi").append(this.childViews.kpiSelector.render().$el)):this._renderNoKPIState()},_onSelectKPI:function(){this._serviceModel&&this._serviceModel._key===this.previewModel.get("serviceId")?(this._updateKpiModel(),this._renderTimeVariantThresholdingView()):(this._serviceModel=new r({_key:this.previewModel.get("serviceId")}),this._serviceModel.fetch().done(function(e){this._serviceModel=e,this._updateKpiModel(),this._renderTimeVariantThresholdingView()}.bind(this)).fail(function(){console.log("Failed to retrieve service model.")}))},_updateKpiModel:function(){this._kpiModel=this._serviceModel.kpis.get(this.previewModel.get("kpiId"))},_renderTimeVariantThresholdingView:function(){return this.$(".threshold-template-error-state").hide(),this.childViews.timeVariantThresholdingView&&this.childViews.timeVariantThresholdingView.remove(),this._serviceModel?this._kpiModel?(this.childViews.timeVariantThresholdingView=new this.KpiTimeVariantThresholdingView({service:this._serviceModel,kpiModel:this._kpiModel,configSettingsModel:this._configSettingsModel,timeVariantThresholdModel:this.thresholdTemplateModel.get("time_variate_thresholds_specification"),previewMode:!0}),this.$(".threshold-template-time-variant-container").html(""),this.$(".threshold-template-time-variant-container").append(this.childViews.timeVariantThresholdingView.render().$el),void this.$(".threshold-template-body").show()):void this._renderNoKPIState():void this._renderNoServiceState()},refreshModel:function(){this._renderTimeVariantThresholdingView(),this._configSettingsModel.set({adaptive_thresholds_is_enabled:this.thresholdTemplateModel.get("adaptive_thresholds_is_enabled"),adaptive_thresholding_training_window:this.thresholdTemplateModel.get("adaptive_thresholding_training_window")})},remove:function(){return e.each(this.childViews,function(e){e.remove()}),i.View.prototype.remove.apply(this,arguments)},_changePoliciesToStatic:function(){for(var e=this.thresholdTemplateModel.get("time_variate_thresholds_specification"),t=e.get("policies"),i=0;i<t.length;++i)t.at(i).set("policy_type","static")}});return g}.apply(t,l),!(void 0!==o&&(e.exports=o))},2754:function(e,t){e.exports='<div class="kpi-threshold-template-editor-view-container">\n\t<div class="threshold-affected-kpis" style="display:none;">\n\t\t<span class="threshold-affected-kpis-count bold-label">0</span><span class="bold-label"><%- vars._(\' KPIs\').t() %></span>\n\t\t<span class="threshold-affected-kpis-message">\n\t\t\t<%- vars._(" using this template").t() %>\n\t\t</span>\n\t</div>\n\t<div class="threshold-template-preview-container">\n\t\t<div class="threshold-template-preview-service"></div>\n\t\t<div class="threshold-template-preview-kpi"></div>\n\t</div>\n\t<div class="threshold-template-error-state" style="display: none;"></div>\n\t<div class="threshold-template-body" style="display: none;">\n\t\t<div class="sec-grp-control"></div>\n\t\t<div class="threshold-template-adaptive-controls">\n\t\t\t<div class="threshold-template-adaptive-enabled-control"></div>\n\t\t\t<div class="threshold-template-adaptive-training-window-control"></div>\n\t\t</div>\n\t\t<div class="threshold-template-aggregate-selector-container"></div>\n\t\t<div class="threshold-template-time-variant-container"></div>\n\t</div>\n</div>'},2755:function(e,t,i){var l=i(2756);"string"==typeof l&&(l=[[e.id,l,""]]);i(15)(l,{});l.locals&&(e.exports=l.locals)},2756:function(e,t,i){t=e.exports=i(14)(),t.push([e.id,".kpi-threshold-template-editor-view-container{padding-left:4px}.threshold-template-adaptive-enabled-control,.threshold-template-adaptive-training-window-control,.threshold-template-preview-kpi,.threshold-template-preview-service{display:inline-block;padding-right:25px}.threshold-template-body,.threshold-template-preview-container{padding-top:10px}.threshold-affected-kpis{display:inline-block}.threshold-template-preview-service{min-width:170px}.bold-label{font-weight:600}.kpi-threshold-template-editor-view-container .sec-grp-control .controls,.kpi-threshold-template-editor-view-container .sec-grp-control label{display:inline-block}",""])},2757:function(e,t){e.exports='<div class="kpi-threshold-template-editor-view-container">\n\n\t<div class="threshold-affected-kpis" style="display:none;">\n\t\t<span class="threshold-affected-kpis-count bold-label"><%- vars._(\'0\').t() %></span><span class="bold-label"><%- vars._(\' KPIs\').t() %></span>\n\t\t<span class="threshold-affected-kpis-message">\n\t\t\t<%- vars._(\' using this template\').t() %>\n\t\t</span>\n\t</div>\n\t<div class="threshold-template-info form form-horizontal">\n\t</div>\n\t<div class="threshold-template-preview-container">\n\t\t<div class="threshold-template-preview-service"></div>\n\t\t<div class="threshold-template-preview-kpi"></div>\n\t</div>\n\t<div class="threshold-template-error-state"></div>\n\t<div class="threshold-template-body">\n\t\t<div class="sec-grp-control"></div>\n\t\t<div class="threshold-template-adaptive-controls">\n\t\t\t<div class="threshold-template-adaptive-enabled-control"></div>\n\t\t\t<div class="threshold-template-adaptive-training-window-control"></div>\n\t\t</div>\n\t\t<div class="threshold-template-aggregate-selector-container"></div>\n\t\t<div class="threshold-template-time-variant-container"></div>\n\t</div>\n</div>'},2758:function(e,t,i){var l=i(2759);"string"==typeof l&&(l=[[e.id,l,""]]);i(15)(l,{});l.locals&&(e.exports=l.locals)},2759:function(e,t,i){t=e.exports=i(14)(),t.push([e.id,".kpi-threshold-template-editor-view-container{padding-left:200px;padding-right:200px}.threshold-template-adaptive-enabled-control,.threshold-template-adaptive-training-window-control,.threshold-template-preview-kpi,.threshold-template-preview-service{display:inline-block;padding-right:25px}.threshold-template-body,.threshold-template-preview-container{padding-top:10px}.threshold-affected-kpis{display:none;margin-bottom:20px}.threshold-template-preview-service{min-width:170px}.threshold-template-body,.threshold-template-error-state{display:none}.bold-label{font-weight:600}.kpi-threshold-template-editor-view-container .threshold-template-preview-kpi .control-group,.kpi-threshold-template-editor-view-container .threshold-template-preview-service .control-group{display:flex}.kpi-threshold-template-editor-view-container .threshold-template-info .control-label{width:161px}.kpi-threshold-template-editor-view-container .time-variant-thresholding-view{margin-left:0}",""])}});