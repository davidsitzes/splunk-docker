webpackJsonp([11],{0:function(e,i,t){var s,r;t.p=function(){function e(){for(var e,t,s="",r=0,a=arguments.length;r<a;r++)e=arguments[r].toString(),t=e.length,t>1&&"/"==e.charAt(t-1)&&(e=e.substring(0,t-1)),s+="/"!=e.charAt(0)?"/"+e:e;if("/"!=s){var o=s.split("/"),n=o[1];if("static"==n||"modules"==n){var l=s.substring(n.length+2,s.length);s="/"+n,window.$C.BUILD_NUMBER&&(s+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(s+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(s+=":"+i("APP_BUILD",0)),s+="/"+l}}var d=i("MRSPARKLE_ROOT_PATH","/"),c=i("DJANGO_ROOT_PATH",""),p=i("LOCALE","en-US"),v="";return v=c&&s.substring(0,c.length)===c?s.replace(c,c+"/"+p.toLowerCase()):"/"+p+s,""==d||"/"==d?v:d+v}function i(e,i){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==i)return i;throw new Error("getConfigValue - "+e+" not set, no default provided")}return e("/static/app/itsi/build/pages")+"/"}(),s=[t("shim/jquery"),t("require/underscore"),t("require/backbone"),t(129),t(4),t(232),t(239),t(473),t(1036),t(1243),t(1037),t(1042),t(1043),t(1055),t(1039)],r=function(e,i,t,s,r,a,o,n,l,d,c,p,v,h,g){var u=r(i("Deep Dive").t()),_='<div class="itsi-deep-dive-container dashboard-body container-fluid main-section-body" data-role="main">';e("#app-main-layout").html(_);var y=function(){var s=new p({title:"",description:"",earliest:u.defaultTokenModel.get("earliest")||"-60m",latest:u.defaultTokenModel.get("latest")||"now"}),r=i.extend({},t.Events),o=new v({appPageHeaderModel:s,pageChrome:u}),_=new h({ddDispatcher:r}),y=e(".itsi-deep-dive-container");y.append(o.render().$el),y.append(_.render().$el),y.append('<div class="dashboard-row dashboard-row1"><div id="deep-dive-wrapper"></div> </div><div class="deep-dive-service-topology-container"></div>');var f=u.defaultTokenModel.get("earliest"),S=u.defaultTokenModel.get("latest"),m=new l({el:e("#deep-dive-wrapper"),savedDeepDive:o.savedDeepDive,laneSettingsCollection:o.savedDeepDive.get("lane_settings_collection"),earliestTime:f,latestTime:S,appPageHeaderModel:s,ddDispatcher:r,subheaderView:_,urlTokenModel:u.urlTokenModel});m.render();var D=new d({el:e(".deep-dive-service-topology-container"),savedDeepDive:o.savedDeepDive,earliestTime:f,latestTime:S});D.render(),window.deepdive=m,window.ddservicetopology=D;var T;try{T=u.defaultTokenModel.get("laneSettingsCollection"),T=JSON.parse(T),T instanceof Array||(console.log("unrecognized uri parameter for laneSettingsCollection, must be Array"),T=[])}catch(e){console.log("unrecognized uri parameter for laneSettingsCollection, must be JSON parsable"),T=[]}var k=function(e,i,t){if(e&&e.kpiServiceId&&e.kpiId){var s=new a({_key:e.kpiServiceId});return s.fetch({success:i,error:t})}},b="";e.each(T,function(e){var i=T[e],t=new g(i,{parse:!0}),s=function(e){var i=e.get("kpis").get(t.get("kpiId")),s=e.get("kpis").first();i?(t.set({laneType:"kpi",search:i.get("search_time_series_aggregate"),kpiUnit:i.get("unit")}),t.get("subtitle")!==e.get("title")&&e.get("title")&&t.set({subtitle:e.get("title")}),t.get("overwriteKpiTitle")&&"no"!==t.get("overwriteKpiTitle")||t.set({kpiTitle:i.get("title"),kpiServiceTitle:e.get("title")}),i===s&&"distributionStream"!==t.get("graphType")?t.set({kpiAddToSummary:"yes"}):"distributionStream"===t.get("graphType")?t.set({kpiAddToSummary:"no"}):t.set({kpiAddToSummary:"yes"}),t.kpiModel=i,o.savedDeepDive.get("lane_settings_collection").add(t)):console.log("could not add lane settings object due to missing KPI data")};if(t&&"kpi"===t.get("searchSource")){var r=k(t.toJSON(),s);r?b=t.get("kpiServiceId"):o.savedDeepDive.get("lane_settings_collection").add(t)}else o.savedDeepDive.get("lane_settings_collection").add(t)}),!i.isArray(T)||i.isEmpty(T)||i.isEmpty(b)||o.savedDeepDive.set({topology_id:b});var w=u.defaultTokenModel.get("savedDeepDiveID");if(w){var A=new c({_key:w}),x=u.defaultTokenModel.get("owner");x&&A.set("_owner",x),A.fetch({success:function(){if(A.get("lane_settings_collection").add(T),A.get("is_named"))A.get("focus_id")&&!A.get("topology_id")?A.set("topology_id",A.get("focus_id")):A.get("focus_id")||A.get("topology_id")||A.set("topology_id",null);else{var t=A.get("focus_id")?A.get("focus_id"):null;A.set("topology_id",t)}var r=[];A.get("lane_settings_collection").each(function(e){var t="entity"===e.get("laneType");if("kpi"===e.get("searchSource")||t){var s=function(s){e.set({isAccessDenied:!1});var r=s.get("kpis").get(e.get("kpiId"));if(r)e.get("subtitle")!==s.get("title")&&s.get("title")&&!t&&e.set("subtitle",s.get("title")),"kpi"===e.get("laneType")||t||e.set("laneType","kpi"),t||e.set("search",r.get("search_time_series_aggregate")),e.set("kpiUnit",r.get("unit")),e.get("overwriteKpiTitle")&&"no"!==e.get("overwriteKpiTitle")||(e.set("kpiTitle",r.get("title")),e.set("kpiServiceTitle",s.get("title"))),e.get("kpiAddToSummary")&&"distributionStream"!==e.get("graphType")||t||("distributionStream"===e.get("graphType")?e.set("kpiAddToSummary","no"):e.set("kpiAddToSummary","yes")),e.kpiModel=r,"distributionStream"!==e.get("graphType")||r.get("is_entity_breakdown")||e.set({graphType:"line"});else{""!==e.get("title")&&"no"!==e.get("overwriteKpiTitle")||t?t&&""===e.get("title")&&"no"===e.get("overwriteEntityTitle")&&e.set("title",e.get("entityTitle")):e.set("title",e.get("kpiTitle")),"yes"===e.get("laneOverlaySettingsModel").get("isEnabled")&&e.get("laneOverlaySettingsModel").set("isEnabled","no");var a="distributionStream"===e.get("graphType")?"line":e.get("graphType");e.set({searchSource:"adhoc",subtitle:i("This KPI/Service has been deleted").t(),laneType:"metric",graphType:a,kpiAddToSummary:"no",thresholdIndicationEnabled:"disabled"})}o.savedDeepDive.get("lane_settings_collection").add(e)},a=function(s,r){if(403===r.status)console.log("Access Denied to service. This will be a blank deep dive lane."),e.set({isAccessDenied:!0});else{e.set({isAccessDenied:!1}),""!==e.get("title")&&"no"!==e.get("overwriteKpiTitle")||t?t&&""===e.get("title")&&"no"===e.get("overwriteEntityTitle")&&e.set("title",e.get("entityTitle")):e.set("title",e.get("kpiTitle")),"yes"===e.get("laneOverlaySettingsModel").get("isEnabled")&&e.get("laneOverlaySettingsModel").set("isEnabled","no");var a="distributionStream"===e.get("graphType")?"line":e.get("graphType");e.set({searchSource:"adhoc",subtitle:i("This KPI/Service has been deleted").t(),laneType:"metric",graphType:a,kpiAddToSummary:"no",thresholdIndicationEnabled:"disabled"}),console.log("Service not found. Creating adhoc search"),o.savedDeepDive.get("lane_settings_collection").add(e)}},n=k(e.toJSON(),s,a);n?r.push(n):(console.log("could not add lane settings object due to missing KPI data"),A.get("lane_settings_collection").remove(e))}});var a=function(){var e=A.get("earliest_time")||"-60m",i=A.get("latest_time")||"now";i&&e&&(f||S)&&A.set({earliest_time:f,latest_time:S}),s.set({earliest:A.get("earliest_time"),latest:A.get("latest_time"),title:A.get("title"),description:A.get("description")}),o.setSavedDeepDive(A),m.setSavedDeepDive(A),D.setSavedDeepDive(A)};if(r.length>0){var n=0;e.when.apply(e,r).always(function(){e.each(r,function(){this.done(function(){console.log("promiseArray done"),n++,n===r.length&&a()}).fail(function(){console.log("promiseArray fail"),n++,n===r.length&&a()})})})}else console.log("promiseArray has no elements"),a()},error:function(e,t){var s=new n({errorMessage:i("Could not load settings for the page.").t(),htmlResponse:t});s.show()}})}};s.setupViewFromDefaultTokenModel(u,y,"savedDeepDiveID")}.apply(i,s),!(void 0!==r&&(e.exports=r))},1243:function(e,i,t){var s,r;s=[t("shim/jquery"),t("require/underscore"),t("require/backbone"),t("splunkjs/mvc/utils"),t("shim/splunk.util"),t(231),t(1246),t(1244),t(1037),t(1039),t(1057),t(1278),t(1276)],r=function(e,i,t,s,r,a,o,n,l,d,c,p){var v=t.View.extend({initialize:function(e){t.View.prototype.initialize.apply(this,arguments),this.id=this.id||this.cid,this.savedDeepDive=null,e.savedDeepDive instanceof l?this.setSavedDeepDive(e.savedDeepDive):this.setSavedDeepDive(new l({is_named:!1,lane_settings_collection:new d({},{})})),this._earliestTime="undefined"==typeof e.earliestTime?this.savedDeepDive.get("earliest_time"):e.earliestTime||"-60m",this._latestTime="undefined"==typeof e.latestTime?this.savedDeepDive.get("latest_time"):e.latestTime||"now",this._horizontalFirstRender=!0,this._verticalFirstRender=!0,this._viewTopology=!0,this._fetchedServiceArray=null},events:{"click .sidebar-close":"_renderSidebar","click .horizontal-sidebar-close":"_renderSidebar","click .deep-dive-service-drilldown":function(){var e=r.make_full_url("/app/itsi/service_definition#new/info");s.redirect(e,!0)},"click .topology-tree-service-dependency-drilldown":function(){if(this._fetchedServiceArray&&!i.isEmpty(this._fetchedServiceArray)){var e=i.findWhere(this._fetchedServiceArray,{_key:this.savedDeepDive.get("topology_id")}),t=this._fetchedServiceArray[0]._key,a=null!==this.savedDeepDive.get("topology_id")&&e?this.savedDeepDive.get("topology_id"):t,o=r.make_full_url("/app/itsi/service_definition#"+a+"/dependency");s.redirect(o,!0)}else console.log("Fetched Service array is empty")}},render:function(){this.$el.append(p),this.getServiceCollectionXHR=c.getServiceCollectionPartialFetchWithSearchesDependencies(),this.getServiceCollectionXHR.done(function(e){this._fetchedServiceArray=e,0===this._fetchedServiceArray.length?console.log("Service Collection is empty"):(this._verticalFirstRender&&(this._verticalFirstRender=!1,this.verticalSidebar=new n({el:".side-bar-master.shared-sidebar",fetchedServiceArray:this._fetchedServiceArray,serviceId:this.savedDeepDive.get("topology_id")}),this.verticalSidebar.render()),this._horizontalFirstRender&&(this._horizontalFirstRender=!1,this.horizontalSidebar=new o({el:".side-bar-master.shared-sidebar",fetchedServiceArray:this._fetchedServiceArray,serviceId:this.savedDeepDive.get("topology_id"),savedDeepDive:this.savedDeepDive}),this.horizontalSidebar.render()),this._renderSidebar())}.bind(this)).fail(function(){this.$el.html('<div><a class="deep-dive-service-drilldown">'+i("Error retrieving services from server, please check service configuration. May need to verify user settings for roles and permissions.").t()+"</a></div>")}.bind(this))},_renderSidebar:function(i){i&&i.preventDefault(),this._viewTopology?(this._viewTopology=!1,e(".dashboard-header.clearfix").animate({"padding-right":380},100,"swing"),e(".dashboard-row.dashboard-row1").animate({"padding-right":380},100,"swing").promise().done(function(){e(window).trigger("resize")}),e(".application-page-sub-header").animate({"padding-right":380},100,"swing").promise().done(function(){e(window).trigger("resize")}),e(".sidebar.expanded").show(),e(".sidebar.collapsed").hide()):(this._viewTopology=!0,e(".sidebar.expanded").hide(),e(".sidebar.collapsed").show(),e(".dashboard-header.clearfix").animate({"padding-right":70},100,"swing"),e(".dashboard-row.dashboard-row1").animate({"padding-right":70},100,"swing").promise().done(function(){e(window).trigger("resize")}),e(".application-page-sub-header").animate({"padding-right":70},100,"swing").promise().done(function(){e(window).trigger("resize")}))},_updateVerticalSidebar:function(){this.verticalSidebar&&(this.verticalSidebar._serviceId=this.savedDeepDive.get("topology_id"),this.verticalSidebar._updateServiceTitle())},_updateSidebars:function(){this._updateVerticalSidebar(),this.horizontalSidebar&&this.horizontalSidebar.updateSeverityTiles()},_onTimeChange:function(){this.horizontalSidebar&&this.horizontalSidebar.onTimeChange()},setSavedDeepDive:function(e){this.savedDeepDive instanceof l&&this.stopListening(this.savedDeepDive),this.savedDeepDive=e,this.listenTo(this.savedDeepDive,"replace",this._replaceSavedDeepDive),this.listenTo(this.savedDeepDive,"change:topology_id",this._updateSidebars),this.listenTo(this.savedDeepDive,"change:earliest_time change:latest_time",this._onTimeChange),this.horizontalSidebar&&this.horizontalSidebar.setSavedDeepDive(e),this.verticalSidebar&&this._updateVerticalSidebar()},_replaceSavedDeepDive:function(e){this.setSavedDeepDive(e)}});return v}.apply(i,s),!(void 0!==r&&(e.exports=r))},1244:function(e,i,t){var s,r;s=[t("shim/jquery"),t("require/underscore"),t("require/backbone"),t(156),t(1245)],r=function(e,i,t,s,r){var a=i.template(r,{_:i}),o=t.View.extend({initialize:function(e){t.View.prototype.initialize.apply(this,arguments),this.id=this.id||this.cid,this._serviceId=e.serviceId,this._fetchedServiceArray=e.fetchedServiceArray},events:{},render:function(){this.$el.removeClass("deep-dive-horizontal-sidebar"),this.$el.addClass("deep-dive-vertical-sidebar").append(a),this._updateServiceTitle()},_updateServiceTitle:function(){if(this._fetchedServiceArray&&!i.isEmpty(this._fetchedServiceArray)){var e=i.findWhere(this._fetchedServiceArray,{_key:this._serviceId}),t=null!==this._serviceId&&e?e.title:this._fetchedServiceArray[0].title;this.$(".service-name").text(t)}else console.log("Fetched Service array is empty")}});return o}.apply(i,s),!(void 0!==r&&(e.exports=r))},1245:function(e,i){e.exports='<div class="sidebar collapsed">\n  <div class="sidebar-body">\n      <div style="display:block">\n            <a class="sidebar-close" href="#" style="left:0px">\n                  <i class="icon-chevron-left"></i>\n            </a>\n            <h3 class="focus-title"><%= _("Focus:").t() %></h3>\n            <h3 class="service-name"></h3>\n                    \n      </div>\n  </div>\n</div>'},1246:function(e,i,t){var s,r;s=[t("shim/jquery"),t("require/underscore"),t("require/backbone"),t("shim/jquery.ui.resizable"),t(156),t("uri/route"),t("splunkjs/mvc/utils"),t("views/shared/controls/ControlGroup"),t("splunkjs/mvc/searchmanager"),t(129),t(1041),t(1247),t(1037),t(231),t(1274),t(1275),t(1276)],r=function(e,i,t,s,r,a,o,n,l,d,c,p,v,h,g,u){var _=i.template(u,{_:i}),y=t.View.extend({initialize:function(e){t.View.prototype.initialize.apply(this,arguments),this.id=this.id||this.cid,this.savedDeepDive=null,e.savedDeepDive instanceof v&&this.setSavedDeepDive(e.savedDeepDive),this._earliestTime=this.savedDeepDive.get("earliest_time")||"-60m",this._latestTime=this.savedDeepDive.get("latest_time")||"now",this._fetchedServiceArray=e.fetchedServiceArray;var i="`service_health_data` | stats latest(color) AS color by serviceid";this.getTimeInIso=!0,this.dataManager=new c({earliestTime:this._earliestTime,latestTime:this._latestTime,search:i,id:"colorMap_manager",getTimeInIso:this.getTimeInIso}),this._colorMap={},this.listenTo(this.dataManager,"change:data",this._onDataManagerChange)},render:function(){this.$el.removeClass("deep-dive-vertical-sidebar"),this.$el.addClass("deep-dive-horizontal-sidebar").append(_),this._updateServiceSelector()},_updateServiceSelector:function(){0===this._fetchedServiceArray.length?console.log("Service collection is empty"):(this._serviceSelectItems=i.map(this._fetchedServiceArray,function(e){return{value:e._key,label:e.title}}),this._renderServiceSelector())},_renderServiceSelector:function(){null!==this.serviceSelector&&this.$(".service-selector-dropdown").empty(),this.serviceSelector=new n({controlType:"SyntheticSelect",controlOptions:{model:this.savedDeepDive,modelAttribute:"topology_id",items:[],popdownOptions:{attachDialogTo:"body"}}}),this.$(".service-selector-dropdown").append(this.serviceSelector.render().el),this.serviceSelector.childList[0].setItems(this._serviceSelectItems),this.serviceSelector.enable(),this.serviceSelector.childList[0].setValueFromModel(),this._renderSeverityTiles()},_fetchedServiceArrayHasTopologyId:function(e){return i.findWhere(this._fetchedServiceArray,{_key:e})},_renderSeverityTiles:function(){if(null===this.kpiSeverityTiles||"undefined"==typeof this.kpiSeverityTiles){var e=this._fetchedServiceArrayHasTopologyId(this.savedDeepDive.get("topology_id")),i=null!==this.savedDeepDive.get("topology_id")&&e?e.title:this._fetchedServiceArray[0].title,t=null!==this.savedDeepDive.get("topology_id")&&e?this.savedDeepDive.get("topology_id"):this._fetchedServiceArray[0]._key;this.kpiSeverityTiles=new p({el:this.$(".deep-dive-kpi-listing-container"),savedDeepDive:this.savedDeepDive,serviceFocusId:t,serviceTitle:i,earliestTime:this._earliestTime,latestTime:this._latestTime}),this.kpiSeverityTiles.render(),this.kpiSeverityTiles.assignKpiUnits(this._fetchedServiceArray),this._createTopologyTreeDataStructure(t)}else this.updateSeverityTiles();this.kpiSeverityTiles.createKpiSelectionMap()},updateSeverityTiles:function(){var e=this._fetchedServiceArrayHasTopologyId(this.savedDeepDive.get("topology_id")),i=null!==this.savedDeepDive.get("topology_id")&&e?this.savedDeepDive.get("topology_id"):this._fetchedServiceArray[0]._key,t=null!==this.savedDeepDive.get("topology_id")&&e?e.title:this._fetchedServiceArray[0].title;this.kpiSeverityTiles.tokens.set("serviceId",i),this.kpiSeverityTiles.kpiHealthTilesView.serviceTitle=t,this.kpiSeverityTiles.kpiHealthTilesView.updateTitle(),this.kpiSeverityTiles.tokens.set("serviceId",i),this.kpiSeverityTiles.kpiHealthTilesView.render(),this._createTopologyTreeDataStructure(i)},_updateSeverityTilesTimeRange:function(){this.kpiSeverityTiles.kpiHealthManager.set({earliest_time:this.savedDeepDive.get("earliest_time"),latest_time:this.savedDeepDive.get("latest_time")}),this.kpiSeverityTiles.kpiHealthTilesView.render()},_generateColorMap:function(){this._colorMap=i.reduce(this.dataManager.get("data"),function(e,i){return e[i[0]]=i[1],e},{})},_getColor:function(e){var i="#cccccc";return this._colorMap.hasOwnProperty(e)?this._colorMap[e]:i},_onDataManagerChange:function(){var e=this._fetchedServiceArrayHasTopologyId(this.savedDeepDive.get("topology_id")),i=null!==this.savedDeepDive.get("topology_id")&&e?this.savedDeepDive.get("topology_id"):this._fetchedServiceArray[0]._key;this._generateColorMap(),this._createTopologyTreeDataStructure(i)},onTimeChange:function(){this.dataManager.set({earliestTime:this.savedDeepDive.get("earliest_time"),latestTime:this.savedDeepDive.get("latest_time")}),this._updateSeverityTilesTimeRange()},_createTopologyTreeDataStructure:function(e){var t=this,s=[],r=[],a=this._fetchedServiceArrayHasTopologyId(e),o=null!==a?a:this._fetchedServiceArray[0]._key;if(o){var n={id:d.generateUUID(),_key:o._key,name:o.title,color:t._getColor(e)},l=o.services_depending_on_me;l&&(i.each(l,function(e){var i=t._fetchedServiceArrayHasTopologyId(e.serviceid);"undefined"!=typeof i&&s.push({id:d.generateUUID(),_key:e.serviceid,name:i.title,color:t._getColor(e.serviceid)})}),n.children=s);var c={id:d.generateUUID(),_key:o._key,name:o.title,color:t._getColor(e)},p=o.services_depends_on;p&&(r=p.map(function(e){var i=t._fetchedServiceArrayHasTopologyId(e.serviceid);return{id:d.generateUUID(),_key:e.serviceid,name:i.title,color:t._getColor(e.serviceid)}}),c.children=r),this._renderTopologyTree(n,c)}},_renderTopologyTree:function(i,t){this.topologyTree=new g({el:e(".deep-dive-topology-tree-container"),impactedTreeRoot:i,dependsOnTreeRoot:t,savedModel:this.savedDeepDive}),this.topologyTree.render(),this.$(".deep-dive-topology-tree-container").resizable({autoHide:!0,containment:"parent",handles:"s",maxHeight:500,minHeight:60})},_onLaneSettingsCollectionChange:function(){this.kpiSeverityTiles.createKpiSelectionMap()},setSavedDeepDive:function(e){this.savedDeepDive instanceof v&&this.stopListening(this.savedDeepDive),this.savedDeepDive=e,this.listenTo(this.savedDeepDive,"replace",this._replaceSavedDeepDive),this.kpiSeverityTiles&&(this.kpiSeverityTiles.setSavedDeepDive(e),this.kpiSeverityTiles.setServiceFetchedArray(this._fetchedServiceArray),this._renderServiceSelector()),this.topologyTree&&this.topologyTree.setSavedModel(e),this.laneSettingsCollection&&this.stopListening(this.laneSettingsCollection),this.laneSettingsCollection=this.savedDeepDive.get("lane_settings_collection"),this.listenTo(this.laneSettingsCollection,"add remove reset change",this._onLaneSettingsCollectionChange)},_replaceSavedDeepDive:function(e){this.setSavedDeepDive(e)}});return y}.apply(i,s),!(void 0!==r&&(e.exports=r))},1247:function(e,i,t){var s,r;s=[t("require/underscore"),t("shim/jquery"),t("require/backbone"),t("splunkjs/mvc"),t("splunkjs/mvc/searchmanager"),t(1248),t(1037),t(1039),t(1272)],r=function(e,i,t,s,r,a,o,n,l){var d=t.View.extend({initialize:function(e){this._earliestTime=e.earliestTime,this._latestTime=e.latestTime,this._serviceFocusId=e.serviceFocusId||"None",this._serviceTitle=e.serviceTitle,this.tokens=s.Components.getInstance("default"),this.tokens.set("serviceId",this._serviceFocusId),this.savedDeepDive=null,e.savedDeepDive instanceof o&&this.setSavedDeepDive(e.savedDeepDive)},events:{},render:function(){var i=this;this.kpiHealthManager=new r({search:s.tokenSafe('`get_full_itsi_summary_service($serviceId$)` source!=service_health_monitor `service_level_kpi_only` | eval alert_value=coalesce(alert_value,"N/A") | stats latest(alert_value) AS alert_value latest(alert_severity) AS severity_label latest(alert_color) AS color latest(alert_level) AS severity_value latest(service) AS service sparkline(avg(alert_value)) AS spark latest(kpi) AS kpi latest(serviceid) AS serviceid by kpiid | join kpiid [| inputlookup service_kpi_lookup | rename kpis._key AS kpiid | mvexpand kpiid | fields kpiid] | sort 0 -severity_value | makemv delim=" " alert_value | eval alert_value=max(alert_value)'),earliest_time:this._earliestTime,latest_time:this._latestTime,indexedRealtime:"true",indexedRealtimeOffset:60,id:"kpi-health-tile-manager",auto_cancel:65}),this.kpiHealthTilesView=new a({el:this.$(".kpi-health-tiles"),tileView:"deep_dive",severityTilesConfig:{idField:"kpiid",severityLabelField:"severity_label",severityLevelField:"severity_value",severityColorField:"color",valueField:"alert_value",sparklineField:"spark",labelField:"kpi",subLabelField:"service",searchManager:this.kpiHealthManager,dataFields:["kpiid","serviceid"]},serviceTitle:this._serviceTitle,addLaneFunction:function(t){var s=i.savedDeepDive.get("lane_settings_collection"),r="avg";s.length>0&&s.some(function(e){if("avg"!==e.get("kpiStatsOp"))return void(r=e.get("kpiStatsOp"))});var a=e.map(t,function(t){var s=t.model,a=e.findWhere(i._fetchedServiceArray,{_key:s.get("dataFields").serviceid}),o=e.findWhere(a.kpis,{_key:s.get("dataFields").kpiid}),l=o.search_time_series_aggregate,d="yes",c=new n({kpiTitle:s.get("label"),subtitle:a.title||"",kpiServiceId:s.get("dataFields").serviceid,kpiServiceTitle:a.title||"",kpiId:s.get("dataFields").kpiid,kpiUnit:s.get("unit"),laneType:"kpi",searchSource:"kpi",kpiStatsOp:r,kpiAddToSummary:d,search:l,thresholdIndicationEnabled:"enabled",thresholdIndicationType:"stateIndication"});return c.kpiModel=o,c});s.add(a)},removeLaneFunction:function(e){var t=[],s=i.savedDeepDive.get("lane_settings_collection");s.forEach(function(i){e.indexOf(i.get("kpiId"))!==-1&&t.push(i.id)}),t.forEach(function(e){var i=s.get(e);s.remove(i)})}})},createKpiSelectionMap:function(){if(void 0!==this._fetchedServiceArray){var e={},i=[],t=this.savedDeepDive.get("lane_settings_collection");if(t.forEach(function(e){null!==e.get("kpiId")&&i.indexOf(e.get("kpiId"))===-1&&i.push(e.get("kpiId"))}),i.length>0)for(var s=0;s<this._fetchedServiceArray.length;s++){var r=this._fetchedServiceArray[s],a=r.kpis;if(void 0!==a&&a.length>0)for(var o=0;o<a.length;o++){var n=a[o];i.indexOf(n._key)!==-1?e[n._key]=!0:e[n._key]=!1}}else console.log("No KPI lanes in lane settings collection");this.kpiHealthTilesView.setKpiSelectionMap(e),this.kpiHealthTilesView.render()}else console.log("Empty service collection")},assignKpiUnits:function(e){if(this._fetchedServiceArray=e,void 0!==this._fetchedServiceArray){for(var i={},t=0;t<this._fetchedServiceArray.length;t++){var s=this._fetchedServiceArray[t],r=s.kpis;if(void 0!==r&&r.length>0)for(var a=0;a<r.length;a++){var o=r[a],n=o.unit;void 0!==n&&null!==n&&""!==n&&(i[o._key]=o.unit)}}this.kpiHealthTilesView.setKpiUnitMap(i),this.kpiHealthTilesView.render()}},setServiceFetchedArray:function(e){this._fetchedServiceArray=e},setSavedDeepDive:function(e){this.savedDeepDive instanceof o&&(this.stopListening(this.savedDeepDive),this.stopListening(this.laneSettingsCollection)),this.savedDeepDive=e,this.laneSettingsCollection=this.savedDeepDive.get("lane_settings_collection"),this.listenTo(this.laneSettingsCollection,"add remove reset",this.createKpiSelectionMap)}});return d}.apply(i,s),!(void 0!==r&&(e.exports=r))},1275:function(e,i){e.exports=' <div class="sidebar expanded">\n  <div class="sidebar-body">\n      <div class="report-preview content-preview splunkjs-mvc-simplexml-addcontent-reportcontent">\n          <div class="header">\n              <a class="horizontal-sidebar-close" href="#" style="left:0px">\n                <i class="icon-chevron-right"></i>\n              </a>\n              <h3 class="horizontal-focus"><%= _("Focus:").t() %></h3>\n              <div class="service-selector-dropdown"></div>\n          </div>\n          <div class="preview-body">\n              <div class="deep-dive-topology-tree-container"></div>\n              <div class="deep-dive-kpi-listing-container">\n                 <div class="kpi-health-tiles"></div>\n              </div>\n          </div>\n      </div>\n  </div>\n</div>'},1276:function(e,i,t){var s=t(1277);"string"==typeof s&&(s=[[e.id,s,""]]);t(15)(s,{});s.locals&&(e.exports=s.locals)},1277:function(e,i,t){i=e.exports=t(14)(),i.push([e.id,".side-bar-master .sidebar{z-index:1038;top:0;right:0;height:100%;background-color:#fff}.sidebar.collapsed,.sidebar.expanded{border:1px solid #ccc}.sidebar.expanded{width:360px;top:111px;position:absolute}.sidebar.collapsed{width:50px;top:111px;position:absolute}.sidebar.collapsed,.sidebar.expanded .header{background-color:#f7f7f7}.sidebar.expanded .sidebar-body .report-preview{width:360px}.sidebar.expanded .header{height:40px;width:360px;padding:0;border-bottom:1px solid #ccc}.sidebar.expanded .preview-body{padding:5px;top:41px}.horizontal-sidebar-close{margin-top:13px}.sidebar-close{margin-top:20px}.horizontal-sidebar-close,.sidebar-close{display:inline-block;margin-left:10px;font-size:20px;font-weight:700;line-height:16px;color:#000;text-shadow:0 1px 0 #fff}.focus-title,.service-name{padding-bottom:10px;transform:rotate(90deg);transform-origin:left bottom 0;-webkit-transform:rotate(90deg);-webkit-transform-origin:left bottom 0;font-size:16px;color:#333}.service-name{padding-left:35px;white-space:nowrap;overflow-x:hidden;min-width:450px;text-overflow:ellipsis}.horizontal-focus{padding-top:10px;font-size:16px;color:#333}.horizontal-focus,.service-selector-dropdown{display:inline-block;padding-left:10px}.service-selector-dropdown .link-label{display:inline-block;max-width:240px;overflow-x:hidden;text-overflow:ellipsis;vertical-align:middle}.service-selector-dropdown .caret{vertical-align:middle}.service-selector-dropdown i.icon-large{display:none}.service-selector-dropdown:hover .link-label{text-decoration:underline}.sidebar.expanded .header .service-selector-dropdown .control-group.shared-controls-controlgroup{margin-top:3px}.deep-dive-topology-tree-container{height:360px;border:3px #ccc;border-bottom-style:double;overflow-y:hidden;background:#fff}.deep-dive-kpi-listing-container{border:1px #ccc;border-top-style:none;overflow:auto;background:#fff;padding-top:10px}.topology-tree-no-dependencies-container{display:none;height:30px;width:350px;padding:5px}@media screen and (max-width:1086px){.sidebar.collapsed,.sidebar.expanded{top:151px}}",""])},1278:function(e,i){e.exports='<div class="side-bar-master shared-sidebar">\n</div>\n\n'}});