webpackJsonp([27],{0:function(t,e,i){var n,s;i.p=function(){function t(){for(var t,i,n="",s=0,a=arguments.length;s<a;s++)t=arguments[s].toString(),i=t.length,i>1&&"/"==t.charAt(i-1)&&(t=t.substring(0,i-1)),n+="/"!=t.charAt(0)?"/"+t:t;if("/"!=n){var o=n.split("/"),r=o[1];if("static"==r||"modules"==r){var l=n.substring(r.length+2,n.length);n="/"+r,window.$C.BUILD_NUMBER&&(n+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(n+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(n+=":"+e("APP_BUILD",0)),n+="/"+l}}var d=e("MRSPARKLE_ROOT_PATH","/"),c=e("DJANGO_ROOT_PATH",""),u=e("LOCALE","en-US"),h="";return h=c&&n.substring(0,c.length)===c?n.replace(c,c+"/"+u.toLowerCase()):"/"+u+n,""==d||"/"==d?h:d+h}function e(t,e){if(window.$C&&window.$C.hasOwnProperty(t))return window.$C[t];if(void 0!==e)return e;throw new Error("getConfigValue - "+t+" not set, no default provided")}return t("/static/app/itsi/build/pages")+"/"}(),n=[i("require/underscore"),i("shim/jquery"),i("util/router_utils"),i(401),i(862),i(2775),i(2781),i(2776),i(2777),i(2778),i(2779),i(2780)],s=function(t,e,i,n,s,a,o,r,l,d,c,u){var h={collection:a,model:s,editMenu:l,infoDetails:u,title:t("Maintenance Windows").t(),tableView:o,tableCaptionView:d,rowView:r,description:t("Viewer for all maintenance windows").t(),CreateButtonView:c};new n(h);i.start_backbone_history()}.apply(e,n),!(void 0!==s&&(t.exports=s))},2776:function(t,e,i){var n,s;n=[i("require/underscore"),i("require/backbone"),i("shim/jquery"),i(853),i(149),i("shim/splunk.util")],s=function(t,e,i,n,s,a){var o=n.extend({initialize:function(t){t.extraHeaders=[{name:"status",value:this.model.savedPage.getMaintenanceWindowStatus()},{name:"start_time",value:this._populateRowStartTime()},{name:"duration",value:this.model.savedPage.getMaintenanceWindowDuration()},{name:"end_time",value:this._populateRowEndTime()}],t.enableBulkActions=!0,n.prototype.initialize.apply(this,arguments),this.model.savedPage.get("can_edit")||this.bulkboxControl.disable()},_populateRowStartTime:function(){this.savedStartTimeUtc=this.model.savedPage.getMaintenanceWindowStartTime();var t=this.model.user.entry.content.get("tz")||"",e=s.convertToTimezoneObject(t),i=s.convertUtcDateToTimezoneDate(this.savedStartTimeUtc,1e3*e.get("offset"));return s.getLocalizedDate(i)},_populateRowEndTime:function(){if(this.savedEndTimeUtc=this.model.savedPage.getMaintenanceWindowEndTime(),this.model.savedPage.isIndefinite())return this.savedEndTimeUtc;var t=this.model.user.entry.content.get("tz")||"",e=s.convertToTimezoneObject(t),i=s.convertUtcDateToTimezoneDate(this.savedEndTimeUtc,1e3*e.get("offset"));return s.getLocalizedDate(i)},render:function(){n.prototype.render.apply(this,arguments);var e=a.sprintf(t("(%s UTC)").t(),this.savedStartTimeUtc.toLocaleString());if(this.$("td.start_time").append(' <span class="start-time-utc">'+e+"</span>"),!this.model.savedPage.isIndefinite()){var i=a.sprintf(t("(%s UTC)").t(),this.savedEndTimeUtc.toLocaleString());this.$("td.end_time").append(' <span class="end-time-utc">'+i+"</span>")}}});return o}.apply(e,n),!(void 0!==s&&(t.exports=s))},2777:function(t,e,i){var n,s;n=[i("require/underscore"),i("shim/jquery"),i("views/Base"),i("views/shared/delegates/Popdown"),i("views/shared/dialogs/TextDialog"),i(473),i("shim/splunk.util"),i(149),i(863),i(892)],s=function(t,e,i,n,s,a,o,r,l,d){var c=i.extend({initialize:function(){i.prototype.initialize.apply(this,arguments)},className:"dropdown",events:{"click a.delete":function(i){i.preventDefault();var n=new s({id:"modal_delete"});n.dialogShown=function(){this.trigger("show"),t.debounce(function(){this.$(".btn-primary:first").focus()}.bind(this),0)()},n.settings.set("primaryButtonLabel",t("Delete").t()),n.settings.set("cancelButtonLabel",t("Cancel").t()),n.settings.set("titleLabel",o.sprintf(t("Delete %s").t(),this.options.objectNameSingular)),n.setText(o.sprintf(t("Are you sure you want to delete %s?").t(),"<em>"+t.escape(this.model.savedPage.get("title"))+"</em>"));var r=this.model.savedPage;n.on("click:primaryButton",function(){r.destroy().done(function(){this.model.state.set("length",this.model.state.get("length")-1),this.collection.savedPages.trigger("refresh")}.bind(this)).always(function(){n.hide()}).fail(function(e){var i=new a({errorMessage:o.sprintf(t("Could not delete the %s.").t(),this.options.objectNameSingular.toLowerCase()),htmlResponse:e});i.show()}.bind(this))},this),n.on("hidden",function(){n.remove()},this),e("body").append(n.render().el),n.show()},"click a.endNow":function(i){i.preventDefault();var n=new s({id:"modal_endNow"});n.dialogShown=function(){this.trigger("show"),t.debounce(function(){this.$(".btn-primary:first").focus()}.bind(this),0)()},n.settings.set("primaryButtonLabel",t("End Now").t()),n.settings.set("cancelButtonLabel",t("Cancel").t()),n.settings.set("titleLabel",o.sprintf(t("End %s Now").t(),this.options.objectNameSingular)),n.setText(o.sprintf(t("Are you sure you want to end %s now?").t(),"<em>"+t.escape(this.model.savedPage.get("title"))+"</em>")),n.on("click:primaryButton",function(){var e=Date.now();this.model.savedPage.set({end_time:e/1e3}),this.model.savedPage.save().done(function(){n.hide()}.bind(this)).error(function(e){var i=new a({errorMessage:o.sprintf(t("Could not end the %s.").t(),this.options.objectNameSingular.toLowerCase()),htmlResponse:e});i.show()}.bind(this))},this),n.on("hidden",function(){n.remove()},this),e("body").append(n.render().el),n.show()},"click a.edit":function(t){t.preventDefault(),this._maintenanceWindowEditWorkflowView=new l({model:{application:this.model.application,savedPage:this.model.savedPage},collection:this.collection,redirectOnCreate:!0,mode:"edit"}),this._maintenanceWindowEditWorkflowView.show(),this._maintenanceWindowEditWorkflowView.render()}},render:function(){this.compiledTemplate=t.template(this.template,null,{variable:"vars"});var e={_:t,canEdit:!0,isActive:!0,isCompleted:!1},i=Date.now();return(i<1e3*this.model.savedPage.get("start_time")||i>1e3*this.model.savedPage.get("end_time"))&&(e.isActive=!1),i>1e3*this.model.savedPage.get("end_time")&&(e.isCompleted=!0),e.canEdit=this.model.savedPage.get("can_edit"),e.viewUrl=this.model.savedPage.getViewUrl(),this.$el.html(this.compiledTemplate(e,{variable:"vars"})),this.children.popdown=new n({el:this.$el}),this},template:'\t\t\t\t\t<% if (vars.canEdit) { %>\t\t\t\t\t<a class="dropdown-toggle" href="#"><%- _("Edit").t() %><span class="caret"></span></a>\t\t\t\t\t<div class="dropdown-menu dropdown-menu-narrow">\t\t\t\t\t\t<div class="arrow"></div>\t\t\t\t\t\t<% if (!vars.isCompleted) {%>\t\t\t\t\t\t\t<ul class="first-group">\t\t\t\t\t\t\t\t<li>\t\t\t\t\t\t\t\t\t<a href="#" class="edit"><%- _("Edit").t() %> </a>\t\t\t\t\t\t\t\t</li>\t\t\t\t\t\t\t</ul>\t\t\t\t\t\t<% } %>\t\t\t\t\t\t<ul class="second-group">\t\t\t\t\t\t\t<% if (vars.isActive) { %>\t\t\t\t\t\t\t\t<li>\t\t\t\t\t\t\t\t\t<a href="#" class="endNow"><%- _("End Now").t() %></a>\t\t\t\t\t\t\t\t</li>\t\t\t\t\t\t\t<% } %>\t\t\t\t\t\t\t<li>\t\t\t\t\t\t\t\t<a href="#" class="delete"><%- _("Delete").t() %></a>\t\t\t\t\t\t\t</li>\t\t\t\t\t\t</ul>\t\t\t\t\t</div>\t\t\t\t\t<% } else { %>\t\t\t\t\t\t<a href="<%- vars.viewUrl %>"><%- _("View").t() %> </a>\t\t\t\t\t<% } %>\t\t\t\t'});return c}.apply(e,n),!(void 0!==s&&(t.exports=s))},2778:function(t,e,i){var n,s;n=[i("require/underscore"),i(846)],s=function(t,e){var i=e.extend({initialize:function(i){i.bulkActions=[{value:"delete-select",text:t("Delete selected").t()}];var n=Date.now()/1e3;i.viewActions=[{value:"view-all",text:t("All").t()},{value:"view-active",text:t("Active").t(),collectionFilter:{start_time:{$lte:n},end_time:{$gte:n}}},{value:"view-scheduled",text:t("Scheduled").t(),collectionFilter:{start_time:{$gt:n}}},{value:"view-completed",text:t("Completed").t(),collectionFilter:{end_time:{$lt:n}}}],e.prototype.initialize.apply(this,arguments)}});return i}.apply(e,n),!(void 0!==s&&(t.exports=s))},2779:function(t,e,i){var n,s;n=[i("require/underscore"),i(841),i(863),i(129),i(237),i("models/services/server/ServerInfo"),i("shim/splunk.util")],s=function(t,e,i,n,s,a,o){var r=e.extend({events:{"click .add-page":function(t){if(t.preventDefault(),!this.options.addNewPageLink){var e=new i({model:{application:this.model.application,savedPage:this.model.savedPage},collection:this.collection,redirectOnCreate:!0,mode:"create",enableEntitySelection:this.enableEntitySelection});e.show(),e.render()}}},render:function(){this.enableEntitySelection=!1;var i=new a;i.fetch({success:function(){var a=o.make_url(["custom","SA-ITOA","itoa_interface","nobody","team",s.GLOBAL_SECURITY_GROUP_KEY].join("/"));n.getPermissionsForObject(a,i).then(function(e,i){var n=e[0].acl.write,s=i[0].entry[0].content.roles;if(n.length>0&&"*"===n[0]||s.indexOf("admin")!==-1)this.enableEntitySelection=!0;else{var a=t.find(n,function(e){return t.find(s,function(t){return e===t})});this.enableEntitySelection="undefined"!=typeof a&&a}}.bind(this)).always(function(){e.prototype.render.apply(this,arguments)}.bind(this))}.bind(this)})}});return r}.apply(e,n),!(void 0!==s&&(t.exports=s))},2780:function(t,e,i){var n,s;n=[i("require/underscore"),i("util/splunkd_utils"),i("views/Base"),i(231),i(887)],s=function(t,e,i,n,s){var a=i.extend({className:"list-dotted",tagName:"dl",initialize:function(){i.prototype.initialize.apply(this,arguments),this.affectedServicesAndEntities=this.model.savedPage.getAffectedServicesAndEntities(),this.affectedServices="",this.affectedEntities="",this._evaluateAffectedServicesList(),this._evaluateAffectedEntitiesList()},render:function(){return this.$el.html(this.compiledTemplate({_:t,affectedServices:this.affectedServices,affectedEntities:this.affectedEntities})),this},_evaluateAffectedServicesList:function(){var e=new n,i=e.getTitlesAndKeys(),s={};i.done(function(e){t.each(e,function(t){s[t._key]=t.title}),t.each(this.affectedServicesAndEntities.services,function(t){t in s&&(this.affectedServices+=s[t]+", ")}.bind(this)),0===this.affectedServices.length?this.affectedServices=t("None").t():this.affectedServices=this.affectedServices.slice(0,-2),this.render()}.bind(this)).fail(function(){console.log("serviceCollection fetch failed")})},_evaluateAffectedEntitiesList:function(){var e=new s,i=e.getTitlesAndKeys(),n={};i.done(function(e){t.each(e,function(t){n[t._key]=t.title}),t.each(this.affectedServicesAndEntities.entities,function(t){t in n&&(this.affectedEntities+=n[t]+", ")}.bind(this)),0===this.affectedEntities.length?this.affectedEntities=t("None").t():this.affectedEntities=this.affectedEntities.slice(0,-2),this.render()}.bind(this)).fail(function(){console.log("entityCollection fetch failed")})},template:'\t\t\t\t\t<dt class="entities"><%- _("Affected Services").t() %></dt>\t\t\t\t\t<dd>\t\t\t\t\t<%- affectedServices %>\t\t\t\t    </dd>\t\t\t\t\t<dt class="kpis"><%- _("Affected Entities").t() %></dt>\t\t\t\t\t<dd>\t\t\t\t\t\t<%- affectedEntities %>\t\t\t\t\t</dd>\t\t\t\t'});return a}.apply(e,n),!(void 0!==s&&(t.exports=s))},2781:function(t,e,i){var n,s;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i(856),i(857),i(901),i(1033)],s=function(t,e,i,n,s,a,o){var r=s.extend({initialize:function(e){e.extraHeaders=[{label:t("State").t()},{label:t("Start Time").t(),sortKey:"start_time"},{label:t("Duration").t()},{label:t("End Time").t(),sortKey:"end_time"}],e.enableBulkActions=!0,s.prototype.initialize.apply(this,arguments),this.model.state.on("change:bulkAction",function(){this.handleBulkAction(this.model.state.get("bulkAction"))}.bind(this))},handleBulkAction:function(t){switch(t){case"bulk-perms":this.editPermissions();break;case"delete-select":this.deleteRows()}},editPermissions:function(){var t=this.getBulkSelectionRows(),i=new o({tableRows:t,onHiddenRemove:!0,collection:this.collection,model:{application:this.model.application,savedPage:this.model.savedPage,user:this.model.user}});e("body").append(i.render().el),i.show()},deleteRows:function(){var t=this.getBulkSelectionRows(),i=new a({id:"modal_bulk_delete",deleteType:"delete-select",tableRows:t,objectNamePlural:this.model.savedPage.prototype.objectNamePlural,filterCreator:n.createJSONFilter});e("body").append(i.render().el),i.show()}});return r}.apply(e,n),!(void 0!==s&&(t.exports=s))}});