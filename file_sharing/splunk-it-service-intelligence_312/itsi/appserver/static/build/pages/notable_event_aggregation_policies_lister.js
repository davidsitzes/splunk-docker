webpackJsonp([28],{0:function(e,t,i){var n,s;i.p=function(){function e(){for(var e,i,n="",s=0,o=arguments.length;s<o;s++)e=arguments[s].toString(),i=e.length,i>1&&"/"==e.charAt(i-1)&&(e=e.substring(0,i-1)),n+="/"!=e.charAt(0)?"/"+e:e;if("/"!=n){var r=n.split("/"),a=r[1];if("static"==a||"modules"==a){var l=n.substring(a.length+2,n.length);n="/"+a,window.$C.BUILD_NUMBER&&(n+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(n+="."+window.$C.BUILD_PUSH_NUMBER),"app"==r[2]&&(n+=":"+t("APP_BUILD",0)),n+="/"+l}}var d=t("MRSPARKLE_ROOT_PATH","/"),u=t("DJANGO_ROOT_PATH",""),c=t("LOCALE","en-US"),p="";return p=u&&n.substring(0,u.length)===u?n.replace(u,u+"/"+c.toLowerCase()):"/"+c+n,""==d||"/"==d?p:d+p}function t(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return e("/static/app/itsi/build/pages")+"/"}(),n=[i("require/underscore"),i("shim/jquery"),i("util/router_utils"),i("splunkjs/mvc/utils"),i("shim/splunk.util"),i(129),i(148),i("models/services/server/ServerInfo"),i(473),i(401),i(841),i(2260),i(2259),i(2782),i(2783),i(2784),i(2785)],s=function(e,t,i,n,s,o,r,a,l,d,u,c,p,h,m,f,g){var v=u.extend({initialize:function(e){e=e||{},e.redirectOnCreate=!0,u.prototype.initialize.call(this,e)},events:{"click .add-page":function(e){e.preventDefault();var t=s.make_full_url("/app/itsi/notable_event_aggregation_policy_configuration_view");n.redirect(t,!1)}}}),b=new a;t.when(o.isUserCapableAllOps("notable_event_aggregation_policy"),b.fetch()).always(function(t){o.getUserModel(b).then(function(n){var s=n.entry[0].content.roles,a=r.getAuthorizedRolesForFeature("defaultNEAPEdit"),u=e.some(s,function(e){return a.indexOf(e)!==-1});t[0].permissions.writeDefaultNEAP=u,t[0].permissions.canEditPermissions=u;var b={collection:p,model:c,tableView:h,tableCaptionView:g,rowView:m,editMenu:f,title:e("Notable Event Aggregation Policies").t(),description:e("All aggregation policies for Notable Events").t(),CreateButtonView:v,permissions:t[0].permissions},w=(new d(b),o.checkJavaVersion());w.fail(function(t){var i=e("Java version installed on this search head does not support Aggregation Policies, Java version 1.7 or greater is required.").t();t=t||i;var n=new l({errorMessage:t,onHiddenRemove:!0});n.render(),n.show()}),i.start_backbone_history()}.bind(t))})}.apply(t,n),!(void 0!==s&&(e.exports=s))},2782:function(e,t,i){var n,s;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i("shim/splunk.util"),i(856),i(473),i(857),i(901),i(1033)],s=function(e,t,i,n,s,o,r,a,l){var d=r.extend({initialize:function(t){t=t||{},t.extraHeaders=[{label:e("Status").t()}],t.enableBulkActions=t.permissions.write,r.prototype.initialize.call(this,t),this.listenTo(this.model.state,"change:bulkAction",function(){this.handleBulkAction(this.model.state.get("bulkAction"))})},handleBulkAction:function(e){switch(e){case"delete-select":this.deleteRows();break;case"bulk-perms":this.editPermissions()}},editPermissions:function(){var e=this.getBulkSelectionRows(),i=new l({tableRows:e,onHiddenRemove:!0,collection:this.collection,model:{application:this.model.application,savedPage:this.model.savedPage,user:this.model.user},permUrl:n.make_url(["custom","SA-ITOA","event_management_interface",this.collection.savedPages._objectType,"perms"].join("/"))});t("body").append(i.render().el),i.show()},deleteRows:function(){var i=this.getBulkSelectionRows(),n=e.some(i,function(e){return 1===e.model.savedPage.get("is_default")});if(n){var r=new o({errorMessage:e("Cannot delete because the default policy is selected.").t()});return void r.show()}var l=new a({id:"modal_bulk_delete",deleteType:"delete-select",tableRows:i,objectNamePlural:this.model.savedPage.prototype.objectNamePlural,filterCreator:s.createJSONFilter});t("body").append(l.render().el),l.show()}});return d}.apply(t,n),!(void 0!==s&&(e.exports=s))},2783:function(e,t,i){var n,s;n=[i("shim/jquery"),i("require/underscore"),i("require/backbone"),i(473),i(853),i("shim/splunk.util")],s=function(e,t,i,n,s,o){var r=s.extend({initialize:function(e){e=e||{},e.extraHeaders=[{name:"status",value:""}],e.enableBulkActions=e.permissions.write,s.prototype.initialize.call(this,e)},events:{"click a.change_to_enabled":function(e){e.preventDefault(),this.updatePolicy(!1).fail(function(e){var i=o.sprintf(t("Could not enable %s.").t(),this.options.objectNameSingular.toLowerCase()),s=new n({errorMessage:i,htmlResponse:e});s.show(),console.log(i)}.bind(this))},"click a.change_to_disabled":function(e){e.preventDefault(),this.updatePolicy(!0).fail(function(e){var i=o.sprintf(t("Could not disable %s.").t(),this.options.objectNameSingular.toLowerCase()),s=new n({errorMessage:i,htmlResponse:e});s.show(),console.log(i)}.bind(this))}},updatePolicy:function(e){var t=this.model.savedPage.save({disabled:e?1:0});return t.done(function(){var t=this.getStatusString(e);this.$("td.status").html(t)}.bind(this)),t},_renderCheckbox:function(){this.options.enableBulkActions&&this.$(".box").append(this.children.bulkbox.render().el),this.model.savedPage.isDefault()&&this.children.bulkbox&&(this.children.bulkbox.disable(),this.children.bulkbox.off("select-all"))},getStatusString:function(e){var i;return i=e?this.options.permissions.write?t("Disabled").t()+' | <a href="#" class="change_to_enabled">'+t("Enable").t()+"</a>":t("Disabled").t():this.options.permissions.write?t("Enabled").t()+' | <a href="#" class="change_to_disabled">'+t("Disable").t()+"</a>":t("Enabled").t(),this.model.savedPage.get("is_default")&&(i=t("Enabled").t()),i},render:function(){var e=this.getStatusString(this.model.savedPage.get("disabled")||0);return s.prototype.render.apply(this),this.$("td.status").html(e),this}});return r}.apply(t,n),!(void 0!==s&&(e.exports=s))},2784:function(e,t,i){var n,s;n=[i("shim/jquery"),i("require/underscore"),i("require/backbone"),i("shim/splunk.util"),i(450),i(457),i("shim/splunk.util")],s=function(e,t,i,n,s,o,r){var a=s.extend({processModelBeforeClone:function(e){e.set({is_default:0,disabled:1})},onEditPerms:function(i){i.preventDefault();var s=this;this.model.savedPage.fetch({wait:!0,success:function(t){var i=new o({model:{document:s.model.savedPage,application:s.model.application,user:s.model.user},objectNameSingular:s.options.objectNameSingular,collection:s.collection.roles,onHiddenRemove:!0,permUrl:n.make_url(["custom","SA-ITOA","event_management_interface",t.collection._objectType,s.model.savedPage.id,"perms"].join("/"))});e("body").append(i.render().el),i.show()},error:function(e,i){console.log(r.sprintf(t("Error fetching %s with id: %s").t(),s.objectNameSingular.toLowerCase(),s.model.savedPage.id)),s._showFetchError(i)}})},render:function(){var e=this.getTemplateOptions();e.canChangePerms=e.permissions.write&&this.options.model.user.hasCapability("configure_perms"),this.model.savedPage.get("is_default")&&(e.modifiable=!1,e.canWrite=this.options.permissions.writeDefaultNEAP),this.setTemplateOptions(e),s.prototype.render.apply(this,arguments),this.model.savedPage.get("is_default")&&this.$(".first-group").eq(1).remove()}});return a}.apply(t,n),!(void 0!==s&&(e.exports=s))},2785:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,o,r=i(1022),a=n(r);s=[i("shim/jquery"),i("require/underscore"),i("require/backbone"),i(846)],o=function(e,t,i,n){var s=n.extend({tagName:"div",initialize:function(e){e=e||{},e.bulkActions=[];var i=e&&e.permissions&&e.permissions.canEditPermissions&&e.permissions.write||!1,s=e&&e.permissions&&e.permissions.delete||!1;e.bulkActions=[].concat((0,a.default)(i?[{value:"bulk-perms",text:t("Edit permissions").t(),disabled:!e.permissions.write}]:[]),(0,a.default)(s?[{value:"delete-select",text:t("Delete selected").t(),disabled:!e.permissions.delete}]:[])),0===e.bulkActions.length&&delete e.bulkActions,n.prototype.initialize.call(this,e)}});return s}.apply(t,s),!(void 0!==o&&(e.exports=o))}});