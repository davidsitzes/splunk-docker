webpackJsonp([13],{0:function(t,e,i){var n,r;i.p=function(){function t(){for(var t,i,n="",r=0,o=arguments.length;r<o;r++)t=arguments[r].toString(),i=t.length,i>1&&"/"==t.charAt(i-1)&&(t=t.substring(0,i-1)),n+="/"!=t.charAt(0)?"/"+t:t;if("/"!=n){var s=n.split("/"),a=s[1];if("static"==a||"modules"==a){var l=n.substring(a.length+2,n.length);n="/"+a,window.$C.BUILD_NUMBER&&(n+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(n+="."+window.$C.BUILD_PUSH_NUMBER),"app"==s[2]&&(n+=":"+e("APP_BUILD",0)),n+="/"+l}}var c=e("MRSPARKLE_ROOT_PATH","/"),u=e("DJANGO_ROOT_PATH",""),d=e("LOCALE","en-US"),p="";return p=u&&n.substring(0,u.length)===u?n.replace(u,u+"/"+d.toLowerCase()):"/"+d+n,""==c||"/"==c?p:c+p}function e(t,e){if(window.$C&&window.$C.hasOwnProperty(t))return window.$C[t];if(void 0!==e)return e;throw new Error("getConfigValue - "+t+" not set, no default provided")}return t("/static/app/itsi/build/pages")+"/"}(),n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i(888),i(4),i(1318),i(1323)],r=function(t,e,i,n,r,o,s){var a=r(t("Entity Definition").t()),l=a.urlTokenModel,c=l.get("id"),u=e(".dashboard-header").first(),d=new o;u.append(d.render().$el);var p,h=new n({_key:c});h.fetch().done(function(){p=new s({entity:h,el:e("#entity-definition-wrapper")}),p.render()})}.apply(e,n),!(void 0!==r&&(t.exports=r))},1318:function(t,e,i){var n,r;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i(1319),i(1320),i(1321)],r=function(t,e,i,n,r){var o=t.template(r),s=i.View.extend({tag:"div",clasName:"entity-bar",initialize:function(){i.View.prototype.initialize.apply(this,arguments)},events:{"click button.cancel-entity":function(){n.trigger("entdef-cancel-entity")},"click button.save-entity":function(){n.trigger("entdef-save-entity")}},render:function(){return this.$el.html(o()),this}});return s}.apply(e,n),!(void 0!==r&&(t.exports=r))},1319:function(t,e,i){var n,r;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone")],r=function(t,e,i){var n={};return t.extend(n,i.Events),n}.apply(e,n),!(void 0!==r&&(t.exports=r))},1320:function(t,e){t.exports='<div class="entity-definition-title">\n  <h2 class="entity-heading"><%- _(\'Entity Definition\').t() %></h2>\n</div>\n<div id="crud-controls" class="entity-controls">\n  <button class="btn cancel-entity"><%- _(\'Cancel\').t() %></button>\n  <button class="btn btn-primary save-entity"><%- _(\'Save\').t() %></button>\n</div>\n'},1321:function(t,e,i){var n=i(1322);"string"==typeof n&&(n=[[t.id,n,""]]);i(15)(n,{});n.locals&&(t.exports=n.locals)},1322:function(t,e,i){e=t.exports=i(14)(),e.push([t.id,".entity-header{height:40px;background:#d3d3d3;margin-bottom:0}.entity-bar{padding-right:20px;padding-left:20px;height:40px;position:relative}.entity-heading{display:block;float:left;padding-left:8px;font-size:24px;font-weight:200}.entity-controls{position:absolute;right:10px;font-size:12px}",""])},1323:function(t,e,i){var n,r;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),i(1319),i(888),i("views/shared/Modal"),i("splunkjs/mvc/utils"),i("uri/route"),i("shim/splunk.util"),i("views/shared/controls/ControlGroup")],r=function(t,e,i,n,r,o,s,a,l,c){var u=i.View.extend({initialize:function(t){t=t||{},this.setEntity(t.entity||new r)},render:function(){this.$el.html("<p>"+l.sprintf(t("Entity summary for %s"),this._entity.get("title"))+":</p>"),this.$el.html("<p>"+t("Loading services for entity...").t()+"</p>"),this.controls={};var e=l.sprintf(t("Entity summary for %s:").t(),this._entity.get("title")),i=t("The entity contains information that associates services with information found in datamodels and searches. This information allows or filters out specific inventory items or application processes per the entity specification").t();return this.$el.html("<p>"+e+"</p>"),this.$el.append("<p>"+i+"</p>"),this.controls.name=new c({controlType:"Text",controlOptions:{modelAttribute:"title",model:this._entity,save:!1},label:t("Entity Name").t()}),this.controls.services=new c({controlType:"Text",controlOptions:{modelAttribute:"services",model:this._entity,save:!1},tooltip:t("The service to associate these entities with, optional").t(),label:t("Service").t()}),this.$el.append('<div class="form form-horizontal entity-info-controls"></div>'),this.$(".entity-info-controls").append(this.controls.name.render().el).append(this.controls.entity_type.render().el).append(this.controls.services.render().el),this.listenTo(n,"entdef-save-entity",function(){this.saveEntity()}),this.listenTo(n,"entdef-cancel-entity",function(){this.cancelEntity()}),this},events:{"click a.run-search":function(t){t.preventDefault();var e=[],i=e.join(" OR "),n={q:i,earliest:"-60m",latest:"now"},r=s.getPageInfo(),o=a.search(r.root,r.locale,r.app,{data:n});s.redirect(o,!0)}},_getReturnUrl:function(){return(window.location.origin+l.make_url(l.getPath())).replace(/\/[^\/]+$/,"/entities_lister")},getEntity:function(){return this._entity},setEntity:function(t){return this._entity=t,this._entity},saveEntity:function(){if(!this._entity)throw new Error("No valid entity to save");if(!Array.isArray(this._entity.get("services"))){for(var t=this._entity.get("services").split(","),i=0;i<t.length;i++)t[i]=e.trim(t[i]);this._entity.set("services",t)}var n=!1;if(n)return alert("Validation Error"),!1;var r=this._entity.save();return r.fail(function(){alert("Failed to save entity.")}.bind(this)),r.done(function(){s.redirect(this._getReturnUrl())}.bind(this)),r},cancelEntity:function(){s.redirect(this._getReturnUrl())}});return u}.apply(e,n),!(void 0!==r&&(t.exports=r))}});