webpackJsonp([12],{0:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,a;i.p=function(){function e(){for(var e,i,n="",s=0,a=arguments.length;s<a;s++)e=arguments[s].toString(),i=e.length,i>1&&"/"==e.charAt(i-1)&&(e=e.substring(0,i-1)),n+="/"!=e.charAt(0)?"/"+e:e;if("/"!=n){var o=n.split("/"),l=o[1];if("static"==l||"modules"==l){var r=n.substring(l.length+2,n.length);n="/"+l,window.$C.BUILD_NUMBER&&(n+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(n+="."+window.$C.BUILD_PUSH_NUMBER),"app"==o[2]&&(n+=":"+t("APP_BUILD",0)),n+="/"+r}}var c=t("MRSPARKLE_ROOT_PATH","/"),d=t("DJANGO_ROOT_PATH",""),u=t("LOCALE","en-US"),h="";return h=d&&n.substring(0,d.length)===d?n.replace(d,d+"/"+u.toLowerCase()):"/"+u+n,""==c||"/"==c?h:c+h}function t(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return e("/static/app/itsi/build/pages")+"/"}();var o=i(130),l=n(o);s=[i("require/underscore"),i("shim/jquery"),i("util/router_utils"),i(888),i(887),i(1314),i(1279),i(1292),i(1296),i(1295),i(1311),i(1312),i(1313)],a=function(e,t,i,n,s,a,o,r,c,d,u,h,p){var f=s.extend({getCount:function(e){return e=this.augmentFilter(e),s.prototype.getCount.apply(this,[e])},fetch:function(e){return e=this.augmentFilter(e),s.prototype.fetch.apply(this,[e])},augmentFilter:function(e){if(e=e||{},e.data=e.data instanceof Object?e.data:{},e.data.filter){var t=JSON.parse(e.data.filter);e.data.filter=(0,l.default)(t)}return e}}),m={collection:f,model:n,titleView:o,tableView:r,tableCaptionView:c,headView:d,rowView:u,editMenu:h,infoDetails:p,title:e("Entities").t(),description:e("Viewer for all Entities").t()};new a(m);i.start_backbone_history()}.apply(t,s),!(void 0!==a&&(e.exports=a))},1279:function(e,t,i){var n,s;n=[e,i("require/underscore"),i(840),i(1280)],s=function(e,t,i,n){var s=i.extend({moduleId:String(e.id),initialize:function(e){e.CreateButtonView=n,i.prototype.initialize.apply(this,arguments)},render:function(){return i.prototype.render.apply(this,arguments),this}});return s}.apply(t,n),!(void 0!==s&&(e.exports=s))},1280:function(e,t,i){var n,s;n=[i("shim/jquery"),i("require/underscore"),i(841),i("shim/splunk.util"),i(231),i(1281),i(888),i(887),i(905)],s=function(e,t,i,n,s,a,o,l,r){var c=i.extend({initialize:function(e){e.model.savedPage=o,e.collection=l,e.permissions.canSeeBulkImportDropdownOptions&&(e.importCsvLink=n.make_full_url(["app","itsi","service_importer#importcsv"].join("/"),{originType:"entity",importType:"importcsv"}),e.importSearchLink=n.make_full_url(["app","itsi","service_importer#search"].join("/"),{originType:"entity",importType:"search"})),i.prototype.initialize.call(this,e)},events:{"click .add-page":function(t){t.preventDefault();var i=r.fetchServices();e.when(i).done(function(){new a({model:{savedPage:this.model.savedPage},collection:{savedPages:this.collection,services:r.serviceIdTitleMap},onHiddenRemove:!0,addAction:!0}).render().show()}.bind(this))}}});return c}.apply(t,n),!(void 0!==s&&(e.exports=s))},1292:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,a,o=i(130),l=n(o);s=[e,i("require/underscore"),i("shim/jquery"),i(856),i(473),i(857),i(901),i(1293),i(1295),i(1296),i(1309)],a=function(e,t,i,n,s,a,o,r,c,d){var u=a.extend({moduleId:String(e.id),initialize:function(e){e.hideTableDock=!0,e.enableBulkActions=!0,a.prototype.initialize.apply(this,arguments),this.model.state.on("change:bulkAction",function(){var e={"delete-select":"deleteRows","edit-select":"editRows","maintenance-mode-select":"putSelectedEntitiesInMaintenanceMode"},i=this.model.state.get("bulkAction");return t.contains(t.keys(e),i)&&t.isFunction(this[e[i]])?void this[e[i]](i):void console.warn("Requested bulk action "+i+" has no handler in EntityListerTableView")}.bind(this)),this.children.head=new c({model:this.model.state,customViews:this.options.customViews,collection:this.collection.savedPages}),this.children.caption&&this.stopListening(this.children.caption,"advanced-filters-change"),this.children.caption=new d({model:{savedPage:this.model.savedPage,savedPageCollection:this.collection,state:this.model.state,application:this.model.application,uiPrefs:this.model.uiPrefs,tableColumns:this.options.customViews.tableColumnsCollection},collection:this.collection.savedPages,noFilter:!1,filterKey:["title"]}),this.listenTo(this.children.caption,"advanced-filters-change",function(e){this.model.state.set("offset",0),this.collection.savedPages.offset=0,this.collection.savedPages.trigger("refresh",e)}.bind(this)),this.listenTo(this.options.customViews.tableColumnsCollection,"add remove update reset sort",t.debounce(function(){var e=this.model.state.get("filterObj").filterString,t='{"shared":"true"}',i={};if(e){var n=(0,l.default)(this.createJSONFilter(e));e&&(t='{"shared":"true","filter_string":'+n+"}")}i.filter=t,this.collection.savedPages.fetch({data:i})}.bind(this)))},createJSONFilter:function(e){return n.createEntityJSONFilter("string"==typeof e?e.toLowerCase():e,this.serviceTitleIds)},editRows:function(e){var a=this.getBulkSelectionRows();if(0===a.length){var o=new s({errorMessage:t("Select at least one entity to edit.").t()});return void o.show()}var l=new r({id:"modal_bulk_edit",collection:this.collection,action:e,tableRows:this.getBulkSelectionRows(),onHiddenRemove:!0,filterCreator:n.createEntityJSONFilter});i("body").append(l.render().el),l.show()},deleteRows:function(e){var t=this.getBulkSelectionRows(),s=new o({id:"modal_bulk_delete",deleteType:e,tableRows:t,objectNamePlural:this.model.savedPage.prototype.objectNamePlural,filterCreator:n.createEntityJSONFilter});i("body").append(s.render().el),s.show()},putSelectedEntitiesInMaintenanceMode:function(){if(0===this.getBulkSelectionRows().length){var e=new s({errorMessage:t("Select at least one entity to put in maintenance mode.").t()});e.show()}else this.putSelectedInMaintenanceMode("entity")}});return u}.apply(t,s),!(void 0!==a&&(e.exports=a))},1293:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,a,o=i(130),l=n(o);s=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),e,i("views/shared/Modal"),i("views/shared/FlashMessagesLegacy"),i("collections/shared/FlashMessages"),i(129),i(902),i(1282),i(1283),i(1284),i(905),i("shim/splunk.util"),i(1294),i(1285)],a=function(e,t,i,n,s,a,o,r,c,d,u,h,p,f,m){var v=s.extend({moduleId:String(n.id),className:"add-entity-modal "+s.CLASS_NAME,initialize:function(t){s.prototype.initialize.apply(this,arguments),this.entities=new i.Collection(e.map(t.tableRows,function(e){return e.model.savedPage})),this.readOnlyMode=this.options.readOnlyMode||!1,this.infoCollection=new d(v.findTagsInCommon(this.entities)),this.restrictedTags=e.difference(v.getOptTagKeys(this.entities),this.infoCollection.pluck("field")),this.loadingMask=new c,this.flashMessagesCollection=new o,this.flashMessagesLegacy=new a({collection:this.flashMessagesCollection})},events:e.extend({},s.prototype.events,{"click a.add-info":"addEntityKeyValueView","click .modal-btn-primary":"maybeCommitEdits"}),addEntityKeyValueView:function(e){e.preventDefault();var t=new u,i=new h({model:{kvModel:t}});this.infoCollection.add(t),this.$(".info-inputs",this.$el).append(i.render().el)},buildUpload:function(t){return this.entities.each(function(e){e.trigger("entity-update-saved",e)}),{entities:this.entities.toJSON(),update:e.pick(t,["attributes","fields","values"])}},createUpdate:function(){var t=e.compose(e.partial(e.filter,e,function(t){return!e.isUndefined(t)&&!e.isEmpty(t)}),e.partial(e.map,e,function(e){return e.trim()}),function(e){return e.split(",")}),i=function(t,i){return e.object(e.map(t,function(e){return[e,i]}))};return this.infoCollection.reduce(function(n,s){var a=t(s.get("field")),o=t(s.get("value"));return o.length&&a.length&&(n.fields=n.fields.concat(a),n.values=e.union(n.values,o),n.attributes=e.extend(n.attributes,i(a,o))),o.length&&0===a.length&&(n.blank_fields=n.blank_fields.concat(o)),0===o.length&&a.length&&(n.blank_values=n.blank_values.concat(a)),n},{attributes:{},fields:[],values:[],blank_fields:[],blank_values:[]})},validateTagCollection:function(t){var i=function(e){return/^\$/.test(e)},n=function(e){return/[=.,"\']/.test(e)},s=v.getAnyDuplicated(t.fields),a=e.intersection(t.fields,v.ITSI_INTERNAL_KEYWORDS),o=e.intersection(t.fields,this.restrictedTags),l=e.filter(t.fields,i),r=e.filter(t.fields,n),c=e('Field name "<%- v %>" appears multiple times"').t(),d=e('Field name cannot match internal keyword "<%- v %>"').t(),u=e('Field name "<%- v %>" exists but is not the same for these entities, cannot be modified').t(),h=e('Field name "<%- v %>" starts with illegal character').t(),p=e('Field name "<%- v %>" contains illegal character').t(),f=e('Field name cannot be blank for value "<%- v %>"').t(),m=e('Values cannot be left blank for field "<%- v %>"').t(),g=function(t,i){return e.map(t,function(t){return e.template(i,{v:t})})},b=e.union([].concat(g(s,c)).concat(g(a,d)).concat(g(o,u)).concat(g(l,h)).concat(g(r,p)).concat(g(t.blank_fields,f)).concat(g(t.blank_values,m))),w=e.partial(e.map,e,function(e,t){return{key:"invalidinformational"+t,type:"error",html:e}});return w(b)},checkForValidationFailure:function(e){var t=this.validateTagCollection(e);return this.$(".control-group-info").removeClass("error"),t.length>0&&this.$(".control-group-info").addClass("error"),this.flashMessagesCollection.reset(t),t.length>0},postData:function(e){var i=t.Deferred(),n=(0,l.default)(this.buildUpload(e)),s=f.make_url(["custom","SA-ITOA","itoa_interface","nobody","entity","bulk_entities_update"].join("/"));return t.ajax({url:s,type:"POST",data:{data:n},contentType:"application/x-www-form-urlencoded",dataType:"json",success:function(e){i.resolve(e)},error:function(e,t,n){i.reject([n,r.extractErrorMsgFromResponse(e)])}}),i},handleSuccessfulWrite:function(){this.flashMessagesCollection.reset();var e=function(){this.hide(),this.remove(),this.loadingMask.hide(),this.entities.each(function(e){e.trigger("entity-update-saved",e)})}.bind(this);t.when(this.collection.savedPages.fetch({reset:!0})).then(e)},handleFailedWrite:function(t,i){this.flashMessagesCollection.reset([{key:"restfailure",type:"error",html:f.sprintf(e("Saving entity changes failed. Details: %s").t(),i)}]),this.loadingMask.hide(),this.$(s.FOOTER_SELECTOR+" .btn.btn-primary.modal-btn-primary").removeClass("disabled")},maybeCommitEdits:function(e){e.preventDefault(),this.$(s.FOOTER_SELECTOR+" .btn.btn-primary.modal-btn-primary").addClass("disabled");var i=this.createUpdate();return this.checkForValidationFailure(i)?void this.$(s.FOOTER_SELECTOR+" .btn.btn-primary.modal-btn-primary").removeClass("disabled"):(t(".main-section-body").first().append(this.loadingMask.render().$el),this.loadingMask.show(""),void t.when(this.postData(i)).done(this.handleSuccessfulWrite.bind(this)).fail(this.handleFailedWrite.bind(this)))},renderModal:function(){return this.$(s.BODY_SELECTOR).html(this.flashMessagesLegacy.render().el),this.$(s.BODY_SELECTOR).append(s.FORM_HORIZONTAL),this.$(s.BODY_FORM_SELECTOR).append(v.entityTemplateMarkup),this.$(".info-inputs").append(this.infoCollection.map(function(e){return new h({model:{kvModel:e}}).render().el})),this.readOnlyMode&&(this.$(s.BODY_SELECTOR+" :input").each(function(e,i){t(i).attr("disabled","disabled")}),this.$(s.BODY_SELECTOR).find("a").each(function(e,i){t(i).hide()})),this},render:function(){this.$el.html(s.TEMPLATE),this.$(s.HEADER_TITLE_SELECTOR).html(f.sprintf(e("Update %s %s").t(),this.entities.length,this.entities.length>1?e("entities").t():e("entity").t()));var t=this.$(s.FOOTER_SELECTOR);return t.append(s.BUTTON_CANCEL),t.append(s.BUTTON_SAVE),this.renderModal(),this}},{ITSI_INTERNAL_KEYWORDS:["title","_key","services","description","informational","identifier","create_by","create_time","create_source","mod_by","mod_time","mod_source","object_type","_type","_owner","_user","identifying_name"],findTagsInCommon:function(t){var i=function(e){return function(t,i){var n=e.get(i).toString();return t[i]=t[i]||{count:0,values:{}},t[i].values[n]=t[i].values[n]||0,t[i].count++,t[i].values[n]++,t}},n=function(t,n){var s=n.get("informational");return e.reduce(s.fields,i(n),t)},s=function(i){var n=i[1],s=e.keys(n.values);return n.count===t.length&&1===s.length&&n.values[s[0]]===t.length},a=function(t){var i=t[1],n=e.keys(i.values)[0];return{field:t[0],value:n}},o=e.pairs(t.reduce(n,{}));return e.map(e.filter(o,s),a)},getOptTagKeys:function(t){return e.uniq(e.flatten(e.map(["informational","identifier"],function(e){return t.map(function(t){return(t.get(e)||{}).fields||[]})})))},getAnyDuplicated:function(t){return e.chain(t).countBy(e.id).pairs().filter(function(e){return 1!==e[1]}).pluck(0).value()},entityTemplateMarkup:e.template(m,{_:e})});return v}.apply(t,s),!(void 0!==a&&(e.exports=a))},1294:function(e,t){e.exports='<div class="control-group control-group-info">\n\t<label for="#" class="control-label"><%- _("Common Info Fields").t() %></label>\n\t<div class="controls">\n\t\t<div class="info-inputs" style="margin-top: 5px;"></div>\n\t\t<a href="#" class="icon-plus add-info"><%- _("add info field").t() %></a>\n\t</div>\n</div>\n'},1295:function(e,t,i){var n,s;n=[i("require/underscore"),e,i("views/shared/TableHead"),i("views/shared/controls/ControlGroup"),i("views/shared/controls/SyntheticCheckboxControl")],s=function(e,t,i,n,s){var a=i.extend({moduleId:String(t.id),startListening:function(){i.prototype.startListening.apply(this,arguments),this.columns=this.options.customViews.tableColumnsCollection,this.listenTo(this.columns,"add remove update reset sort",this.debouncedRender)},render:function(){this.$el.html(this.compiledTemplate({_:e,columns:this.columns.renderHeaders(),model:this.model.state})),this.bulkboxControl=new s({modelAttribute:"selectAll",model:this.model.state,checkboxClassName:"btn lister-page"}),this.children.bulkbox=new n({controls:[this.bulkboxControl],controlClass:"lister-page"});var t=function(){this.bulkboxControl.setValue(!1)}.bind(this);return this.listenTo(this.collection,"refresh",t),this.options.checkboxClassName&&(this.children.checkbox&&this.children.checkbox.remove(),this.children.checkbox=new s({modelAttribute:"selectAll",model:this.model.state}),this.children.checkbox.render().appendTo(this.$("."+this.options.checkboxClassName))),this.columns.chain().filter(function(e){return e.has("tooltip")}).each(function(e){this.$("."+e.get("className")).find(".column-tooltip").tooltip({animation:!1,title:e.get("tooltip"),container:"body"})}.bind(this)).value(),this.$(".bulk-checkbox").append(this.children.bulkbox.render().el),this},setAllSelected:function(e,t){this.bulkboxControl.setValue(e,!0,{silent:t})}});return a}.apply(t,n),!(void 0!==s&&(e.exports=s))},1296:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,a,o=i(130),l=n(o);s=[i("require/underscore"),i("require/backbone"),e,i("shim/jquery"),i(887),i(846),i(1297),i(1308),i("views/shared/controls/ControlGroup")],a=function(e,t,i,n,s,a,o,r,c){var d=a.extend({moduleId:String(i.id),tagName:"div",initialize:function(i){i.hideTableDock=!0,i.bulkActions=[{value:"maintenance-mode-select",text:e("Put selected in Maintenance Mode").t()},{value:"delete-select",text:e("Delete selected").t()},{value:"edit-select",text:e("Edit selected").t()}],this.urlWithoutFilters=(new s).url,this.urlWithFilters=Splunk.util.make_url(["custom","SA-ITOA","itoa_interface","get_entity_filter","nobody"].join("/")),this._entityRulesContainer=new t.Model({}),this.specifyEntityRulesView=new o({rulesContainerModel:this._entityRulesContainer}),this.listenTo(this.specifyEntityRulesView,"ruleschange",this._rulesChanged),this.listenTo(this.specifyEntityRulesView,"height-update",this._containerHeightChanged),this.children.perPageView=new c({controlType:"SyntheticSelect",controlOptions:{model:this.model.state,modelAttribute:"count",items:[{value:10,label:e("10 Per Page").t()},{value:20,label:e("20 Per Page").t()},{value:50,label:e("50 Per Page").t()},{value:100,label:e("100 Per Page").t()}],popdownOptions:{attachDialogTo:"body"}}}),i.advancedFilterView=this.specifyEntityRulesView,a.prototype.initialize.apply(this,arguments),this.options.collection.on("add",function(e){e.on("entity-update-saved",function(){this.specifyEntityRulesView.handleEntityUpdate()}.bind(this))}.bind(this))},events:function(){return e.extend({},a.prototype.events,{"click .edit-visible-columns":"_showColumnEditor"})},_showColumnEditor:function(e){e.preventDefault();var t=new r({tableRows:this.collection,columns:this.model.tableColumns}).render().show();return t},_containerHeightChanged:function(){this.trigger("advanced-filter-height-update")},_rulesChanged:function(e,t){var i,n=0===t.length,s=this.urlWithoutFilters;n||(s=this.urlWithFilters,i=t.toJSON()),this.trigger("advanced-filters-change",{advancedFilterUrl:s,urlPayload:{entity_filter:i?(0,l.default)(i):i},isFilterInEffect:!n})},render:function(){a.prototype.render.apply(this,arguments);var t=this.children.perPageView.render().$el;return t.addClass("perpageview pull-right"),this.$(".pagination").after(t),this.$(".control-group",t).css({"line-height":"26px"}),this.$(".bulk-dropdown").after('<a href="#" class="edit-visible-columns pull-left">'+e("Edit Columns").t()+"</a>"),this}});return d}.apply(t,s),!(void 0!==a&&(e.exports=a))},1308:function(e,t,i){var n,s;n=[i("require/underscore"),i("shim/jquery"),i("require/backbone"),e,i("views/shared/Modal"),i("views/shared/FlashMessagesLegacy"),i("collections/shared/FlashMessages"),i("views/shared/controls/SyntheticCheckboxControl")],s=function(e,t,i,n,s,a,o,l){var r=[["other",e("Default Fields").t()],["identifier",e("Aliases").t()],["informational",e("Info Fields").t()]],c=e.object(e.map(r,function(e,t){return[e[0],t]})),d=e.map(r,function(e){return{field:e[0],title:e[1]}}),u=i.Collection.extend({comparator:function(e,t){return u.cmp(c[e.get("type")]||0,c[t.get("type")]||0)||u.cmp(e.get("name"),t.get("name"))}},{cmp:function(e,t){return e<t?-1:e===t?0:1}}),h=s.extend({moduleId:String(n.id),initialize:function(t){s.prototype.initialize.apply(this,arguments),this.columns=t.columns;var i=function(t,i){return e.map((t.get(i)||{}).fields||[],function(e){return i+":"+e})},n=this.columns.chain().filter(function(e){return e.editable()&&!e.get("dynamic")}).map(function(e){return"other:"+e.get("name")}).value(),l=e.uniq(e.flatten(t.tableRows.map(function(e){return i(e,"informational").concat(i(e,"identifier"))}))).concat(n),r=e.map(this.columns.visible(),function(e){return e.get("name")});return this.collection=new u(e.map(l,function(t){var i=t.split(":",2);return{type:i[0],name:i[1],active:e.contains(r,i[1])}})),this.flashMessagesCollection=new o,this.flashMessagesLegacy=new a({collection:this.flashMessagesCollection}),this},events:e.extend({},s.prototype.events,{"click .modal-btn-primary":"commitEdits"}),commitEdits:function(t){t.preventDefault();var i=function(t){return t=t.replace("_"," "),t=e.map(t.split(" "),function(e){return e.charAt(0).toUpperCase()+e.slice(1)}),t=e.map(t,function(t){return e.contains(["Id","Dns","Ip","Cpu"],t)?t.toUpperCase():t}),t.join(" ")},n=e.map(this.columns.local(),function(e){return e.get("name")});this.columns.reset(this.collection.chain().filter(function(e){return e.get("active")}).filter(function(t){return!e.contains(n,t.get("name"))}).map(function(t){var n=t.get("name");return{label:i(n),name:n,value:function(){var t=this.model.savedPage.get(n);return e.isArray(t)?t.join(", "):t},sortKey:n,editable:!0,dynamic:!0}}).value(),{silent:!0}),this.collection.chain().filter(function(t){return e.contains(n,t.get("name"))}).each(function(e){var t=this.columns.findWhere({name:e.get("name")});t.set("visible",e.get("active"),{silent:!0})}.bind(this)).value(),this.columns.trigger("reset",this.collection),this.hide(),this.remove()},render:function(){this.$el.html(s.TEMPLATE),this.$(s.HEADER_TITLE_SELECTOR).html(e("Edit Visible Columns").t());var t=this.$(s.FOOTER_SELECTOR);t.append(s.BUTTON_CANCEL),t.append(s.BUTTON_SAVE),this.$(s.BODY_SELECTOR).html(this.flashMessagesLegacy.render().el),this.$(s.BODY_SELECTOR).append(s.FORM_HORIZONTAL),this.$(s.BODY_FORM_SELECTOR).append(e.template(h._template,{})),e.each(d,function(e){var t=new u(this.collection.where({type:e.field}));t.length&&this.$(".column-fieldnames").append("<h4>"+e.title+"<h4>",t.map(function(e){return new l({model:e,modelAttribute:"active",label:e.get("name")}).render().el}))},this)}},{_template:['<div class="control-group control-group-info">','    <div class="controls">','        <div class="column-fieldnames" style="margin-top: 5px;"></div>',"    </div>","</div>"].join("\n")});return h}.apply(t,n),!(void 0!==s&&(e.exports=s))},1309:function(e,t,i){var n=i(1310);"string"==typeof n&&(n=[[e.id,n,""]]);i(15)(n,{});n.locals&&(e.exports=n.locals)},1310:function(e,t,i){t=e.exports=i(14)(),t.push([e.id,".edit-visible-columns{line-height:36px;padding-left:2em}",""])},1311:function(e,t,i){var n,s;n=[e,i("shim/jquery"),i(853),i(905),i(1281)],s=function(e,t,i,n,s){var a=i.extend({initialize:function(e){e.enableBulkActions=!0,this.model.savedPage.on("edit_param_change",function(){this.render()},this),i.prototype.initialize.apply(this,arguments)},render:function(){var e=this.model.savedPage.hasAcl?this.model.savedPage.get("acl").owner:null,i=this.options.customViews.tableColumnsCollection;return this._extraHeaders=i.renderColumnsWith(this),t(".loading-table-rows").hide(),this.renderRow(e),this.children.editmenu&&this.children.editmenu.delegateEvents(),this.$(".actions").append(this.children.editmenu.render().el),this.updateSharing(),this.setSecurityGroupTitle(),this},events:{"click a.edit-row":function(e){e.preventDefault();var i=n.fetchServices(),a=this;t.when(i).done(function(){new s({model:{savedPage:a.model.savedPage},collection:{savedPages:a.collection,services:n.serviceIdTitleMap},objectNameSingular:a.options.objectNameSingular,onHiddenRemove:!0,addAction:!1}).render().show()})}}});return a}.apply(t,n),!(void 0!==s&&(e.exports=s))},1312:function(e,t,i){function n(e){return e&&e.__esModule?e:{default:e}}var s,a,o=i(130),l=n(o);s=[i("require/underscore"),i("require/backbone"),e,i("shim/jquery"),i(148),i("views/Base"),i("views/shared/delegates/Popdown"),i("views/shared/dialogs/TextDialog"),i("shim/splunk.util"),i("uri/route"),i("models/Base"),i("models/ACLReadOnly"),i(231),i(888),i(862),i(838),i(905),i(863),i(1281),i(473)],a=function(e,t,i,n,s,a,o,r,c,d,u,h,p,f,m,v,g,b,w,y){var _=a.extend({moduleId:String(i.id),initialize:function(e){a.prototype.initialize.apply(this,arguments),this._savedPagesCollection=e.collection.savedPages},className:"dropdown",events:{"click a.maintenance":function(e){e.preventDefault(),this._putEntityInMaintenanceMode()},"click a.delete":function(e){e.preventDefault(),this._deleteEntity()},"click a.edit":function(e){e.preventDefault(),this._editEntity()}},_putEntityInMaintenanceMode:function(){var e=[],t={_key:this.model.savedPage.get("_key"),object_type:s.ITSI_OBJECT_ENTITY};e.push(t),this._maintenanceWindowModel=new m({objects:e}),this._maintenanceWindowCreateWorkflowView=new b({model:{savedPage:this._maintenanceWindowModel},redirectOnCreate:!0,mode:"create",preselectObject:s.ITSI_OBJECT_ENTITY}),this._maintenanceWindowCreateWorkflowView.show(),this._maintenanceWindowCreateWorkflowView.render()},_deleteEntity:function(){this.model.savedPage.fetch({wait:!0,success:function(){var e=new v({id:"modal_delete",objectNameSingular:this.options.objectNameSingular,savePage:this.model.savedPage,stateModel:this.model.state,savedPagesCollection:this._savedPagesCollection});n("body").append(e.render().el),e.show()}.bind(this),error:function(t){var i=c.sprintf(e("Could not delete the %s.").t(),this.options.objectNameSingular.toLowerCase()),n=new y({errorMessage:i,htmlResponse:t});n.show(),console.log(i)}.bind(this)})},_editEntity:function(){var e=g.fetchServices();n.when(e).done(function(){new w({model:{savedPage:this.model.savedPage},collection:{savedPages:this.collection,services:g.serviceIdTitleMap},onHiddenRemove:!0,addAction:!1}).render().show()}.bind(this))},_cloneEntity:function(){this.model.savedPage.fetch({success:function(){var e=new f(JSON.parse((0,l.default)(this.model.savedPage.toJSON())),{parse:!0});if(e.unset(f.prototype.idAttribute),e.unset("services"),e.unset("sec_grp"),this.model.savedPage.hasAcl){var i=new t.Model(JSON.parse((0,l.default)(this.model.savedPage.get("acl").toJSON())),{parse:!0});i.owner=this.model.application.get("owner"),e.set("acl",i)}var n=new w({model:{savedPage:e},collection:{savedPages:this.collection.savedPages,services:g.serviceIdTitleMap},onHiddenRemove:!0,addAction:!0});n.render().show()}.bind(this),error:function(t,i){var n=c.sprintf(e("Could not clone the %s.").t(),this.options.objectNameSingular.toLowerCase()),s=new y({errorMessage:n,htmlResponse:i});s.show(),console.log(n)}.bind(this)})},render:function(){var t=(!this.model.savedPage.hasAcl||this.model.savedPage.get("acl").can_write)&&this.model.savedPage.canWrite(),i={_:e,savedPage:this.model.savedPage,app:this.model.application.get("app"),view:this.model.savedPage.get("title"),returnTo:encodeURIComponent(window.location.pathname),canWrite:t,modifiable:!this.model.savedPage.hasAcl||this.model.savedPage.get("acl").modifiable,savedPageLink:d.page(this.model.application.get("root"),this.model.application.get("locale"),this.model.application.get("app"),this.model.application.get("name")),savedPageId:this.model.savedPage.id,editUrl:this.model.savedPage.getEditUrl()};return this.$el.html(this.compiledTemplate(i)),this.children.popdown=new o({el:this.$el}),this},template:'\t\t\t\t\t<% if (canWrite) { %>\t\t\t\t\t\t<a class="dropdown-toggle" href="#"><%- _("Edit").t() %><span class="caret"></span></a>\t\t\t\t\t\t<div class="dropdown-menu">\t\t\t\t\t\t\t<div class="arrow"></div>\t\t\t\t\t\t\t<ul class="first-group">\t\t\t\t\t\t\t\t<li><a href="#" class="edit"><%- _("Edit").t() %> </a></li>\t\t\t\t\t\t\t</ul>\t\t\t\t\t\t\t<% if (modifiable) { %>\t\t\t\t\t\t\t<ul class="second-group">\t\t\t\t\t\t\t\t<li><a href="#" class="maintenance"><%- _("Put Entity in Maintenance Mode").t() %></a></li>\t\t\t\t\t\t\t\t<li><a href="#" class="delete"><%- _("Delete").t() %></a></li>\t\t\t\t\t\t\t</ul>\t\t\t\t\t\t\t<% } %>\t\t\t\t\t\t</div>\t\t\t\t\t<% } else { %>\t\t\t\t\t\t<a href="#" class="edit"><%- _("View").t() %> </a>\t\t\t\t\t<% } %>\t\t\t\t'});return _}.apply(t,s),!(void 0!==a&&(e.exports=a))},1313:function(e,t,i){var n,s;n=[i("require/underscore"),e,i("util/splunkd_utils"),i("views/Base")],s=function(e,t,i,n){return n.extend({moduleId:String(t.id),className:"list-dotted",tagName:"dl",initialize:function(){n.prototype.initialize.apply(this,arguments),this.listenTo(this.model.savedPage,"change change:acl",this.render)},render:function(){var t,n,s,a=this.model.savedPage.hasAcl,o=this.model.savedPage.get("mod_time"),l=this.model.application.get("app");if(a){var r=this.model.savedPage.get("acl").sharing;t=this.model.savedPage.get("acl").owner,n=i.getPermissionLabel(r,t),s=this.model.savedPage.get("acl").can_change_perms}return this.$el.html(this.compiledTemplate({_:e,owner:t,permissionString:n,canChangePerms:s,appString:l,hasAcl:a,modTime:o,canUseApps:!0})),e.defer(function(){var e=this.$el.closest("table"),t=e.find(".table-head tr th").length-1;e.find("td.details").attr("colspan",t)}.bind(this)),this},template:'\t\t\t\t\t<% if(canUseApps) { %>\t\t\t\t\t\t<dt class="app"><%- _("App").t() %></dt>\t\t\t\t\t\t<dd>\t\t\t\t\t\t\t<%= appString %>\t\t\t\t\t\t</dd>\t\t\t\t\t<% } %> \t\t\t\t\t<% if(hasAcl) { %>\t\t\t\t\t\t<dt class="owner"><%- _("Owner").t() %></dt>\t\t\t\t\t\t<dd>\t\t\t\t\t\t\t<%= owner %>\t\t\t\t\t\t</dd>\t\t\t\t\t\t<dt class="permissions"><%- _("Permissions").t() %></dt>\t\t\t\t\t\t<dd class="edit-permissions">\t\t\t\t\t\t\t<%- permissionString %>\t\t\t\t\t\t</dd>\t\t\t\t\t<% } %>\t\t\t\t\t<dt class="modTime"><%- _("Last Modified Time").t() %></dt>\t\t\t\t\t<dd>\t\t\t\t\t\t<%= modTime %>\t\t\t\t\t</dd>\t\t\t\t'})}.apply(t,n),!(void 0!==s&&(e.exports=s))},1314:function(e,t,i){var n,s;n=[i("require/underscore"),i("shim/jquery"),e,i(856),i(1018),i(841),i(1315),i(1316),i(905)],s=function(e,t,i,n,s,a,o,l,r){var c=s.extend({moduleId:String(i.id),initialize:function(){s.prototype.initialize.apply(this,arguments),this.servicedfd=r.fetchServices(),this.servicedfd.done(function(){this.serviceTitleIds=r.serviceTitleIdMap}.bind(this)),this.tableColumns=new l(null,{enableBulkActions:!0,checkboxClassName:"btn lister-page"}),this.securityGroupCacheDfd=this.objectsCache.securityGroupsCache.waitXHR},initializeAndRenderViews:function(){this.objectsCache.securityGroupsCache&&this.objectsCache.securityGroupsCache.waitXHR&&this.objectsCache.securityGroupsCache.objects&&this.doRBACFiltering(),this.pagesView=this.initializePagesView(),this.renderPagesView(this.pagesView)},initializePagesView:function(){return new o({model:{savedPage:this.pagesModel,clonePage:this.cloneModel,state:this.stateModel,application:this.model.application,appLocal:this.model.appLocal,uiPrefs:this.uiPrefsModel,user:this.model.user},collection:{savedPages:this.pagesCollection,roles:this.rolesCollection},pageTitle:this.pageTitle,pageDescr:this.pageDescr,permissions:this.permissions,customViews:{EditMenuView:this.editMenu,InfoDetailsView:this.infoDetails,TitleView:this.titleView,HeadView:this.headView,CreateButtonView:this.CreateButtonView||a,TableView:this.tableView,tableColumnsCollection:this.tableColumns,TableCaptionView:this.tableCaptionView,RowView:this.rowView},collectionRender:this.collectionRender,objectsCache:this.objectsCache})},renderPagesView:function(e){this.pageView.$(".main-section-body").append(e.render().el)},createJSONFilter:function(e){return n.createEntityJSONFilter("string"==typeof e?e.toLowerCase():e,this.serviceTitleIds)},doRBACFiltering:function(){s.prototype.doRBACFiltering.apply(this,arguments),this.checkCanSeeBulkImportDropdownOptions()}});return c}.apply(t,n),!(void 0!==s&&(e.exports=s))},1315:function(e,t,i){var n,s;n=[i(449)],s=function(e){var t=e.extend({initialize:function(t){e.prototype.initialize.call(this,t),this.children.title=new this.options.customViews.TitleView({model:{application:this.model.application,savedPage:this.model.savedPage},collection:this.collection.savedPages,pageTitle:this.options.pageTitle,pageDescr:this.options.pageDescr,CreateButtonView:this.options.customViews.CreateButtonView,permissions:this.options.permissions})}});return t}.apply(t,n),!(void 0!==s&&(e.exports=s))},1316:function(e,t,i){var n,s;n=[i("require/underscore"),i("require/backbone"),i(1317),i(905)],s=function(e,t,i,n){var s=i.extend({before:[{label:e("Aliases").t(),name:"aliases",value:function(){return this.model.savedPage.get("identifier").values.join(", ")},editable:!0}],after:[{label:e("Services").t(),name:"services",sortKey:"services",value:function(){var t=new Date,i=function(){var e=n.getServicesAccessibleToUser(this.model.savedPage.get("services"),n.serviceIdTitleMap);e.sort(),this.$("td.services").text(e.join(", "))}.bind(this);return e.defer(function(){n.fetchServices().done(function(){var n=new Date-t;e.delay(i,n>600?0:600-n)})}),e("Loading service names...").t()}},{label:e("Health").t(),name:"health",value:function(){return e("View Health").t()},valueUrl:function(){return"entity_detail?entity_key="+this.model.savedPage.get("_key")}}],isSecurable:!0});return s}.apply(t,n),!(void 0!==s&&(e.exports=s))},1317:function(e,t,i){var n,s;n=[i("require/underscore"),i("require/backbone"),i(148)],s=function(e,t,i){var n=t.Model.extend({defaults:{name:"",label:"",sortKey:"",editable:!1,visible:!0,dynamic:!1},visible:function(){return this.get("dynamic")||this.get("visible")},editable:function(){return this.get("dynamic")||this.get("editable")}}),s=t.Collection.extend({before:[],after:[],isSecurable:!1,model:n,initialize:function(i,n){t.Collection.prototype.initialize.call(this,[],n),
this.reset(i||[],e.extend({silent:!0},n)),this.options=n},_mapVisible:function(e){return this.chain().filter(function(e){return e.visible()}).map(e).value()},dynamicHeaders:function(){return this._mapVisible(function(e){return e.pick(["label","sortKey"])})},renderColumnsWith:function(e){return this._mapVisible(s.extractRowValues(e))},renderHeaders:function(){var t=this.options.enableBulkActions?"col-checkbox":"col-info",n={label:"i",className:t,html:'<i class="icon-info"></i>'},s={className:"bulk-checkbox col-checkbox col-inline"},a={label:e("Title").t(),sortKey:"title"},o={label:i.getRoleBasedAccessControlName(!1,!0),sortKey:"sec_grp"},l={label:e("Actions").t(),className:"col-actions"},r=[{label:e("Owner").t(),className:"col-owner",sortKey:"owner"},{label:e("App").t(),className:"col-app"},{label:e("Sharing").t(),className:"col-sharing",sortKey:"sharing"}];return[n].concat(this.options.enableBulkActions?[s]:[]).concat([a]).concat([l]).concat(this.dynamicHeaders()).concat(this.isSecurable?[o]:[]).concat(this.options.hasAcls?r:[])},reset:function(i,n){n=n||{};var s=e.extend({silent:!0},n);return t.Collection.prototype.reset.call(this,[],s),this.add(this.before,s),this.add(i,s),this.add(this.after,s),n.silent||this.trigger("reset",this,n),i},local:function(){return this.filter(function(e){return!e.get("dynamic")})},visible:function(){return this.filter(function(e){return e.visible()})}},{extractSubValArray:function(t){return e.isObject(t)&&t.title?t.title||t._key:t},extractRowValues:function(t){return function(i){var n=s,a=n.extractDynamic(i,"value",t),o=e.escape(e.isArray(a)?e.map(a,n.extractSubValArray):a),l=n.extractDynamic(i,"valueUrl",t);return e.extend({value:o,name:i.get("name")},l?{valueUrl:l}:{})}},extractDynamic:function(t,i,n){return t.has(i)?e.isFunction(t.get(i))?t.get(i).call(n):t.get(i):""}});return s}.apply(t,n),!(void 0!==s&&(e.exports=s))}});