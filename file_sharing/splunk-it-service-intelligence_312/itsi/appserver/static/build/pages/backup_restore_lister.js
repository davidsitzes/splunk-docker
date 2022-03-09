webpackJsonp([2],{0:function(e,t,s){var a,i;s.p=function(){function e(){for(var e,s,a="",i=0,o=arguments.length;i<o;i++)e=arguments[i].toString(),s=e.length,s>1&&"/"==e.charAt(s-1)&&(e=e.substring(0,s-1)),a+="/"!=e.charAt(0)?"/"+e:e;if("/"!=a){var l=a.split("/"),n=l[1];if("static"==n||"modules"==n){var r=a.substring(n.length+2,a.length);a="/"+n,window.$C.BUILD_NUMBER&&(a+="/@"+window.$C.BUILD_NUMBER),window.$C.BUILD_PUSH_NUMBER&&(a+="."+window.$C.BUILD_PUSH_NUMBER),"app"==l[2]&&(a+=":"+t("APP_BUILD",0)),a+="/"+r}}var d=t("MRSPARKLE_ROOT_PATH","/"),c=t("DJANGO_ROOT_PATH",""),u=t("LOCALE","en-US"),h="";return h=c&&a.substring(0,c.length)===c?a.replace(c,c+"/"+u.toLowerCase()):"/"+u+a,""==d||"/"==d?h:d+h}function t(e,t){if(window.$C&&window.$C.hasOwnProperty(e))return window.$C[e];if(void 0!==t)return t;throw new Error("getConfigValue - "+e+" not set, no default provided")}return e("/static/app/itsi/build/pages")+"/"}(),a=[s("require/underscore"),s("shim/jquery"),s("util/router_utils"),s("shim/splunk.util"),s("stubs/splunk.config"),s(401),s(894),s(919),s(895),s(900),s(906),s(907),s(917),s(918)],i=function(e,t,s,a,i,o,l,n,r,d,c,u,h,p){var g={collection:n,model:l,editMenu:r,rowView:c,tableView:d,tableCaptionView:h,titleView:u,infoDetails:p,title:e("Backup/Restore Jobs").t(),description:e("Viewer for all Backup/Restore Jobs").t()};new o(g);s.start_backbone_history()}.apply(t,a),!(void 0!==i&&(e.exports=i))},894:function(e,t,s){var a,i;a=[s("shim/jquery"),s("require/underscore"),s("require/backbone"),s("shim/splunk.util"),s(148),s(235),s("shim/splunk.util")],i=function(e,t,s,a,i,o,l){var n=o.extend({idAttribute:"_key",hasAcl:!1,objectNameSingular:t("Job").t(),objectNamePlural:t("Jobs").t(),_objectType:i.ITSI_OBJECT_BACKUP_RESTORE,aclFilteringEnabled:!1,defaults:function(){return{_owner:"nobody",create_time:"",last_queued_time:"",start_time:null,end_time:null,job_type:"Backup",path:"",rules:[],splunk_server:"",status:"Queued",title:"",last_error:"None",search_head_id:"",scheduled:0,enabled:0}},urlRoot:function(){var e=this.get("_owner");e||(e="nobody",this.set("_owner",e));var t=l.make_url(["custom","SA-ITOA","backup_restore_interface",e,this._objectType].join("/"));return t},initialize:function(){s.Model.prototype.initialize.apply(this,arguments)},getEditUrl:function(){return"#"},getViewUrl:function(){return this.getEditUrl()},queueJob:function(){this.set("status","Queued"),this.set("last_queued_time",(new Date).getTime()/1e3)},updateScheduledJobStatus:function(){var e=this.get("enabled"),t=this.get("frequency");1===e?"daily"===t?this.set("status","Scheduled Daily"):this.set("status","Scheduled Weekly"):this.set("status","Disabled")},getJobTypeLabel:function(){return"Backup"===this.get("job_type")?t("Backup").t():t("Restore").t()},getStatusLabel:function(){var e="";switch(this.get("status")){case"Queued":e=t("Queued").t();break;case"Disabled":e=t("Disabled").t();break;case"Scheduled Daily":e=t("Scheduled Daily").t();break;case"Scheduled Weekly":e=t("Scheduled Weekly").t();break;case"Failed":e=t("Failed").t();break;case"In Progress":e=t("In Progress").t();break;case"Not Started":e=t("Not Started").t();break;case"Completed":e=t("Completed").t();break;default:e=""}return e}});return n}.apply(t,a),!(void 0!==i&&(e.exports=i))},895:function(e,t,s){var a,i;a=[s("require/underscore"),e,s("shim/jquery"),s("views/Base"),s("views/shared/delegates/Popdown"),s("views/shared/dialogs/TextDialog"),s("shim/splunk.util"),s("uri/route"),s("models/Base"),s("models/ACLReadOnly"),s(148),s(838),s(894),s(896),s(899),s(473)],i=function(e,t,s,a,i,o,l,n,r,d,c,u,h,p,g,m){return a.extend({moduleId:String(t.id),initialize:function(){a.prototype.initialize.apply(this,arguments)},className:"dropdown",events:{"click a.delete-job":function(e){if(e.preventDefault(),!this.$("a.delete-job").hasClass("disabled")){var t=this;this.model.savedPage.fetch({wait:!0,success:function(){var e=new u({id:"modal_delete",savePage:t.model.savedPage,stateModel:t.model.state,objectNameSingular:t.options.objectNameSingular,savedPagesCollection:t.collection.savedPages});s("body").append(e.render().el),e.show()},error:function(){console.log("Error fetching "+t.options.objectNameSingular.toLowerCase()+" with id="+t.model.savedPage.id)}})}},"click a.edit-job":function(e){e.preventDefault(),new p({model:{savedPage:this.model.savedPage,user:this.model.user},collection:{savedPages:this.collection},onHiddenRemove:!0,addAction:!1}).render().show()},"click a.start-job":function(t){if(t.preventDefault(),!this.$el.find("li a.start-job").hasClass("disabled"))if("Restore"===this.model.savedPage.get("job_type")){var a=new g({id:"modal_start_job",savedPageModel:this.model.savedPage});s("body").append(a.render().el),a.show()}else this.model.savedPage.set("start_time",null),this.model.savedPage.queueJob(),this.model.savedPage.set("end_time",null),this.model.savedPage.save().done(function(){console.log("Queued backup job")}).error(function(t){var s=new m({errorMessage:e("Could not start backup job.").t(),htmlResponse:t});s.show()})},"click a.restore-backup":function(e){if(e.preventDefault(),!this.$el.find("a.restore-backup").hasClass("disabled")){var t=new g({id:"modal_start_job",savedPageModel:this.model.savedPage,savedPagesCollection:this.collection.savedPages});s("body").append(t.render().el),t.show()}},"click a.download-backup":function(t){t.preventDefault();var a=this.getDownloadUrl();s.ajax({url:a,type:"GET"}).done(function(){window.location.assign(a)}).fail(function(t){var s=new m({errorMessage:e("Could not download backup.").t(),htmlResponse:t});s.show()})},"click a.enable-job":function(t){t.preventDefault(),this.model.savedPage.set("enabled",0===this.model.savedPage.get("enabled")?1:0),this.model.savedPage.updateScheduledJobStatus(),this.model.savedPage.save({},{error:function(t,s){var a=new m({errorMessage:e("Could not enable/disable of default backup job.").t(),htmlResponse:s});a.show()}})}},getDownloadUrl:function(){var e="Restore"===this.model.savedPage.get("job_type"),t=this.model.savedPage.get("path"),s=e&&t&&t.indexOf("ItsiDefaultScheduledBackup")>-1?"ItsiDefaultScheduledBackup":this.model.savedPage.id;return l.make_url(["custom","SA-ITOA","backup_restore_interface","nobody","files",s].join("/"))+".zip"},render:function(){var t=1===this.model.savedPage.get("enabled")?e("Disable Scheduled Job").t():e("Enable Scheduled Job").t(),s={_:e,savedPage:this.model.savedPage,app:this.model.application.get("app"),view:this.model.savedPage.get("title"),savedPageId:this.model.savedPage.id,editUrl:this.model.savedPage.getEditUrl(),jobType:this.model.savedPage.get("job_type")||"Backup",scheduled:this.model.savedPage.get("scheduled"),enabledDisabledText:t};this.$el.html(this.compiledTemplate(s)),this.children.popdown=new i({el:this.$el});var a=this.model.savedPage.get("status");return a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.QUEUED&&a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.IN_PROGRESS||this.$("li a.start-job").addClass("disabled"),"Restore"===this.model.savedPage.get("job_type")&&a===c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.NOT_STARTED&&(this.$("li a.start-job").addClass("disabled"),this.$("li a.download-backup").addClass("disabled")),a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.COMPLETED&&a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.SCHEDULED_DAILY&&a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.SCHEDULED_WEEKLY&&a!==c.ITSI_CONFIG_BACKUP_RESTORE_JOB_STATUS.DISABLED||(this.$("li a.restore-backup").removeClass("disabled"),this.$("li a.download-backup").removeClass("disabled")),this},template:'\t\t\t\t\t<a class="dropdown-toggle" href="#"><%- _("Edit").t() %><span class="caret"></span></a>\t\t\t\t\t<div class="dropdown-menu dropdown-menu-narrow">\t\t\t\t\t\t<div class="arrow"></div>\t\t\t\t\t\t<ul class="first-group">\t\t\t\t\t\t\t<li><a href="#" class="edit-job"><%- _("Edit").t() %> </a></li>\t\t\t\t\t\t</ul>\t\t\t\t\t\t<ul class="second-group">\t\t\t\t\t\t\t<% if (jobType === "Backup") { %>\t\t\t\t\t\t\t\t<% if (scheduled === 0) { %>\t\t\t\t\t\t\t\t\t<li><a href="#" class="start-job"><%- _("Start Backup").t() %></a></li>\t\t\t\t\t\t\t\t<% } %>\t\t\t\t\t\t\t\t<li><a href="#" class="restore-backup disabled"><%- _("Restore Backup").t() %></a></li>\t\t\t\t\t\t\t\t<li><a class="download-backup disabled"><%- _("Download Backup").t() %></a></li>\t\t\t\t\t\t\t<% } else { %>\t\t\t\t\t\t\t\t<li><a href="#" class="start-job"><%- _("Start Restore").t() %></a></li>\t\t\t\t\t\t\t\t<li><a class="download-backup"><%- _("Download Backup").t() %></a></li>\t\t\t\t\t\t\t<% } %>\t\t\t\t\t\t</ul>\t\t\t\t\t\t<ul class="third-group">\t\t\t\t\t\t<% if (scheduled === 0) { %> \t\t\t\t\t\t\t<li><a href="#" class="delete-job"><%- _("Delete").t() %></a></li>\t\t\t\t\t\t<% } else { %>\t\t\t\t\t\t\t<li><a href="#" class="enable-job"><%- enabledDisabledText %></a></li>\t\t\t\t\t\t<% } %>\t\t\t\t\t\t</ul>\t\t\t\t\t</div>\t\t\t\t'})}.apply(t,a),!(void 0!==i&&(e.exports=i))},896:function(e,t,s){var a,i;a=[s("shim/jquery"),s("require/underscore"),s("require/backbone"),s("shim/splunk.util"),e,s("models/Base"),s("models/ACLReadOnly"),s("models/shared/DateInput"),s("views/shared/Modal"),s("views/shared/controls/ControlGroup"),s("views/shared/controls/SyntheticSelectControl"),s("views/shared/controls/TextControl"),s("views/shared/waitspinner/Master"),s(129),s(149),s("views/shared/FlashMessagesLegacy"),s("collections/shared/FlashMessages"),s(897)],i=function(e,t,s,a,i,o,l,n,r,d,c,u,h,p,g,m,b){var v=r.extend({moduleId:String(i.id),initialize:function(){r.prototype.initialize.apply(this,arguments),this.showUploadFileControl=this.options.showUploadFileControl,this.addAction=this.options.addAction;var e=this.model.savedPage;this.model.savedPage=e instanceof s.Model?e:new e,this.jobType=this.model.savedPage.get("job_type")||"Backup",this.addAction&&(this.jobType=this.options.jobType||"Backup"),this.scheduled=this.model.savedPage.get("scheduled")||0,this._user_tz=this.model.user.entry.content.get("tz")||"",this._user_tz_object=g.convertToTimezoneObject(this._user_tz);var a="",i=t("optional").t();this.addAction||(a=this.model.savedPage.get("title"),i=this.model.savedPage.get("description"));var o=new s.Model({job_type:this.model.savedPage.getJobTypeLabel(),status:this.model.savedPage.getStatusLabel(),last_error:"None"===this.model.savedPage.get("last_error")?t("None").t():this.model.savedPage.get("last_error")});this.children.title=new d({controlType:"Text",controlOptions:{modelAttribute:"title",model:this.model.savedPage,save:!1,placeholder:a},label:t("Name").t()}),this.children.description=new d({controlType:"Textarea",controlOptions:{modelAttribute:"description",model:this.model.savedPage,placeholder:i,save:!1},label:t("Description").t()}),this.model.savedPage.set("job_type",this.jobType),this.children.jobType=new d({controlType:"Text",controlOptions:{modelAttribute:"job_type",model:o,save:!1},label:t("Operation").t()}),this.children.status=new d({controlType:"Text",controlOptions:{modelAttribute:"status",model:o,save:!1},label:t("Status").t()}),this.children.lastError=new d({controlType:"Textarea",controlOptions:{modelAttribute:"last_error",model:o,save:!1},label:t("Last Error").t()});var l=g.convertUtcDateToTimezoneDate(p.convertBackendDate(this.model.savedPage.get("start_time")),1e3*this._user_tz_object.get("offset"));this.children.startTime=new d({controlType:"Text",controlOptions:{placeholder:g.getLocalizedDate(l),save:!1},label:t("Last Started").t()});var n=g.convertUtcDateToTimezoneDate(p.convertBackendDate(this.model.savedPage.get("end_time")),1e3*this._user_tz_object.get("offset"));if(this.children.endTime=new d({controlType:"Text",controlOptions:{placeholder:g.getLocalizedDate(n),save:!1},label:t("Last Ended").t()}),1===this.scheduled){var u=s.Model.extend({defaults:function(){return{day:0,hour:0,min:0}}});this.model.backupScheduleModel=new u;var v=p.convertBackendDate(this.model.savedPage.get("scheduled_time")),f=g.convertUtcDateToTimezoneDate(v,1e3*this._user_tz_object.get("offset")),_=f.getDay(),y=f.getHours(),w=f.getMinutes();this.model.backupScheduleModel.set({day:_,hour:y,min:w});var T=t.map(t.range(24),function(e){var t=function(e){if(e<10){var t="0"+e;return t}return e.toString()},s=t(e),a=t(w);return{label:s+":"+a,value:e}});this.children.scheduleStatus=new d({controlType:"SyntheticRadio",controlOptions:{modelAttribute:"enabled",model:this.model.savedPage,items:[{label:t("Enabled").t(),value:1},{label:t("Disabled").t(),value:0}],save:!1},label:t("Enabled").t()}),this.children.schedule=new d({controlType:"SyntheticSelect",controlClass:"schedule-control",controlOptions:{className:"schedule",toggleClassName:"btn",model:this.model.savedPage,modelAttribute:"frequency",items:[{label:t("Weekly").t(),value:"weekly"},{label:t("Daily").t(),value:"daily"}],popdownOptions:{attachDialogTo:"body"}},label:t("Schedule").t()}),this.children.scheduleHour=new c({additionalClassNames:"schedule-subcontrol schedule-hour",modelAttribute:"hour",model:this.model.backupScheduleModel,items:T,save:!1,toggleClassName:"btn",labelPosition:"outside",elastic:!0,popdownOptions:{attachDialogTo:"body"}}),this.children.scheduleDay=new c({additionalClassNames:"schedule-subcontrol schedule-day",modelAttribute:"day",model:this.model.backupScheduleModel,items:[{label:t("Sunday").t(),value:0},{label:t("Monday").t(),value:1},{label:t("Tuesday").t(),value:2},{label:t("Wednesday").t(),value:3},{label:t("Thursday").t(),value:4},{label:t("Friday").t(),value:5},{label:t("Saturday").t(),value:6}],save:!1,toggleClassName:"btn",labelPosition:"outside",popdownOptions:{attachDialogTo:"body"}});var S=this;this.listenTo(this.model.savedPage,"change:frequency",function(){S._toggleScheduleControls(),this.model.savedPage.updateScheduledJobStatus()}),this.listenTo(this.model.savedPage,"change:enabled",function(){this.model.savedPage.updateScheduledJobStatus()})}this.waitSpinner=new h,this.flashMessagesCollection=new b,this.flashMessagesView=new m({collection:this.flashMessagesCollection})},_toggleScheduleControls:function(){var e=this.$(r.BODY_FORM_SELECTOR+" .schedule-hour"),t=this.$(r.BODY_FORM_SELECTOR+" .schedule-day"),s=this.$(r.BODY_FORM_SELECTOR+" .day-pre-label"),a=this.$(r.BODY_FORM_SELECTOR+" .hour-pre-label");switch(this.model.savedPage.get("frequency")){case"weekly":t.show(),e.show(),t.css("display","inline-block"),e.css("display","inline-block"),a.removeClass("schedule-subcontrol-label"),s.addClass("schedule-subcontrol-label"),s.show(),a.show();break;case"daily":e.show(),e.css("display","inline-block"),t.hide(),s.hide(),a.addClass("schedule-subcontrol-label"),a.show()}},events:e.extend({},r.prototype.events,{"click a.modal-btn-primary":function(e){e.preventDefault();var i=function(e,t){t===!1?e.$("a.modal-btn-primary").attr("disabled","disabled"):e.$("a.modal-btn-primary").removeAttr("disabled")};this.$(".loading-mask").hide(),this.flashMessagesCollection.reset(),i(this,!1);var o="nobody",l=this;if(p.isEmptyString(this.model.savedPage.get("title")))return this.flashMessagesCollection.reset([{key:"error",type:"error",html:t("Title cannot be an empty string.").t()}]),void i(this,!0);if(1===l.model.savedPage.get("scheduled")){var d=function(e,t,s){var a=new Date;return a.setDate(a.getDate()+(e+(7-a.getDay()))%7),a.setHours(t),a.setMinutes(s),a},c=new Date,u=p.convertBackendDate(c.getTime()/1e3),h=g.convertUtcDateToTimezoneDate(u,1e3*this._user_tz_object.get("offset")),m="daily"===l.model.savedPage.get("frequency")?h.getDay():l.model.backupScheduleModel.get("day"),b=d(m,l.model.backupScheduleModel.get("hour"),l.model.backupScheduleModel.get("min"));h>b&&("weekly"===l.model.savedPage.get("frequency")?b.setDate(b.getDate()+7):b.setDate(b.getDate()+1));var v=g.convertTimezoneDateToUtcDate(b,1e3*l._user_tz_object.get("offset"));l.model.savedPage.set("scheduled_time",g.getTrueUtcTimeForBackend(v))}var f=new n;if(l.model.savedPage.set("mod_timestamp",f.strftime("%Y-%m-%d %H:%M:%S")),l.addAction){var _=f.strftime("%Y-%m-%d %H:%M:%S");l.model.savedPage.set("create_time",_),l.model.savedPage.queueJob(),l.model.savedPage.set("_owner",o)}"Restore"!==this.model.savedPage.get("job_type")||!this.showUploadFileControl||this.files&&0!==this.files.length?"Restore"===this.model.savedPage.get("job_type")&&this.showUploadFileControl&&".zip"!==this.files[0].name.slice(-4)?(this.flashMessagesCollection.reset([{key:"error",type:"error",html:t("Invalid file format.").t()}]),i(this,!0)):("Restore"===this.model.savedPage.get("job_type")&&this.showUploadFileControl&&(this.model.savedPage.set("status","Not Started"),this.$(r.FOOTER_SELECTOR+" .btn.cancel.modal-btn-cancel.pull-left").addClass("disabled"),l.$(r.FOOTER_SELECTOR+" .btn.cancel.modal-btn-cancel.pull-left").prop("disabled",!0)),this.model.savedPage.save({},{success:function(e,o){l.model.savedPage.fetch({success:function(){if(l.addAction&&l.collection.savedPages instanceof s.Collection&&(l.collection.savedPages.add(l.model.savedPage),l.collection.savedPages.trigger("refresh")),i(l,!1),l.showUploadFileControl){l.$(".loading-mask").show(),l.waitSpinner.start();var e=l._upload(o._key+".zip");e.done(function(){l.model.savedPage.queueJob(),l.model.savedPage.save({},{success:function(){i(l,!0),l.hide(),l.remove()}})}),e.fail(function(e,s,o){l.waitSpinner.stop(),i(l,!0),l.flashMessagesCollection.reset([{key:"error",type:"error",html:t("File upload failed.").t()}]),l.model.savedPage.set("status","Failed"),l.model.savedPage.set("last_error",a.sprintf(t("Upload of backup file failed: %s %s",s,o))),l.model.savedPage.save({},{success:function(){i(l,!0),l.hide(),l.remove()}})})}else i(l,!0),l.hide(),l.remove()},error:function(){console.log(a.sprintf(t("Error fetching %s with id: %s").t(),l.objectNameSingular.toLowerCase(),l.model.savedPage.id)),i(l,!0)}})},error:function(e,s){var o=a.sprintf(t("Save failed. Details: %s").t(),p.extractErrorMsgFromResponse(s));l.flashMessagesCollection.reset([{key:"error",type:"error",html:o}]),i(l,!0)}}),l.addAction||l.model.savedPage.trigger("edit_param_change")):(this.flashMessagesCollection.reset([{key:"error",type:"error",html:t("No backup file provided.").t()}]),i(this,!0))},"click .upload-button":"_upload",'change input[type="file"]':"_onChangeFile"}),_onChangeFile:function(e){this.files=e.target.files},_upload:function(t){var s=a.make_url(["custom","SA-ITOA","backup_restore_interface","nobody","files",t].join("/")),i=new FormData;return i.append("backupFile",this.files[0]),e.ajax({url:s,type:"POST",data:i,success:function(){},cache:!1,contentType:!1,processData:!1})},renderModal:function(){return this.$(r.BODY_SELECTOR).append(r.FORM_HORIZONTAL),this.$(r.BODY_FORM_SELECTOR).append('<div class="modal-messages-container"></div>'),e(".modal-messages-container",this.$(r.BODY_FORM_SELECTOR)).append(this.flashMessagesView.render().$el),this.$(r.BODY_FORM_SELECTOR).append(this.children.title.render().el),this.$(r.BODY_FORM_SELECTOR).append(this.children.description.render().el),this.showUploadFileControl&&this.$(r.BODY_FORM_SELECTOR).append('<form class="main-form" enctype="multipart/form-data"><div class="backup-file-control">'+t("Backup File").t()+'</div><input class="upload-file-selector" style="display:inline-block" name="backupFile" type="file" accept="application/zip" /></form>'),this.$(r.BODY_FORM_SELECTOR).append(this.children.jobType.render().el),this.children.jobType.$el.find(":input").attr("disabled","disabled"),1===this.scheduled?(this.$(r.BODY_FORM_SELECTOR).append(this.children.scheduleStatus.render().el),this.$(r.BODY_FORM_SELECTOR).append(this.children.schedule.render().el),this.$(r.BODY_FORM_SELECTOR).append(this.children.scheduleDay.render().el),this.$(r.BODY_FORM_SELECTOR).append(this.children.scheduleHour.render().el),this.$(r.BODY_FORM_SELECTOR+" .schedule-day").before('<span class="day-pre-label">'+t("on").t()+"</span>"),this.$(r.BODY_FORM_SELECTOR+" .schedule-hour").before('<span class="hour-pre-label">'+t("at").t()+"</span>"),this.$(r.BODY_FORM_SELECTOR+" .schedule-hour").after('<div class="backup-delay-message alert alert-info"><i class="icon-alert"></i><div class="scheduled-backup-info-message">'+t("Backup will run within one hour of scheduled time.").t()+"</div></div>"),void this._toggleScheduleControls()):void(this.addAction||(this.$(r.BODY_FORM_SELECTOR).append(this.children.status.render().el),this.children.status.$el.find(":input").attr("disabled","disabled"),this.$(r.BODY_FORM_SELECTOR).append(this.children.lastError.render().el),this.children.lastError.$el.find(":input").attr("disabled","disabled"),this.$(r.BODY_FORM_SELECTOR).append(this.children.startTime.render().el),this.children.startTime.$el.find(":input").attr("disabled","disabled"),this.$(r.BODY_FORM_SELECTOR).append(this.children.endTime.render().el),this.children.endTime.$el.find(":input").attr("disabled","disabled")))},render:function(){this.$el.html(r.TEMPLATE);var e,s;if(this.addAction)e=t("Create Job").t(),this.$(r.HEADER_TITLE_SELECTOR).html(e),s=t("Create").t(),this.renderModal();else{e=t("Edit Job").t(),this.$(r.HEADER_TITLE_SELECTOR).html(e),s=t("Save").t();var i=this;this.model.savedPage.fetch({wait:!0,success:function(){i.renderModal()},error:function(){console.log(a.sprintf(t("Error fetching %s with id: %s").t(),i.objectNameSingular.toLowerCase(),i.model.savedPage.id))}})}return this.$(r.FOOTER_SELECTOR).append('<div class="loading-mask" style="display:none"><div class="loading-mask-spinner-container"></div><div class="loading-mask-message-container">'+t("Uploading backup file...").t()+"</div></div>"),this.$(".loading-mask-spinner-container").append(this.waitSpinner.render().$el),this.$(r.FOOTER_SELECTOR).append(r.BUTTON_CANCEL),this.$(r.FOOTER_SELECTOR).append('<a href="#" class="btn btn-primary modal-btn-primary">'+s+"</a>"),this}});return v}.apply(t,a),!(void 0!==i&&(e.exports=i))},897:function(e,t,s){var a=s(898);"string"==typeof a&&(a=[[e.id,a,""]]);s(15)(a,{});a.locals&&(e.exports=a.locals)},898:function(e,t,s){t=e.exports=s(14)(),t.push([e.id,".form-horizontal .main-form{margin-left:15px}.form-horizontal .main-form .upload-file-selector{margin-left:20px}input.upload-file-selector{line-height:18px;height:18px}.loading-mask{display:inline-block;padding-right:10px}.modal-messages-container{padding-left:20px}.schedule-subcontrol{margin-bottom:10px}.hour-pre-label{margin:5px}.schedule-subcontrol-label{margin-left:180px!important}div.form-horizontal span.schedule-subcontrol-label{margin-left:97px;margin-right:5px}.backup-delay-message{margin-left:15px}.backup-file-control{display:inline-block;float:left;width:145px;padding-top:5px;text-align:right}",""])},899:function(e,t,s){var a,i;a=[s("require/underscore"),s("require/backbone"),e,s("views/shared/dialogs/TextDialog"),s("views/shared/controls/ControlGroup"),s("models/shared/DateInput"),s("shim/splunk.util"),s(473)],i=function(e,t,s,a,i,o,l,n){var r=a.extend({moduleId:String(s.id),initialize:function(t){a.prototype.initialize.apply(this,arguments),this.savedPageModel=t.savedPageModel,this.savedPagesCollection=t.savedPagesCollection,this.settings.set("primaryButtonLabel",e("Start Restore").t()),this.settings.set("cancelButtonLabel",e("Cancel").t()),this.settings.set("titleLabel",e("Start Restore").t());var s=l.sprintf(e("Are you sure you want to start the job for %s? Restore will attempt to merge current configuration with the backup. This action will schedule the job immediately and this background operation is irreversible.").t(),e.escape(this.savedPageModel.get("title")));s+="<br/><br/>",s+=e("It is best practice and highly recommended to take a backup of the current objects before attempting to restore. This will provide a good version of the objects to rollback to if restore fails.").t(),this.setText(s)},dialogShown:function(){this.trigger("show"),e.debounce(function(){this.$(".btn-primary:first").focus()}.bind(this),0)()},events:function(){return e.extend({},a.prototype.events,{"click .btn-dialog-primary":function(s){s.preventDefault();var a=this;if(1===this.savedPageModel.get("scheduled")){var i=this.savedPageModel.clone(),r=["_key","last_error","frequency","mod_timestamp","hour","day","scheduled_time"];e.each(r,function(e){i.unset(e)});var d=new o,c=d.strftime("%Y-%m-%d %H:%M:%S");i.set({title:l.sprintf(e("Restore from %s %s").t(),i.get("title"),c),description:l.sprintf(e("Restore from %s").t(),i.get("title")),job_type:"Restore",start_time:null,end_time:null,enabled:0,scheduled:0}),i.queueJob(),i.save({},{success:function(e){a.savedPagesCollection&&a.savedPagesCollection instanceof t.Collection&&(a.savedPagesCollection.add(e),a.savedPagesCollection.trigger("refresh"))},error:function(t,s){var a=new n({errorMessage:e("Could not start the job.").t(),htmlResponse:s});a.show()}})}else if("Backup"===this.savedPageModel.get("job_type")){var u=l.sprintf(e("Restore from %s").t(),e.escape(this.savedPageModel.get("title"))||e("existing backup").t());this.savedPageModel.set({title:u,description:u,job_type:"Restore",status:"Queued"}),this.savedPageModel.queueJob()}else this.savedPageModel.queueJob();0===this.savedPageModel.get("scheduled")&&(this.savedPageModel.set("start_time",null),this.savedPageModel.set("end_time",null),this.savedPageModel.save().done(function(){a.hide(),a.remove()}).error(function(t){a.hide(),a.remove();var s=new n({errorMessage:e("Could not start the job.").t(),htmlResponse:t});s.show()}))},hidden:function(){this.remove()}})}});return r}.apply(t,a),!(void 0!==i&&(e.exports=i))},900:function(e,t,s){var a,i;a=[e,s("require/underscore"),s("shim/jquery"),s("require/backbone"),s(856),s(857),s(901)],i=function(e,t,s,a,i,o,l){return o.extend({moduleId:String(e.id),initialize:function(e){e.extraHeaders=[{label:t("Status").t()},{label:t("Last Started").t()},{label:t("Last Ended").t()}],e.enableBulkActions=!0,o.prototype.initialize.apply(this,arguments),this.model.state.on("change:bulkAction",function(){this.handleBulkAction(this.model.state.get("bulkAction"))}.bind(this))},handleBulkAction:function(e){switch(e){case"delete-select":this.deleteRows()}},deleteRows:function(){var e=this.getBulkSelectionRows(),t=new l({id:"modal_bulk_delete",deleteType:"delete-select",tableRows:e,objectNamePlural:this.model.savedPage.prototype.objectNamePlural,filterCreator:i.createJSONFilter});s("body").append(t.render().el),t.show()}})}.apply(t,a),!(void 0!==i&&(e.exports=i))},906:function(e,t,s){var a,i;a=[e,s("require/underscore"),s("shim/jquery"),s(149),s(129),s(853),s(896)],i=function(e,t,s,a,i,o,l){var n=o.extend({moduleId:String(e.id),initialize:function(e){this._user_tz=this.model.user.entry.content.get("tz")||"",this._user_tz_object=a.convertToTimezoneObject(this._user_tz);var s=a.convertUtcDateToTimezoneDate(i.convertBackendDate(this.model.savedPage.get("start_time")),1e3*this._user_tz_object.get("offset")),l=a.convertUtcDateToTimezoneDate(i.convertBackendDate(this.model.savedPage.get("end_time")),1e3*this._user_tz_object.get("offset"));e.extraHeaders=[{name:t("Status").t(),value:this.model.savedPage.getStatusLabel()},{name:t("Last Started").t(),value:a.getLocalizedDate(s)},{name:t("Last Ended").t(),value:a.getLocalizedDate(l)}],e.enableBulkActions=!0,o.prototype.initialize.apply(this,arguments)},_renderCheckbox:function(){this.options.enableBulkActions&&this.$(".box").append(this.children.bulkbox.render().el),1===this.model.savedPage.get("scheduled")&&(this.children.bulkbox.disable(),this.children.bulkbox.off("select-all"))},events:{"click a.edit-row":function(e){e.preventDefault(),new l({model:{savedPage:this.model.savedPage,user:this.model.user},collection:{savedPages:this.collection},objectNameSingular:this.options.objectNameSingular,onHiddenRemove:!0,addAction:!1}).render().show()}}});return n}.apply(t,a),!(void 0!==i&&(e.exports=i))},907:function(e,t,s){var a,i;a=[e,s("require/underscore"),s(840),s(908)],i=function(e,t,s,a){var i=s.extend({moduleId:String(e.id),initialize:function(e){e.CreateButtonView=a,s.prototype.initialize.apply(this,arguments)}});return i}.apply(t,a),!(void 0!==i&&(e.exports=i))},908:function(e,t,s){var a,i;a=[s("require/backbone"),s("require/underscore"),s("splunkjs/mvc/utils"),s("shim/splunk.util"),s("views/shared/delegates/Popdown"),s(148),s(909),s(473),s(896)],i=function(e,t,s,a,i,o,l,n,r){var d=e.View.extend({_template:t.template('<a class="dropdown-toggle btn btn-primary pull-right" href="#"><%- _("Create New Job").t() %><span class="caret"></span></a><div class="dropdown-menu dropdown-menu-narrow"><div class="arrow"></div><ul><li><a href="#" class="create-backup-job"><%- _("Create Backup Job").t() %> </a></li><li><a href="#" class="create-restore-job"><%- _("Create Restore Job").t() %> </a></li></ul></div>'),initialize:function(t){e.View.prototype.initialize.apply(this,arguments),this.options=t},render:function(){return this.$el.html(this._template({_:t})),new i({el:this.$el}),this},events:{"click .create-backup-job":function(e){e.preventDefault();var i=new l,d=i.getTitlesKeysAndSyncStatus();d.done(function(e){i=e;var l=t.any(e,function(e){return e.sync_status===o.BASE_SERVICE_TEMPLATE_STATUS.SYNCING},this);if(l){var d=t("Service Templates lister page").t(),c=t("Scheduled sync of service template is in progress, cannot create backup at this time. Try again a little later. To see the status of sync operations, check the ").t()+'<a class="service-lister-page-link">'+d+"</a>";return this.errorModal=new n({errorMessage:c,events:{"click .service-lister-page-link":function(e){e.preventDefault(),this.hide();var t=a.make_full_url("/app/itsi/service_templates_lister");s.redirect(t,!0)}}}),void this.errorModal.show()}new r({model:{savedPage:this.model.savedPage,user:this.model.user},collection:{savedPages:this.collection},onHiddenRemove:!0,addAction:!0,jobType:"Backup"}).render().show()}.bind(this)).fail(function(e){var s=new n({errorMessage:t("Could not retrieve the Service Template Collection.").t(),htmlResponse:e});s.show()})},"click .create-restore-job":function(e){e.preventDefault(),new r({model:{savedPage:this.model.savedPage,user:this.model.user},collection:{savedPages:this.collection},onHiddenRemove:!0,addAction:!0,showUploadFileControl:!0,jobType:"Restore"}).render().show()}}});return d}.apply(t,a),!(void 0!==i&&(e.exports=i))},917:function(e,t,s){var a,i;a=[s("require/underscore"),e,s("views/shared/delegates/Popdown"),s(846)],i=function(e,t,s,a){var i=a.extend({moduleId:String(t.id),tagName:"div",initialize:function(t){t.bulkActions=[{value:"delete-select",text:e("Delete selected").t()}],a.prototype.initialize.apply(this,arguments)}});return i}.apply(t,a),!(void 0!==i&&(e.exports=i))},918:function(e,t,s){var a,i;a=[s("shim/jquery"),s("require/underscore"),s("require/backbone"),s(839)],i=function(e,t,s,a){var i=a.extend({render:function(){return a.prototype.render.apply(this,arguments),"Failed"===this.model.savedPage.get("status")&&this.$el.append('<dt class="fail"><i class="icon-alert" style="color:#d6563c;"></i>'+t("Failed").t()+"</dt><dd>"+this.model.savedPage.get("last_error")=="None"?t("None").t():this.model.savedPage.get("last_error")+"</dd>"),this}});return i}.apply(t,a),!(void 0!==i&&(e.exports=i))},919:function(e,t,s){var a,i;a=[s("shim/splunk.util"),s(148),s(256),s(894)],i=function(e,t,s,a){var i=s.extend({model:a,_objectType:t.ITSI_OBJECT_BACKUP_RESTORE,url:e.make_url(["custom","SA-ITOA","backup_restore_interface","nobody","backup_restore"].join("/")),setUrl:function(t){t=t||"nobody",this.url=e.make_url(["custom","SA-ITOA","backup_restore_interface",t,this._objectType].join("/"))}});return i}.apply(t,a),!(void 0!==i&&(e.exports=i))}});