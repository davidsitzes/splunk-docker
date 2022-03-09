# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
#
# This file contains settings and options structure for an itsi_settings.conf file. ITSI settings are a
# collection of specifications for configuring the app.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
# CAUTION:  You can drastically affect your Splunk installation by changing these settings.  
# Consult technical support (http://www.splunk.com/page/submit_issue) if you are not sure how 
# to configure this file.
#

[datamodels://<app>]
* app is the ID for the app containing the datamodel
blacklist = <datamodel_names_list>
* datamodel_names_list is a pipe separated list of data model EAI names (IDs) that need to be blacklisted.
* Note that data model names do not contain pipe characters.
* The blacklisted data models will not be supported and remain hidden from the ITSI UI.

[cloud]
show_migration_message  = <0|1>

[backup_restore]
* Defines settings related to backup_restore

job_queue_timeout = <seconds>
* Jobs queued should timeout if node owning the backup/restore job has been down for too long to allow other jobs to proceed.
* job_queue_timeout specifies in seconds what this time out period is.
* Minimum timeout supported is 3600secs. The system will set timeout to 3600s when a value lower than this is set.


[import]
* Defines limits for import behavior.

import_batch_size = <integer>
* Defines the number of rows or objects the importer should analyze before attempting a save to KVStore

preview_sample_limit = <integer>
* Defines the maximum number of rows that will be returned from a preview request for a pending import

asynchronous_processing_threshold = <integer>
* Defines the number of rows after which the bulk importer will spool the inbound content rather than process it immediately
