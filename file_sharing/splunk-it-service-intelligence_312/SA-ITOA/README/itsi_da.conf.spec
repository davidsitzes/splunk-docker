# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

########## ########## ########## ########## ########## ########## ########## ########## ##########
# This .conf file is DEPRECATED.                                                                 #
# For [entity_source_template://<string>], use inputs.conf/[itsi_csv_import://<name>] instead.   #
# For [service_template://<string>], use itsi_service_template.conf/[string] instead.            #
########## ########## ########## ########## ########## ########## ########## ########## ##########

#
# This file contains settings and options structure for an itsi_da.conf file. With this file,
# an app can be configured to export entity searches and service templates for use within the
# ITSI app
#
# To learn more about configuration files (including precedence) please see the documentation
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
# CAUTION:  You can drastically affect your Splunk installation by changing these settings.
# Consult technical support (http://www.splunk.com/page/submit_issue) if you are not sure how
# to configure this file.
#

[entity_source_template://<string>]
title = <string>
* The display name of the search.
description = <string>
* Human-readable description of this search.
saved_search = <string>
* The actual Splunk saved search that outputs a table. This will be enforced by client-side code.
title_field = <string>
* A single field that acts as the title for the entity
description_fields = <string>
* A comma-separated list of fields that describe the entity.
identifier_fields = <string>
* A comma-separated list of fields that identify the entity.
informational_fields = <string>
* A comma-separated list of fields that act as additional entity metadata.

[service_template://<string>]
title = <string>
* A title for the service template.
description = <string>
* The full description of the service being created.
entity_source_templates = <string>
* The list of entity searches that create entities that can be used with this service.
* This is used to populate the list of entity searches in the combined entity-service creation workflow.
entity_rules = <string>
* A list of entity rules (rules specification) used to associate entities to service created from this template.
* This is same as entity_rules field in itsi_service.conf.spec.
recommended_kpis = <string>
* A comma-separated list of KPIs that are automatically added when a service is created with this template.
informational_kpis = <string>
* A comma-separated list of informational (no threshold) KPIs that are automatically added when a service is created with this template.
optional_kpis = <string>
* A comma-separated list of KPIs that are available for this service (but not added automatically).