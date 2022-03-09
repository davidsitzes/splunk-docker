# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
#
# This file contains settings and options structure for an itsi_service_template.conf file. With this file,
# an app can be configured to export service templates for use within the ITSI app
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
# CAUTION:  You can drastically affect your Splunk installation by changing these settings.  
# Consult technical support (http://www.splunk.com/page/submit_issue) if you are not sure how 
# to configure this file.
#

[<string>]
title = <string>
* A title for the service template.
description = <string>
* The full description of the service being created.
entity_rules = <string>
* A list of entity rules (rules specification) used to associate entities to service created from this template.
* This is same as entity_rules field in itsi_service.conf.spec.
recommended_kpis = <string>
* A comma-separated list of KPIs that are automatically added when a service is created with this template.
optional_kpis = <string>
* A comma-separated list of KPIs that are available for this service (but not added automatically).
