# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved. 
#
# This file contains all possible options for an threshold_label.conf file.  Use this file to configure 
# threshold name and color mappings.
#
# To map threshold name and colors, place a threshold_label.conf in 
# $SPLUNK_HOME/etc/apps/<app>/local/. For examples, see threshold_label.conf.example.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#
# CAUTION:  You can drastically affect your Splunk installation by changing these settings.  
# Consult technical support (http://www.splunk.com/page/submit_issue) if you are not sure how 
# to configure this file.
#


[<name>]
color = <string>
	* Valid color coding
	* Required

lightcolor = <string>
	* Valid color coding
	* Required

threshold_level = <integer>
	* A level value which is used to short list the labels in the specific order
	* Optional

health_weight = <int>
	* A weight of status, should be between 0 and 1
	* Required

health_min = <int>
	* Minimum threshold value of threshold (0 to 100). O and 100 values are inclusive but Minimum threshold value is exclusive
	* Required

health_max = <int>
	* Maximum threshold value of threshold (0 to 100). O and 100 values are inclusive but Maximum threshold value is inclusive
	* Required

score_contribution = <int>
	* The number, traditionally from 0 to 100, that this particular level will contribute towards health score calculations
	* Required