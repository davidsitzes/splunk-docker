# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import csv

# Core Splunk Imports
import splunk.rest
import splunk.Intersplunk
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from itsi.suppress_alert import CustomSuppressAlert, ParseArgs

def get_params(args):
    '''
    Parse search arguments and return dict of search params
    :param: dict list of system arguments pass to scripts
    :return: dict of search params and their values
    :rtype: dict
    '''
    params, error_msg = ParseArgs.get_params(args[1:])
    if error_msg is not None:
        splunk.Intersplunk.parseError(error_msg)
    return params


params = get_params(sys.argv)

# Check for required fields
if 'count' not in params.keys():
    splunk.Intersplunk.parseError(_("Required field count is missing"))

if 'is_consecutive' not in params.keys():
    splunk.Intersplunk.parseError(_("Required field is_consecutive is missing"))

# Make sure required param must exist
if not params.get('count'):
    splunk.Intersplunk.parseError(_("count field  has invalid value"))

if params.get('is_consecutive') is None or not isinstance(params.get('is_consecutive'), bool):
    splunk.Intersplunk.parseError(_("is_consecutive field has invalid value"))

alert_sup = CustomSuppressAlert(params)
results = []
# Get data in streaming mode
try:
    csvr = csv.reader(sys.stdin)
    header = []
    first = True
    for line in csvr:
        if first:
            header = line
            first = False
            continue
        result = {}
        i = 0
        for val in line:
            result[header[i]] = val
            i = i + 1
        # pass to suppress logic
        alert_sup.process_result(result)
    # Now get alert if suppress criteria met, otherwise empty list
    results = alert_sup.get_alerts()
except Exception as e:
    if alert_sup is not None:
        alert_sup.logger.exception(e)
    results = splunk.Intersplunk.generateErrorResults(e)
finally:
    # Output results
    splunk.Intersplunk.outputResults(results)
