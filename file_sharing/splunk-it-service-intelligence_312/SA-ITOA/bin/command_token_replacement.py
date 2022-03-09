# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import csv
import re

# Core Splunk Imports
from splunk.util import normalizeBoolean
import splunk.rest
import splunk.Intersplunk
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_config import get_supported_objects
from ITOA.setup_logging import setup_logging
logger = setup_logging('itsi_searches.log', 'itsi.token_replacement')



def get_params(args):
    '''
    Parse search arguments and return dict of search params
    :param: dict list of system arguments pass to scripts
    :return: dict of search params and their values
    :rtype: dict
    '''
    args = (args[1:])
    i = 0
    params = {}
    error_msg = None

    while i < len(args):
        arg = args[i]
        if arg.find('fields') != -1 or arg.find('debug'):
            values = arg.split("=")
            if len(values) != 2:
                error_msg = _("Invalid argument '%s'.") % arg
                break
            key = values[0].strip()
            value = values[1].strip()
            if not value:
                error_msg = _("Invalid argument value '%s', it should be a valid value.") % arg
                break
            if key == 'debug':
                params[key] = normalizeBoolean(value)
            elif key == 'fields':
                params[key] = value.split(',')
        else:
            error_msg = _("Invalid argument '%s'.") % arg
            break
        i += 1

    if error_msg:
        logger.error('Error message=%s', error_msg)
        splunk.Intersplunk.parseError(error_msg)
    return params


def replace_tokens(value, result):
    regex = re.compile('\\$([\w.]+)\\$')
    dynamic_fields = regex.findall(value)
    new_value = value
    if dynamic_fields:
        logger.debug('Found tokens=%s', dynamic_fields)
        for token_field in dynamic_fields:
            new_value = new_value.replace('$'+token_field+'$', result.get(token_field, 'unknown'))
            logger.info('Value=%s after %s token replacement, token_value=%s', new_value, token_field, result.get(token_field))
    logger.debug('Replaced value=%s', new_value)
    return new_value


params = get_params(sys.argv)
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
        # do a token replacement and fix
        for field in params.get('fields'):
            logger.info('Replacing token for field=%s, value=%s', field, result.get(field))
            result[field] = replace_tokens(result.get(field), result)
        results.append(result)
except Exception as e:
    logger.exception(e)
    results = splunk.Intersplunk.generateErrorResults(e)
finally:
    splunk.Intersplunk.outputResults(results)
