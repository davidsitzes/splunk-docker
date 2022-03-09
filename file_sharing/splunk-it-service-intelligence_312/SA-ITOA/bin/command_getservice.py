# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import re
import logging

import splunk.Intersplunk
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_common import is_valid_dict, is_valid_list, dict_to_search_field_value

from ITOA.setup_logging import setup_logging
from itsi.objects.itsi_service import ItsiService

LOGGER = "itsi.command.getservice"

logger = setup_logging("itsi_searches.log", LOGGER, level=logging.ERROR, is_console_header=True)


def parseArgs():
    '''
    Parse the arguments out, we're expecting only one argument - service
    '''
    i = 1
    service = None
    debug = False
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg.find("service=") != -1:
            service = arg[arg.find("service=") + 8:]
        elif arg.find('debug=') != -1:
            debug = arg[arg.find('debug=') + 6:]
        else:
            splunk.Intersplunk.parseError(_("Invalid argument '%s'") % arg)
        i += 1

    if service is None or len(service) == 0:
        service = "*"

    if debug:
        logger.setLevel(logging.DEBUG)

    return {"service": service}


args = parseArgs()
settings = dict()
records = splunk.Intersplunk.readResults(settings=settings, has_header=True)
try:
    owner = "nobody"  # entities can only exist at app-level
    service_object = ItsiService(settings['sessionKey'], 'nobody')
    results = []
    #ITOA-1190 Bad keys - These are keys that outputResults doesn't like, so we need to do extra processing.
    bad_keys = [
        'kpis',
        'services_depending_on_me',
        'services_depends_on',
        'entity_rules'
    ]
    pre_results = service_object.get_bulk(owner)
    service = args['service']
    reg_ex = None
    if '*' in service:
        #Convert the * into an appropriate regex pattern
        reg_ex = re.compile("^" + str(service).replace('*', '.*?') + "$")
    else:
        reg_ex = re.compile("^" + str(service) + "$")

    logger.debug('Processing results set.')
    for r in pre_results:
        #splunk treats _field as hidden fields, we want the service id, so we expose it.
        r['serviceid'] = r['_key']
        logger.debug("Current Service: %s" % r['_key'])
        for bad in bad_keys:
            logger.debug('Current bad: %s' % bad)
            if r.has_key(bad):
                tempobject = r[bad]
                if bad == "kpis":
                    tempkpislist = []
                    tempshkpislist = []
                    for kpi in tempobject:
                        logger.debug('Current kpi: %s' % kpi)
                        logger.debug('Adding in kpi to list, key:%s, urgency:%s' % (kpi['_key'], kpi['urgency']))
                        tempkpislist.append("id=" + str(kpi['_key']) + "~~~urgency=" + str(int(kpi['urgency'])))
                    logger.debug("Finalized KPI list: %s" % tempkpislist)
                    r[bad] = tempkpislist
                elif (bad == 'services_depending_on_me') or (bad == 'services_depends_on'):
                    tempitemlist = []
                    for service in tempobject:
                        tempserviceid = ''
                        tempkpis = ''
                        tempserviceid = service['serviceid']
                        for kpi in service['kpis_depending_on']:
                            tempkpis = tempkpis + kpi + ","
                        outputTemplate = "serviceid=" + str(tempserviceid) + "~~~kpis=" + str(tempkpis[:-1])
                        tempitemlist.append(outputTemplate)
                    r[bad] = tempitemlist
                elif bad == 'entity_rules':
                    entity_rule_strs = []
                    if is_valid_list(tempobject):
                        for entity_rule in tempobject:
                            if is_valid_dict(entity_rule):
                                entity_rule_strs.append(dict_to_search_field_value(entity_rule))
                            else:
                                # Entry seems incorrect, but lets just return it as is - dont need to fail search for this
                                entity_rule_strs.append(str(entity_rule))
                    else:
                        # Entry seems incorrect, but lets just return it as is - dont need to fail search for this
                        entity_rule_strs.append(str(tempobject))
                    r[bad] = entity_rule_strs
                else:
                    assert False
        # Guard against ITOA-1190 in general for any other values that have not
        # been serialized above into a string. Even the ones in bad_keys may
        # not have been serialized above if they are None. This guard will protect
        # primarily against that and any other fields we may add that we dont care
        # about serializing in a specific way.
        for key, value in r.items():
            if is_valid_list(value):
                r[key] = [str(x) for x in value]
            elif not isinstance(value, basestring):
                r[key] = str(value)

        if reg_ex.match(r['_key']):
            logger.debug("Current service matches regex, outputing results for this row: %s" % r)
            results.append(r)
            logger.debug("Result appended to current results object.")
    logger.debug("Finished processing all services.")
except Exception as e:
    logger.exception(e)
    results = splunk.Intersplunk.generateErrorResults(e)

splunk.Intersplunk.outputResults(results)

