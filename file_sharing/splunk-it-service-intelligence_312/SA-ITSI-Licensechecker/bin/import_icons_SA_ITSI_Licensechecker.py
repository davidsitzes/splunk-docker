'''
This script automatically collects icons from glasstable_icon_library.conf and imports them to kvstore icon collection.
It utilizes icon_collection endpoint from apiiconcollection.
Icons with conflicting names not imported. 

@author lbudchenko
'''

import sys, os
import splunk.rest as rest
import xml.dom.minidom
import json
import time
import logging, logging.handlers

ICON_COLLECTION_ENDPOINT = 'services/%s/v1/icon_collection' % 'SA-ITSI-Licensechecker'

def setup_logger(level):
    logger = logging.getLogger('import_icons')
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
 
    file_handler = logging.handlers.RotatingFileHandler(os.environ['SPLUNK_HOME'] + '/var/log/splunk/gt_icon_collection.log', maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s import_icons_SA-ITSI-Licensechecker: %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger
    
# Setup the handler
logger = setup_logger(logging.INFO)

def get_conf(session_key, conf_name, count=0, app='-'):
    '''
    Retrieves data from a conf file
    '''
    getargs = {'output_mode': 'json', 'count': count}
    path = rest.makeSplunkdUri() + 'servicesNS/nobody/' + app + '/configs/conf-' + conf_name
    response, content = rest.simpleRequest(
        path,
        method='GET',
        getargs=getargs,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    if response.status != 200:
        logger.error('Failed to load config: ' + path)

    return {'response': response, 'content': content}

def conf_to_json(conf):
    '''
    Converts response object from conf request to json object formatted for icon_collection endpoint
    Skips duplicates.
    '''
    entries = conf['entry']
    iconsInfo = [entry['content'] for entry in entries]
    icons = []
    seen = []
    for iconInfo in iconsInfo:
        label = iconInfo['iconLabel']
        category = iconInfo['iconCategory']
        if (label,category) in seen:
            continue # skip duplicates
        icon = {
            'title': label,
            'category': category,
            'default_width': iconInfo['defaultWidth'],
            'default_height': iconInfo['defaultHeight'],
            'svg_path': iconInfo['svgPath']
        }
        icons.append(icon)
        seen.append((label,category))
    return icons 

def get_all_icons_from_kvstore(session_key):
    '''
    Requests a list of icons from kvstore to check for conflicts
    '''
    getargs = {'fields': 'title,category'}
    path = rest.makeSplunkdUri() + ICON_COLLECTION_ENDPOINT
    response, content = rest.simpleRequest(
        path,
        method='GET',
        getargs=getargs,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    if response.status != 200:
        logger.error('Failed to load kvstore: ' + str(response.status) + ' ' + str(content))
    return {'response': response, 'content': content}

def put_kvstore(session_key, payload):
    '''
    Saves new icons in kvstore
    '''
    path = rest.makeSplunkdUri() + ICON_COLLECTION_ENDPOINT
    response, content = rest.simpleRequest(
        path,
        method='PUT',
        jsonargs=payload,
        sessionKey=session_key,
        raiseAllErrors=False
    )
    return {'response': response, 'content': content}


def run_script(): 
    session_key = sys.stdin.readline().strip()
    
    if len(session_key) == 0:
       logger.error("Did not receive a session key from splunkd. " + 
                    "Please enable passAuth in inputs.conf for this " +
                    "script\n")
       exit(2)

    try:   
        logger.info('Glasstable icon importer started')
        response = get_conf(session_key, 'glasstable_icon_library')
        conf_icons = conf_to_json(json.loads(response['content']))
        
        kvstore_output = []
        for i in range(5):
            # kvstore might be not available yet: try 5 times with 5sec delay
            kvstore_output = get_all_icons_from_kvstore(session_key)
            if kvstore_output['response']['status'] == '200':
                break
            else:
                time.sleep(5)
        if kvstore_output['response']['status'] != '200':
            logger.error('Error connecting to kvstore')
            return

        kvstore_tuples = [(res['title'],res['category']) for res in json.loads(kvstore_output['content'])['result']]
        new_icons = []
        for icon in conf_icons:
            if (icon['title'],icon['category']) in kvstore_tuples:
                # skip icons already existing in kvstore
                continue
            icon['immutable'] = 1 # mark icons that are being imported
            new_icons.append(icon)  

        if len(new_icons) > 0:
            put_kvstore(session_key, json.dumps(new_icons))
            logger.info('Successfully imported %s icons to kvstore' % str(len(new_icons)))
            
    except Exception, e:
        logger.error(str(e))

if __name__ == '__main__':
    run_script()

    sys.exit(0)