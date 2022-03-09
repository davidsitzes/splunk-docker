# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

'''
A script that allows for the following:
    - Set default team.
'''

print ('#############################\n'
    'This script sets the default team to the Global team in the kvstore.\n'
    '#############################\n')

import sys
import getpass

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk import auth

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from itsi.itsi_utils import ItsiSettingsImporter

SPLUNKD_HOST_PATH = 'https://localhost'
SPLUNKD_PORT = '8089'
SPLUNK_USER = 'admin'

if __name__=='__main__':
    retries = 3
    splunkd_port = None

    while not splunkd_port and retries:
        splunkd_port = raw_input(('Enter splunkd port. Press enter to use'
            ' %s: ')%SPLUNKD_PORT)
        if not splunkd_port.strip():
            splunkd_port = SPLUNKD_PORT
        else:
            try:
                int(splunkd_port)
            except ValueError:
                retries -= 1
                print 'Invalid port. Try again. {} tries left'.format(retries)
                continue
    if not retries and not splunkd_port:
        print 'You have reached the maximum number of retries. Run the script again.'
        sys.exit(1)

    hostpath = SPLUNKD_HOST_PATH + ':' + splunkd_port + ''
    print 'Your Splunk instance is: %s' % hostpath

    retries = 3
    session_key = None
    while not session_key and retries:
        username = raw_input(('\nEnter your splunk username. Press enter to use '
            '%s: ' )%SPLUNK_USER)
        if not username.strip():
            username = SPLUNK_USER
        password = getpass.getpass(prompt='Enter password for %s: ' % username)
        print 'Trying to obtain a Splunk session key...'

        try:
            session_key = auth.getSessionKey(username, password, hostpath)
        except Exception as e:
            retries -= 1
            print 'Encountered an error when trying to log you in - ' + str(e)
            print 'Let\'s try again...%d retries left'% retries

    if not retries and not session_key:
        print 'You have reached the maximum number of retries. Run the script again.'
        sys.exit(1)
    print 'Splunk session key successfully obtained'
    print 'Attempting to restore default team setting...'

    itsi_settings_importer = ItsiSettingsImporter(session_key=session_key)
    success = itsi_settings_importer.import_team_setting('nobody', from_conf=False)
    if success:
        print 'Success'
    else:
        print 'Failed...Please check internal logs'
        sys.exit(1)
