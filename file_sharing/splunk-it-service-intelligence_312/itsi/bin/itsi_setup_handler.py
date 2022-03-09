# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import splunk.admin as admin
import splunk.entity as en

from install.itsiinstaller import ITInstaller

class ConfigITApp(admin.MConfigHandler):

    '''
    Set up supported arguments
    '''
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['IT_do_install']:
                self.supportedArgs.addOptArg(arg)

    '''
    Lists configurable parameters
    '''
    def handleList(self, confInfo):

        stanza = "general_settings"

        confInfo[stanza].append('IT_do_install', '1')

    '''
    Controls parameters
    '''
    def handleEdit(self, confInfo):
        name = self.callerArgs.id
        args = self.callerArgs

        if self.callerArgs.data['IT_do_install'][0] in [1,'1']:
            # Run the installer
            ITInstaller.doInstall(sessionKey=self.getSessionKey())

        ## reload the app to trigger splunkd restart
        #self.handleReload()


    def handleReload(self, confInfo=None):
        """
        Handles refresh/reload of the configuration options
        """
        try:
            refreshInfo = en.refreshEntities('apps/local/itsi', sessionKey=self.getSessionKey())
        except Exception as e:
            raise


# initialize the handler
admin.init(ConfigITApp, admin.CONTEXT_NONE)