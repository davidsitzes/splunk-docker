import splunk.admin  as admin
import splunk.bundle as bundle
import logging
import logging.handlers
import splunk.rest
import splunk.clilib.cli_common
import re

class GenerateXMLHandler(admin.MConfigHandler):
	def setup(self):
		# Need to setup the allowed args
		for arg in ['view_name', 'dash_script', 'dash_stylesheet', 'title', 'app_name']:
			self.supportedArgs.addOptArg(arg)

	def handleList(self, confArgs):
		# Implicitly used for some operations, and all handler classes must implement this
		return None

	''' This XML portion should never change based on tabs/panels for all applications.
	    Since the script CSS, JS, and page title can vary, we plug these in '''
	def __generateBaseXML(self):
		return '\n'.join(['<dashboard script="%s"' % self.callerArgs.data['dash_script'][0], \
			   ' stylesheet="%s"' % self.callerArgs.data['dash_stylesheet'][0], \
			   '>', \
			   '<label>%s</label>' % self.callerArgs.data['title'][0], \
			   '<row>', \
			   '<html>', \
			   '<div class="context-panel" id="context-panel"></div>', \
			   '</html>', \
			   '</row>', \
			   '<row id="tabs">', \
			   '<panel id="tabs_panel">', \
			   '<html>', \
			   '<div class="modal fade" id="new-tab-modal" tabindex="-1" role="dialog"></div>', \
			   '<div class="modal fade" id="delete-tab-modal" tabindex="-1" role="dialog"></div>', \
			   '<ul id="tabs-container" class="nav nav-tabs">', \
			   '</ul>', \
			   '</html>', \
			   '</panel>', \
			   '</row>'])

	''' This filters all the keys in each stanza, and only returns the keys that contain
	    the pattern "row" something, since this would be a key for the row '''
	def __filterRows(self, tabDict):
		keys = tabDict.keys()
		matchPattern = re.compile('row.+')
		rowKeys = list(filter((lambda key: not matchPattern.search(key) == None), keys))
		rowKeys.sort()
		return rowKeys

	def handleEdit(self, confArgs):
		# Define the endpoint to post to; this can vary based on app and view name
		endpoint = '/servicesNS/nobody/%s/data/ui/views/%s' % \
		  (self.callerArgs.data['app_name'][0], self.callerArgs.data['view_name'][0])

		# Generates the XML that does not change based on panel/row configuration
		baseXml = self.__generateBaseXML()

		# Given the input view name, pulls the list and ordering of tabs from the conf file
		view_name = self.callerArgs.data['view_name'][0]
		confObj = splunk.clilib.cli_common.getConfStanza('itsi_module_viz', view_name)
		tabsIdList = confObj['tabs'].split(',');

		# Generates the XML for rows and panels associated with those rows
		for tabId in tabsIdList:
			curr_tab = self._getTabDictFromConf(confObj,tabId)
			rows = self.__filterRows(curr_tab)
			for row in rows:
				panelXml = ['<row depends="$%s$">' % curr_tab['control_token']]
				panels = curr_tab[row].split(',')
				for panel in panels:
					app, panelName = panel.split(':')
					panelString = '<panel ref="%s" app="%s"></panel>' % (panelName, app)
					panelXml.append(panelString)
				panelXml.append('</row>')

				# Appends the row of panels to base XML
				baseXml += '\n'.join(panelXml)

		# Closes the dashboard tag
		baseXml += '\n</dashboard>'

		# POSTs the generated XML to the view
		response, content = splunk.rest.simpleRequest(endpoint, method="POST", sessionKey=self.getSessionKey(), \
		 postargs={'eai:data' : baseXml})

	'''
	Helper function to create Tab dictionary object from confObj
	@param confObj JSON object that contains all information under view stanza
	@param tabId ID for the given tab
	'''
	def _getTabDictFromConf(self, confObj, tabId):
		return dict((k[len(tabId)+1:],confObj[k]) for k in confObj.keys() if re.match('%s\.'%tabId, k) is not None)


admin.init(GenerateXMLHandler, admin.CONTEXT_APP_ONLY)
