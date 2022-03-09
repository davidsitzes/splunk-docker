# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
import shutil
from os import listdir,path
import splunk.rest as rest
import json

class ITSIDSSetupHandler(object):
    '''
    Custom itsi setup and validation
    '''
    def rename_lookup_files(self, lookup_path):
        '''
        Looks for files in the lookup directory and renames anything with a .default extension
        '''
        all_files = listdir(lookup_path)
        for f in all_files:
            if f.endswith(".csv.default"):
                #Remove the .default and save
                new_name = f[:-8]
                shutil.copyfile(path.join(lookup_path,f), path.join(lookup_path, new_name))

    def ds_setup(self, serverclass, aim):
        '''
        Run the distributed app installation ITSI specific code
        @param serverclass: The specific serverclass we're configuring for
        @param aim: The application installation manager object
        '''
        #Rename the files that we have in our directory
        #Establish that setup is complete
        if serverclass != "itsi_indexers":
            lookup_directory = path.join(aim.get_staging_path(), serverclass, "itsi", "lookups")
            self.rename_lookup_files(lookup_directory)
            #Establish that we are finished
            aim.upsert_conf(serverclass, "itsi", "app.conf")
            aim.upsert_stanza(serverclass, "itsi", "app.conf", "install")
            aim.upsert_stanza_key(serverclass, "itsi", "app.conf", "install", "is_configured", "1")
        return True

    def ds_validate(self, serverclass, aim):
        '''
        Run the distributed app installation ITSI specific validation
        @param serverclass: The specific serverclass we're configuring for
        @param aim: The application installation manager object
        '''
        #Make sure that the app.conf is set appropriately
        if serverclass != "itsi_indexers":
            configured = aim.get_stanza_key(serverclass,"itsi","app.conf","install","is_configured")
            #Extract the key - its nested at the cost of giving the app developer full
            #knowledge of the context
            #TODO: Determine if the app developer needs full access to the context
            flag = configured['files']['local']['app.conf']['install']['is_configured']
            if flag not in ["1", 1]:
                return False

        #Validation is finished
        return True

    def distributed_final_setup(self, serverclass, aim):
        '''
        This is the VERY last setup procedure that gets called before we deploy out to the deployment server
        This is only done for remote installs - because the final information that we have when running this call
        is special
        @param serverclass: The serverclass passed in that we're configuring for
        @type serverclass: string

        @param aim: The aim object
        @type aim:  The aim object.  See SA-AppInstallation/lib/aim.py.  More notes below

        Here are the unique variables:
        aim.session_key -- Our local session key
        aim.ds_session_key -- Our distributed server session key (can be None for a local install)
        aim.user_serverclasses -- A JSON file of what the user has selected for their serverclass config
                               -- It should look like someone has a different
                               -- Note that we CAN MODIFY what the deployment server is sending out for
                               -- its final config
                               -- None for a local install
        aim.use_host -- (Debug only) if we are aliasing requests as though we were another host
        aim.splunk_env -- A reference to common utilities used to determine the environment
        As always, trust but verify
        '''
        #Currently no configuration needed on the indexing tier
        if serverclass == "itsi_indexers":
            return True

        #Compare what's in the deployment clients to what the user has.
        if aim.user_serverclasses != None:
            specified_serverclass = aim.user_serverclasses.get(serverclass,None)
            if specified_serverclass == None or len(specified_serverclass) == 0:
                #The user doesn't have a configuration matching this one - skip
                return True
        else:
            specified_serverclass = {} #Set to empty so we skip the loop

        found_machine_types = set()
        #First thing we want to do, if aim.splunk_env exists, use it to grab the deployment clients
        if aim.splunk_env and aim.ds_session_key:
            clients = aim.splunk_env.get_deployment_clients(aim.ds_session_key,aim.use_host)
        else:
            #Get the local server info - make it look like a deployment client
            uri = '/services/server/info'
            get_args = {"output_mode":"json"}
            response, content = rest.simpleRequest(uri, sessionKey=aim.session_key, getargs=get_args, raiseAllErrors=False)
            if response.status != 200:
                raise Exception(content)
            localhost = json.loads(content)
            localhost_content = localhost["entry"][0]["content"]
            clients = [] #Set this to an empty list so we skip it entirely
            machine_type = localhost_content.get("os_name",None)
            if machine_type != None:
                found_machine_types.add(machine_type.lower())

        for machine_filter in specified_serverclass:
            #We found a key starting with whitelist, we can make this look at something to go
            if isinstance(machine_filter,basestring) and machine_filter.lower().find("whitelist") == 0:
                if machine_filter.lower() == "whitelist-size":
                    continue
                machine_name = specified_serverclass.get(machine_filter,None)
                for c in clients:
                    content = c.get("content",None)
                    if content is None:
                        continue
                    if (content.get("dns","").find(machine_name) != -1 or
                        content.get("hostname","").find(machine_name) != -1 or
                        content.get("ip","").find(machine_name) != -1):
                        #We have a match!  Get the machine type
                        machine_type = content.get("utsname",None)
                        if machine_type is not None:
                            found_machine_types.add(machine_type)

        #Now, prior to deployment, lets delete any SA-Anaconda things that will slow down the transfer
        anaconda_machine_types = {"linux":"linux_x86_64","darwin":"darwin_x86_64","windows":"windows_x86_64"}
        keep_folders = []
        #This will likely be anything except linux_64
        for machine, folder in anaconda_machine_types.items():
            for x in found_machine_types:
                if x.find(machine) != -1 and folder not in keep_folders:
                    keep_folders.append(folder)
        #So now we have a list of folders that we are okay getting rid of
        #aim.staging_full_path  -- this is where we stage our temporary files
        anaconda_bin = path.join(aim.staging_full_path,serverclass,"Splunk_SA_Anaconda","bin")
        if path.exists(anaconda_bin):
            for folder in listdir(anaconda_bin):
                if folder not in keep_folders and path.exists(path.join(anaconda_bin, folder)):
                    shutil.rmtree(path.join(anaconda_bin, folder))
        #Apply the machine types filter to this, remember it doesnt exist for local installs
        if aim.user_serverclasses:
            aim.user_serverclasses[serverclass]["machineTypesFilter"] = ",".join(found_machine_types)
        return True
