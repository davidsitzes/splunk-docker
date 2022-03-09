# Copyright (C) 2005-2016 Splunk Inc. All Rights Reserved.


"""
Shared Component - apifilesave

Rest api server stub for file save api

"""
import os.path as op
import sys
import splunk.rest.external as external

from splunk.clilib.bundle_paths import make_splunkhome_path

current_dir = op.dirname(op.abspath(__file__))
sys.path.insert(0, current_dir)
# Fixing code-clobbering issue in Splunk apps by overwriting rest.external's path variable to only this app.
external.__path__ = [current_dir]

# Ensure our libraries are always found first.
# Adding current app's lib/app_common to sys.path
sys.path.insert(1, make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib', 'SA_ITOA_app_common']))

# Import the custom rest handler.
from apifilesave.filesave import FilesaveRestHandler
