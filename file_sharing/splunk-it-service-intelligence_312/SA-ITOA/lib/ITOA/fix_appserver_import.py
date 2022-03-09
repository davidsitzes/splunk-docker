# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Refer to ITOA-5663 for more details
"""

from splunk.appserver import bundleList
import os
import sys
import copy

class FixAppserverImports(object):
    '''
    This class attempts to remove unwanted imports from the import path
    Usually, the bundleList import is responsible for a dirtier path, so
    we want to nip that in the bud as soon as possible
    But we can't trust that fully since there are likely other sources
    that can dirty the path
    '''
    def __init__(self):
        pass

    @staticmethod
    def fix():
        '''
        Attempt to fix
        '''
        pass


FixAppserverImports.fix()
