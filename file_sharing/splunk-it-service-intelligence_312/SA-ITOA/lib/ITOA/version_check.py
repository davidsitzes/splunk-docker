# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
Module for VersionCheck class and related classes
'''
import re
from splunk.appserver.mrsparkle.lib import i18n

class VersionCheck(object):
    '''
        Class to check version
        Note we do support only dotted version for example
            1
            1.0
            1.0.1.2
            1.0.1.234
            #NOTE: This does not support the following formats
            like v1.0
            10.0.2-r1
            10.0.4-build 2323
            10.0.5-RC2 etc
    '''

    VERSION_REGEX = r'\d+(\.\d+)*$'

    @staticmethod
    def validate_version(version, is_accept_empty=True):
        '''
            validate version

        @type version: string
        @param version: version number

        @type: boolean
        @param is_accept_empty: should emtpy version be considered valid, useful during migration

        @return: true|false
        '''
        # Handle empty string
        if version == "" and is_accept_empty:
            return True
        match = re.match(VersionCheck.VERSION_REGEX, version)
        return match is not None

    @staticmethod
    def compare(dest_version, src_version):
        '''
        @param dest_version: version
        @type dest_version: string
        @param src_version: version against, it does comparison
        @type src_version: string
        @return:
            1 if dest_version > src_version
            0 if dest_version = src_version
            -1 if dest_version < src_version
        '''
        # We're disabling these checks because the return statements and branches
        # Could be refactored at the cost of readability.  And I think readability
        # Is more important here
        # pylint: disable=too-many-return-statements, too-many-branches
        if not VersionCheck.validate_version(dest_version):
            raise ValueError(_("dest_version:%s format is invalid"), dest_version)
        if not VersionCheck.validate_version(src_version):
            raise ValueError(_("src_version:%s format is invalid"), src_version)

        dest_split_versions = dest_version.split(".") if dest_version != "" else []
        src_split_versions = src_version.split(".") if src_version != "" else []

        if len(dest_split_versions) == 0 and len(src_split_versions) == 0:
            return 0
        elif len(dest_split_versions) == 0 and len(src_split_versions) > 0:
            return -1

        index = 0
        for index in range(0, len(dest_split_versions)):
            if len(src_split_versions) > index:
                if int(dest_split_versions[index]) > int(src_split_versions[index]):
                    return 1
                elif int(dest_split_versions[index]) < int(src_split_versions[index]):
                    return -1
                else:
                    continue
            else:
                break

        if (len(dest_split_versions) == len(src_split_versions) and
                index == len(dest_split_versions) - 1):
            return 0
        elif len(dest_split_versions) < len(src_split_versions):
            # Check if any of values are more than 0
            # in this case we need to increase index value because we compared old one
            index = index + 1
            while index < len(src_split_versions):
                if int(src_split_versions[index]) > 0:
                    return -1
                index = index + 1
        else:
            while index < len(dest_split_versions):
                if int(dest_split_versions[index]) > 0:
                    return 1
                index = index + 1
        # Seems like all other values are zeros
        return 0

