"""
This module/package contains implementations for ITOA shareable APIs
and ITSI specific implementations
"""

from splunk.clilib.bundle_paths import make_splunkhome_path

# pylint: disable = import-error
from lib.ITOA.itoa_common import add_to_sys_path
# pylint: enable = import-error

# Add lib path to import paths for packages
add_to_sys_path([make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib'])])
