# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
from __future__ import absolute_import

import sys


try:
    from . import solnlib
except ImportError:
    try:
        from ... import solnlib
    except (ImportError, ValueError):
        import solnlib

    sys.modules['%s.solnlib' % __name__] = solnlib

try:
    from . import splunklib
except ImportError:
    try:
        from ... import splunklib
    except (ImportError, ValueError):
        import splunklib

    sys.modules['%s.splunklib' % __name__] = splunklib
