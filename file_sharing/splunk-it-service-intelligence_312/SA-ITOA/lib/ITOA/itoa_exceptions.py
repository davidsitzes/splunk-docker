# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
"""
Contains different defined exceptions

ITOA-8115: remove dependencies of SA-ITOA from SA-ITSI-Licensechecker.
Manually copied to apps/SA-ITSI-Licensechecker/lib/ITOA/itoa_exceptions.py
If you change this file, please also update the copy.
"""


class ItoaError(Exception):
    """
    Generic exception class with some generic defaults
    If it gets the logger passed into it, it will also log the
    error appropriately
    """
    def __init__(self, message, logger, log_prefix='[ITOA Error]', status_code=500):
        super(ItoaError, self).__init__(message)
        self.message = message
        # if this error ends up making it up to REST, allow a status code to be declared
        self.status_code = status_code
        if logger is not None:
            logger.error(log_prefix + message)

    def __str__(self):
        return self.message


class UnsupportedObjectTypeError(ItoaError):
    """
    Indicates that the object type passed in is unsupported
    """
    def __init__(self, message, logger=None, status_code=400):
        super(UnsupportedObjectTypeError, self).__init__(message, logger, status_code=status_code)


class ItoaValidationError(ItoaError):
    """ Bad request exception result in 400 error """
    def __init__(self, message, logger, log_prefix='[ITOA Validation Error]', status_code=400):
        super(ItoaValidationError, self).__init__(message, logger, log_prefix, status_code)


class ItoaDatamodelContextError(ItoaError):
    """
    Indicates that the datamodel context(for datamodel, its objects or fields) being looked up could not be found
    """
    def __init__(self, message, logger, log_prefix='[ITOA Datamodel Context Error]', status_code=400):
        super(ItoaDatamodelContextError, self).__init__(message, logger, log_prefix, status_code)


class ItoaAccessDeniedError(ItoaError):
    def __init__(self, message, logger, log_prefix='[ITOA Access Denied Error]', status_code=403):
        if 'access denied' not in message.lower():
            message = _('Access denied. %s') % message
        super(ItoaAccessDeniedError, self).__init__(message, logger, log_prefix, status_code)
