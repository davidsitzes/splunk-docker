# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import Request
from .access_control_controller_utils import EnforceRBAC
from ITOA.controller_utils import ITOAError

logger = setup_logging("itsi.log", "itsi.rest_handler_splunkd.itoa_interface.RBAC")


class SplunkdRequest(Request):
    """
    Splunkd request specific implementation to hook into access control for RBAC
    """
    def __init__(
        self,
        rest_method,
        rest_method_args,
        logger,
        session_key,
        current_user,
        owner,
        object_type,
        object_id,
        is_bulk_op=False
    ):
        """
        Basic constructor

        @type: string
        @param rest_method: the current REST method - GET/POST/PUT/DELETE

        @type: dict
        @param rest_method_args: args passed into REST method

        @type: object
        @param logger: logger to use

        @type: string
        @param session_key: splunkd session key for current REST request

        @type: string
        @param current_user: current user initiating the REST request

        @type: string
        @param owner: owner initiating the REST request

        @type: string
        @param object_type: type of ITOA object

        @type: string
        @param object_id: id of ITOA object

        @type: boolean
        @param is_bulk_op: indicates if this is a bulk type request
        """
        super(SplunkdRequest, self).__init__(rest_method_args, rest_method, logger, session_key, current_user)
        self._qp.set_owner(owner)
        self._qp.set_id(object_id)
        self._qp.set_object_type(object_type)
        self._is_bulk_op = is_bulk_op
        self.method = rest_method

    def get_method(self):
        """
        Gets current REST method

        @rtype: string
        @return: REST method name GET/PUT/POST/DELETE
        """
        return self.method

    def validate(self, params, operation, logger):
        """
        # Not useful for splunkd endpoints
        """
        pass

    def is_bulk(self):
        """
        Gets if current REST method is for bulk operations

        @rtype: boolean
        @return: True if bulk operation, False otherwise
        """
        return self._is_bulk_op


class EnforceRBACSplunkd(EnforceRBAC):
    def __init__(self, is_bulk_op=False):
        """
        Basic contructor

        @type: boolean
        @param is_bulk_op: indicates if this is a bulk type request
        """
        super(EnforceRBACSplunkd, self).__init__(logger)
        self.is_bulk_op = is_bulk_op

    def validate_input(self, kwargs, logger):
        """
        # Not useful for splunkd endpoints
        """
        pass

    def update_request(self, decorated, decorated_self, args):
        """
        Method that implements splunkd controller specific update of request info

        @type: reference
        @param decorated: the decorated function reference

        @type: reference
        @param decorated_self: the decorated function's self

        @type: tuple
        @param args: the decorated function's args

        @rtype: None
        @return: None
        """
        if len(args) < 2:
            raise ITOAError(status=400, message=_('Bad Request: Missing required args needed by decorator.'))

        owner = args[0]
        object_type = args[1]

        self.session_key = decorated_self._session_key
        self.user = decorated_self._current_user
        self.method = decorated_self._rest_method

        self.request = SplunkdRequest(
            self.method,
            self.kwargs,
            self.logger,
            self.session_key,
            self.user,
            owner,
            object_type,
            None if len(args) < 3 else args[2],
            is_bulk_op=self.is_bulk_op
        )
        self.operation = self.request.get_operation(self.method)
