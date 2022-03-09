# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

"""
Exposes Cherrypy/Splunkweb endpoints that do basic CRUD on objects for maintenance purposes
"""

import sys
import json

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.rest_interface_provider_base import ItoaInterfaceProviderBase
from itsi.itoa_rest_interface_provider.itoa_rest_interface_provider import handle_exceptions
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import ObjectOperation, ITOAError
from maintenance_services.constants import MAINTENANCE_CALENDAR_OBJECT_TYPE
from maintenance_services.objects.maintenance_calendar import MaintenanceCalendar

logger = setup_logging("maintenance_services.log", "maintenance_services.MaintenanceServicesRestProvider")
logger.debug("Initialized maintenance services log")


class MaintenanceServicesRestProvider(ItoaInterfaceProviderBase):
    """
    MaintenanceServices provides backend interaction via REST for maintenance operations like CRUD for maintenance
    configuration
    """

    SUPPORTED_OBJECT_TYPES = [MAINTENANCE_CALENDAR_OBJECT_TYPE]
    SUPPORTED_OBJECT_TYPES_FOR_BY_ID_OPS = SUPPORTED_OBJECT_TYPES

    def _get_supported_object_types(self):
        """
        An app or an SA might want to query the supported object types
        Return a list of supported object types
        No Access Control enforcement on this endpoint...

        @type: object
        @param self: The self reference

        @type: list
        @return: an array of supported object types
        """
        if self._rest_method != 'GET':
            raise ITOAError(status="500", message=_("Unsupported HTTP method"))
        return self.render_json(self.SUPPORTED_OBJECT_TYPES)

    def _bulk_crud(self, owner, object_type, **kwargs):
        """
        CRUD interface for IT context objects (routes without an ID)

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        """
        with handle_exceptions():
            log_prefix = '[crud_general] '
            op = ObjectOperation(logger, self._session_key, self._current_user)

            if object_type not in self.SUPPORTED_OBJECT_TYPES:
                raise ITOAError(status="400", message=_("Unsupported object type %s.") % object_type)

            if owner != "nobody":
                raise ITOAError(status="500", message=_("Maintenance objects can only exist at app level (owner='nobody')."))

            if self._rest_method in ['POST', 'PUT']:
                result = op.create(log_prefix, owner, object_type, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'GET':
                result = op.get_bulk(log_prefix, owner, object_type, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'DELETE':
                op.delete_bulk(log_prefix, owner, object_type, kwargs)
            else:
                raise ITOAError(status="405", message=_("Unsupported HTTP method"))

    def _get_object_count(self, owner, object_type, **kwargs):
        """
        Get the object count

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @type: string
        @param aggregation: aggregation operation request in the REST call

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with identifier (for POST or PUT), json with object collection (for GET)

        """
        with handle_exceptions():
            if self._rest_method != 'GET':
                raise ITOAError(status="500", message=_("Unsupported HTTP method"))

            filter_data = kwargs.get('filter')
            try:
                if filter_data is not None:
                    filter_data = json.loads(filter_data)
            except ValueError:
                logger.exception("ValueError, could not parse filterdata=%s", filter_data)
                filter_data = None
            except TypeError:
                logger.exception("TypeError, could not parse filterdata=%s", filter_data)
                filter_data = None

            maintenance_window_obj = MaintenanceCalendar(self._session_key, self._current_user)

            return self.render_json({"count": len(maintenance_window_obj.do_rbac_filtering(
                owner,
                sort_key=None,
                sort_dir=None,
                filter_data=filter_data,
                fields=None,
                skip=None,
                limit=None,
                req_source='_get_object_count',
                transaction_id=None))})

    def _crud_by_id(self, owner, object_type, object_id, **kwargs):
        """
        CRUD operations for maintenance services objects by their identifiers

        @type: object
        @param self: The self reference

        @type: string
        @param owner: owner of the object

        @type: string
        @param object_type: maintenance object type

        @type: string
        @param object_id: existing maintenance object identifier

        @param: dict
        @param **kwargs: Key word arguments extracted from the POST body

        @rtype: dict
        @return: json with object
        """
        with handle_exceptions():
            log_prefix = '[crud_general] '

            op = ObjectOperation(logger, self._session_key, self._current_user)

            if object_type not in self.SUPPORTED_OBJECT_TYPES_FOR_BY_ID_OPS:
                raise ITOAError(status="400", message=_("Unsupported object type %s.") % object_type)

            if self._rest_method == 'GET':
                retval = op.get(log_prefix, owner, object_type, object_id, kwargs, raw=True)
                if retval is None:
                    raise ITOAError(status=404, message=_("Object not found."))
                try:
                    return self.render_json(retval)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method in ['PUT', 'POST']:
                result = op.edit(log_prefix, owner, object_type, object_id, kwargs, raw=True)
                try:
                    return self.render_json(result)
                except (TypeError, ValueError) as e:
                    logger.exception(e)
                    raise ITOAError(status="500", message=_("Unexpected server error occurred. Please check logs."))
            elif self._rest_method == 'DELETE':
                op.delete(log_prefix, owner, object_type, object_id, kwargs)
            else:
                raise ITOAError(status="405", message=_("Unsupported HTTP method %s.") % self._rest_method)
