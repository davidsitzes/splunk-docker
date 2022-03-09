# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Exposes Cherrypy/Splunkweb endpoints to accept CSV bulk import data and metadata, and to
provide preview information for both for the UI.

"""
import cherrypy
import json
import sys

import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.auth import getCurrentUser

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

# try:  # noqa: F401
#     from typing import Iterator, Sequence, Dict, List, Text, Type, Any, Optional, Union, Callable, Tuple, Generator  # noqa: F401
# except:  # noqa: F401
#     pass  # noqa: F401

# HACK: Import the supported objects to trigger loading of everything
from ITOA.fix_appserver_import import FixAppserverImports
FixAppserverImports.fix()

from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from ITOA.controller_utils import handle_json_in

from itsi.csv_import.itoa_bulk_import_rest_interface_provider import ItsiBulkImportInterfaceProvider
from itsi.csv_import.itoa_bulk_import_preview_utils import ServicePreviewer, EntityPreviewer, TemplatePreviewer, RowPreviewer

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

logger = setup_logging('itsi_config.log', 'itsi.controllers.itoa_csv_interface')
logger.debug('Initialized ITOA bulk-import interface log')


class itoa_csv_interface(ITOABaseController, controllers.BaseController, ItsiBulkImportInterfaceProvider):
    """
    ITOA_CSV_Interface provides the endpoints for uploading, previewing, and committing
    bulk imports to the spool for import to KVStore
    """

    def _setup_provider(self):
        return self._setup(cherrypy.session['sessionKey'], getCurrentUser()['name'], cherrypy.request.method)

    ##############################################################################
    # Bulk Import
    ##############################################################################
    @route('/:action=csv_upload/:owner')
    @expose_page(must_login=True, methods=['POST'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def csv_upload(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Loads entities/services into w/e backend storage is currently defined
        @param action: action param
        @param owner: the owner of this upload
        @param *args: not used
        @param **kwargs: keyword arguments extracted from the request.  Expected keywords: filename, transaction_id, csvfile
        @return dict of metadata derived from upload: CSV headers, array of sample rows, total data length
        @type json string
        """
        self._setup_provider()
        self._confirm_contract(action, 'csv_upload', ['POST'], kwargs, ['transaction_id', 'csvfile'])
        return self._csv_upload(kwargs['transaction_id'], kwargs['csvfile'].file)

    @route('/:action=from_search/:owner')
    @expose_page(must_login=True, methods=['GET'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def from_search(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Loads entities/services into w/e backend storage is currently defined
        @param self: Self reference
        @param action: action param
        @param **kwargs: key word arguments extracted from the request

        @return created keys or error message.
        @type json string
        """
        self._setup_provider()
        self._confirm_contract(action, 'from_search', ['GET'], kwargs, ['transaction_id', 'search'])
        return self._csv_from_search(kwargs['transaction_id'], kwargs['search'], kwargs['index_earliest'], kwargs['index_latest'])

    @route('/:action=service_preview/:owner/')
    @expose_page(must_login=True, methods=['GET'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def service_preview(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Provide preview of service objects in the spool, given a bulk import specification.
        @param action: must be 'service_preview'
        @param owner: The owner of the transaction
        @param *args: not used
        @param **kwargs: keyword arguments extracted from the request.  Required field: transaction_id, columns
        @return A JSON list of the requested objects, or an error message.
        @type unicode
        """
        self._setup_provider()
        self._confirm_contract(action, ServicePreviewer.action, ['GET'], kwargs, ['transaction_id', 'columns'])
        return self._csv_object_preview(kwargs['transaction_id'], json.loads(kwargs['columns']), owner, ServicePreviewer)

    @route('/:action=template_preview/:owner/')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def template_preview(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Provide a preview of which services will be linked to templates.

        @param action:
        @type: string

        @param owner:
        @type: string

        @param *args: not used

        @param **kwargs: Keywork arguments extracted from the request. Required fields: transaction_id and columns
        @type: dict

        @return: A JSON list of ImportTemplate objects
        @type: unicode
        """
        try:
            data = json.loads(kwargs.get('data', None))
        except (TypeError, ValueError):
            data = {}

        self._setup_provider()
        self._confirm_contract(action, TemplatePreviewer.action, ['GET'], data, ['transaction_id', 'columns'])
        return self._csv_object_preview(data['transaction_id'], data['columns'], owner, TemplatePreviewer)

    @route('/:action=entity_preview/:owner/')
    @expose_page(must_login=True, methods=['GET'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def entity_preview(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Provide preview of entity objects in the spool, given a bulk import specification
        @param action: must be 'service_preview'
        @param owner: The owner of the transaction
        @param *args: not used
        @param **kwargs: keyword arguments extracted from the request.  Required field: transaction_id, columns
        @return A JSON list of the requested objects, or an error message.
        @type unicode
        """
        self._setup_provider()
        self._confirm_contract(action, EntityPreviewer.action, ['GET'], kwargs, ['transaction_id', 'columns'])
        return self._csv_object_preview(kwargs['transaction_id'], json.loads(kwargs['columns']), owner, EntityPreviewer)

    @route('/:action=row_preview/:owner/')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def row_preview(self, action, owner, *args, **kwargs):
        self._setup_provider()
        self._confirm_contract(action, RowPreviewer.action, ['GET'], kwargs, ['transaction_id', 'spec'])

        try:
            spec = json.loads(kwargs['spec'])
        except (TypeError, ValueError):
            spec = {}

        return self._csv_object_preview(kwargs['transaction_id'], spec, owner, RowPreviewer)

    @route('/:action=finalize/:owner/')
    @expose_page(must_login=True, methods=['POST'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type='service', logger=logger)
    def finalize(self, action, owner, *args, **kwargs):
        # type: (Text, Text, *Any, **Any) -> Text
        """
        Accept the final version of the Bulk Import Specification from the customer, and write
        it to the spool directory to begin the bulk import asynchronous process.
        @param action: must be 'service_preview'
        @param owner: The owner of the transaction
        @param *args: not used
        @param **kwargs: keyword arguments extracted from the request.  Required field: transaction_id, columns
        @return Either a JSON success message, or a JSON error message.
        @type unicode
        """
        self._setup_provider()
        self._confirm_contract(action, 'finalize', ['POST'], kwargs.get('data', {}), ['transaction_id', 'columns'])

        data = kwargs['data']
        return self._csv_commit_upload(data['transaction_id'], data['columns'], owner)
