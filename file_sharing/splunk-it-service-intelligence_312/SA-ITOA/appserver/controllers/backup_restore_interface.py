# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import os
import shutil
import re
import json

import cherrypy

import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.auth import getCurrentUser

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from SA_ITOA_app_common.solnlib.server_info import ServerInfo

from ITOA.itoa_config import get_supported_objects
from ITOA.itoa_base_controller import ITOABaseController
from ITOA.setup_logging import setup_logging
from itsi.itsi_utils import CAPABILITY_MATRIX
from ITOA.controller_utils import handle_json_in, ObjectOperation, ITOAError
from itsi.backup_restore.backup_restore_rest_provider import BackupRestoreRestProvider
from itsi.backup_restore.itsi_backup_restore_utils import ITSIBackupRestoreJobsQueueAdapter

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-UserAccess', 'lib']))
from user_access_utils import CheckUserAccess

logger = setup_logging('itsi_config.log', 'itsi.controllers.backup_restore_interface')

class BackupRestoreService(ITOABaseController, controllers.BaseController, BackupRestoreRestProvider):
    def __init__(self):
        """
        @param self: The self reference
        """
        super(BackupRestoreService, self).__init__()

    def _setup_provider(self):
        self._setup(cherrypy.session['sessionKey'], getCurrentUser()['name'], cherrypy.request.method)

    @route('/:owner/:object=files/:id')
    @expose_page(must_login=True, methods=['POST', 'GET', 'DELETE'])
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def fileops(self, owner, object, id, **kwargs):
        """
        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target action type

        @type id: basestring
        @param id: file identifier

        @return: file contents (for GET), text (for POST)
        @rtype: binary
        """
        try:
            LOG_PREFIX = '[File Operations] '
            method = cherrypy.request.method
            session_key = cherrypy.session["sessionKey"]
            current_user = getCurrentUser()['name']
            op = ObjectOperation(logger, session_key, current_user)

            dirloc = make_splunkhome_path(['var', 'itsi', 'backups'])
            fileloc = make_splunkhome_path(['var', 'itsi', 'backups', id])

            # ITOA-4820
            if os.path.abspath(dirloc) != os.path.abspath(os.path.join(fileloc, '..')):
                error_message = _('File %s is not a file name, seems to be a path. Paths are not supported.') % id
                logger.error(error_message)
                raise cherrypy.HTTPError(status=400, message=error_message)

            # validate the id
            regex = re.compile(r'^[A-Za-z0-9-]+.zip$')
            if not regex.match(id):
                error_msg = _('File name provided contains characters not supported.')
                logger.error(error_msg)
                raise cherrypy.HTTPError(status=400, message=error_msg)

            if not os.path.exists(dirloc):
                os.makedirs(dirloc)

            logger.info("calling {}".format(method))

            if method == 'POST':
                if os.path.isfile(fileloc):
                    error_message = _('File already exists.')
                    logger.error(error_message)
                    raise cherrypy.HTTPError(status=400, message=error_message)

                with open(fileloc, 'wb') as f:
                    shutil.copyfileobj(kwargs['backupFile'].file, f)
                return self.render_json({'success': True})
            elif method == 'GET':
                info = ServerInfo(session_key)
                if os.path.isfile(fileloc):
                    return cherrypy.lib.static.serve_file(fileloc, 'application/octet-stream', id)
                elif info.is_shc_member():
                    backup_restore_object = op.get(LOG_PREFIX, owner, object_type='backup_restore',
                                                   object_id=id.split(".")[0], kwargs=kwargs)
                    backup_restore_object_json = json.loads(backup_restore_object)
                    backup_owning_search_head_id = backup_restore_object_json['search_head_id']
                    logger.info('search_head_id for remote host that contains the backup file on disk: %s',
                                backup_owning_search_head_id)
                    adapter = ITSIBackupRestoreJobsQueueAdapter(session_key, logger)
                    backup_owning_hostname = adapter.get_shc_member_hostname(backup_owning_search_head_id)
                    if backup_owning_hostname != 'None':
                        logger.info('hostname of remote host that contains the backup file on disk: %s',backup_owning_hostname)
                        error_msg = _('Unable to locate the backup file on this host. The backup is possibly resident on ' \
                                    'the host: %s in the search head cluster. Please try to download the backup from ' \
                                    'this host.') % backup_owning_hostname
                        logger.error(error_msg)
                        #since 404 is masked with 'Page not found' error message and we want a custom message, returning a 400
                        raise cherrypy.HTTPError(status=400, message=error_msg)
                    # if we cannot retrieve the hostname print a generic message
                    else:
                        #since 404 is masked with 'Page not found' error message and we want a custom message, returning a 400
                        error_msg = _('Unable to locate the backup file on this host. The backup is possibly resident on ' \
                                    'another host in the search head cluster. Please try to download the backup from ' \
                                    'other search head hosts.')
                        logger.error(error_msg)
                        raise cherrypy.HTTPError(status=400, message=_('Unable to find backup file on the current host.'))
                else:
                    logger.error('unable to find backup file')
                    raise cherrypy.HTTPError(status=404, message=_('Unable to find backup file.'))
            elif method == 'DELETE':
                if os.path.isfile(fileloc):
                    os.unlink(fileloc)
                return ""
            else:
                logger.error('method %s not supported', method)
                raise cherrypy.HTTPError(status=400,
                                         message=_('Invalid method. Valid methods are GET, POST and DELETE.'))
        except cherrypy.HTTPError as e:
            raise cherrypy.HTTPError(status=int(e.status), message=str(e._message))
        except Exception as e:
            logger.exception(e)
            raise cherrypy.HTTPError(message=e.message)

    @route('/:owner/:object')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET', 'DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def crud(self, owner, object, **kwargs):
        """
        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target action type

        @type kwargs: args
        @param kwargs: Key word arguments extracted from the POST body

        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        @rtype: json
        """
        self._setup_provider()
        result = self._bulk_crud(owner, object, **kwargs)
        if cherrypy.request.method == 'DELETE':
            cherrypy.response.status = 204
        return result

    @route('/:owner/:object/:id_')
    @expose_page(must_login=True, methods=['POST', 'PUT', 'GET', 'DELETE'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def crud_by_id(self, owner, object, id_,  **kwargs):
        """
        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target action type

        @type id_: basestring
        @:param object: id of object

        @type kwargs: args
        @param kwargs: Key word arguments extracted from the POST body

        @return: json with identifier (for POST or PUT), json with object collection (for GET)
        @rtype: json
        """
        self._setup_provider()
        result = self._crud_by_id(owner, object, id_, **kwargs)
        if cherrypy.request.method == 'DELETE':
            cherrypy.response.status = 204
        return result

    @route('/:owner/:object/:aggregation=count')
    @expose_page(must_login=True, methods=['GET'])
    @handle_json_in
    @CheckUserAccess(capability_matrix=CAPABILITY_MATRIX, object_type=None, logger=logger)
    def object_count(self, owner, object, aggregation, **kwargs):
        """
        Get the object count
        """
        self._setup_provider()
        return self._get_object_count(owner, object, **kwargs)
