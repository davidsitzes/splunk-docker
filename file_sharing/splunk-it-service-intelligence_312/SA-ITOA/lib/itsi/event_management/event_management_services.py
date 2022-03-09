# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import sys

from splunk.appserver.mrsparkle.lib import i18n
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import normalizeBoolean

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging
from ITOA.event_management.event_management_object_manifest import object_manifest
from ITOA import itoa_common as utils

from ITOA.event_management.notable_event_utils import NotableEventConfiguration

logger = setup_logging('itsi_event_management.log', 'itsi.controllers.event_management_interface')

# FIXME - this class can't be used along because it has reference of some instance variable like
# self._session etc, which is initialized by another imported class.
# this is really very bad pattern. We should address this
class EventManagementService(object):

    def __init__(self, session_key=None):
        self._session_key = session_key

    def _get_instance(self, object_type, owner, current_user_name=None):
        """
        Get instance for given object_ type

        @type: string
        @param object_type: type of object to instantiate

        @type: string
        @param owner: owner of the object

        @rtype: ItsiNotableEvent
        @return: object_ instance of given type
        """
        object_class = object_manifest.get(object_type)
        # We want to perform all operation at nobody context
        return object_class(self._session_key, current_user_name=current_user_name)

    def get_all_notable_event_configuration(self, session_key):
        """
        Get all notable event configuration info like severities, statuses, owners and email formats too
        @param session_key: basestring
        @param session_key: session key

        @rtype: dict
        @return: dict for all notable event information
         Return a dictionary which hold information about severities, status and owners
            {
                severities: [
                {
                    name: <name>,
                    value: <name>,
                    default: 0|1,
                    color: <name>
                }..],
                statuses: [
                {
                    name: <name>,
                    value: <name>,
                    default: 0|1
                } ...],
                owners: [{
                    name: <name>,
                    value: <name>,
                    default: 0|1
                }..],
                email_formats: [{
                    name: <name>,
                    value: <name>,
                    default: 0|1
                }..]

        """
        ns_config = NotableEventConfiguration(session_key, logger)
        data = {}
        # Get Severity
        data['severities'] = []
        for severity_value, content in ns_config.severity_contents.iteritems():
            data['severities'].append({
                'label': content.get('label'),
                'value': severity_value,
                'default': ns_config.get_default_severity() == severity_value,
                'color': content.get('color')
            })
        # Get Status
        data['statuses'] = []
        for status_value, content in ns_config.status_contents.iteritems():
            data['statuses'].append({
                'label': content.get('label').capitalize(),
                'value': status_value,
                'default': ns_config.get_default_status() == status_value
            })
        # Get Owner
        data['owners'] = []
        for key, owner in ns_config.owner_contents.iteritems():
            data['owners'].append({
                'label': owner.get('realname') if owner.get('realname') else owner.get('_key'),
                'value': owner.get('_key'),
                'default': ns_config.get_default_owner() == owner.get('_key')
            })
        data['email_formats'] = []
        for eformat in ['pdf', 'html', 'csv']:
            data['email_formats'].append({
                'label': eformat,
                'value': eformat,
                'default': eformat == 'pdf'
            })
        logger.debug('Return notable event configuration "%s"', data)
        return data


#################### CURD and BULK Notable event CURD Operation ##############################

    def upsert(self, owner, object_type, identifier, kwargs, current_user=None, object_instance=None):
        """
        Perform create or update

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object_type type

        @type identifier: basestring
        @param identifier: id. Id can be null. When id is not specified then create operation is being
                called otherwise update

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @type current_user: basestring
        @param current_user: current user who initiated the request

        @type object_instance: object instance
        @param object_instance: based upon type instance was created

        @rtype: json or Exception
        @return: json object
        """
        if not object_instance:
            object_instance = self._get_instance(object_type, owner, current_user_name=current_user)
        # add user who is performing this operation
        data = kwargs.get('data') or kwargs
        self._add_user(data, owner)
        self._delete_data(kwargs)

        # get earliest or latest time from data itself
        if 'earliest_time' not in kwargs:
            kwargs['earliest_time'] = data.get('earliest_time')
        if 'latest_time' not in kwargs:
            kwargs['latest_time'] = data.get('latest_time')

        # check if the key already exists
        create = True
        if identifier:
            try:
                object_instance.get(identifier)
                create = False
            except:
                logger.debug('Object %s does not exist.' % identifier)

        if identifier and not create:
            logger.debug('Performing update for id=%s', identifier)
            is_partial_update = normalizeBoolean(kwargs.pop('is_partial_update', True))

            # Enforcing RBAC checks on update require the current user for correlation search.
            # Other objects are not enforcing rbac check for now
            result = object_instance.update(identifier, data, is_partial_update=is_partial_update, **kwargs)
        else:
            logger.debug('Creating new %s', object_type)
            # Add user who create this object_type in _owner field
            self._add_user(data, owner, '_owner')

            if normalizeBoolean(data.get('_is_group', False)) is True:
                result = object_instance.create_for_group(data, **kwargs)
            else:
                result = object_instance.create(data, **kwargs)

        logger.debug('Returning values=%s', result)
        return result

    def get(self, owner, object_type, identifier, kwargs):
        """
        Perform get operations

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object_type type

        @type identifier: basestring
        @param identifier: id. Id can be null. When id is not specified then create operation is being
                called otherwise update

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @rtype: json or Exception
        @return: json object
        """
        logger.debug('Getting _key=%s of object=%s ,and user=%s', identifier, object_type, owner)
        object_instance = self._get_instance(object_type, owner)
        self._delete_data(kwargs)
        result = object_instance.get(identifier, **kwargs)
        logger.debug('Returning values=%s', result)
        return result

    def delete(self, owner, object_type, identifier, kwargs):
        """
        Perform delete operation

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object_type type

        @type identifier: basestring
        @param identifier: id. Id can be null. When id is not specified then create operation is being
                called otherwise update

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @rtype: None or Exception
        @return: None if delete operation is successful otherwise exception

        """
        logger.debug('Deleting _key=%s of object=%s', identifier, object_type)
        object_instance = self._get_instance(object_type, owner)
        self._delete_data(kwargs)
        object_instance.delete(identifier, **kwargs)

    def get_bulk(self, owner, object_type, kwargs):
        """
        Perform get bulk operations
        if data is not specify in the kwargs then all objects are return based
        upon count and offset values

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object_type type

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @rtype: json or Exception
        @return: json object
        """
        logger.debug('Getting %s in bulk for user=%s', object_type, owner)
        object_instance = self._get_instance(object_type, owner)
        ids = kwargs.get('ids')
        if ids:
            object_ids_list = json.loads(ids)
        else:
            object_ids_list = []
        logger.info('Getting %s with ids=%s', object_type, ids)
        object_ids = object_ids_list if object_ids_list else []

        self._delete_data(kwargs)
        results = object_instance.get_bulk(object_ids, **kwargs)
        logger.debug('Returned objects=%s for object=%s', len(results), object_type)
        return results

    def delete_bulk(self, owner, object_type, kwargs):
        """
        Perform delete operations in bulk. If data is not specify then all objects is delete
        for provided type

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object type

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @rtype: None or Exception
        @return: None if operation is successful otherwise exception
        """
        logger.debug('Deleting objects for object=%s user=%s', object_type, owner)
        object_instance = self._get_instance(object_type, owner)
        ids = kwargs.get('ids')
        if ids:
            object_ids = json.loads(ids)
        else:
            object_ids = None
        logger.info('Deleting %s with ids=%s', object_type, object_ids)
        self._delete_data(kwargs)
        object_instance.delete_bulk(object_ids, **kwargs)
        logger.debug('Successfully deleted object(s) of object=%s', object_type)

    def upsert_bulk(self, owner, object_type, kwargs):
        """
        Perform update/create operations in bulk, note that this method is not safe for upserts of mixed creates and
        updates, it must all be create or all update.

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object_type: basestring
        @param object_type: Target object type

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @rtype: json or Exception
        @return: json object
        """
        object_instance = self._get_instance(object_type, owner)
        data_list = kwargs.get('data') or kwargs
        self._delete_data(kwargs)
        # check if data list contains _key
        if len(data_list) > 0:
            first_identifier = data_list[0].get(object_instance.id_key)
            create = True
            if first_identifier:
                try:
                    object_instance.get(first_identifier)
                    create = False
                except:
                    logger.debug('Object %s does not exist.' % first_identifier)

            if first_identifier is not None and not create:
                logger.debug('Updating %s objects object=%s', len(data_list), object_type)
                object_ids_list = [data.get(object_instance.id_key) for data in data_list]
                object_ids = object_ids_list if object_ids_list else None
                is_partial_update = normalizeBoolean(kwargs.pop('is_partial_update', True))
                # Update one
                results = object_instance.update_bulk(object_ids, data_list, is_partial_update=is_partial_update, **kwargs)
            else:
                # Create one
                logger.debug('Creating bulk %s objects %s', len(data_list), object_type)
                results = object_instance.create_bulk(data_list, **kwargs)
        return results


################ Helper functions ##############

    def _delete_data(self, kwargs):
        """
        Deleting extra data from kwargs otherwise data would be passed twice

        @rtype: dict
        @return: updated kwargs
        """
        kwargs.pop('data', None)

    def _add_user(self, data, owner, field_name='_user'):
        """
        Add user or owner information in data to know who is performing the operation

        @type data: dict
        @param data: data (inplace update to the dict)

        @type field_name: basestring
        @param field_name: field name for user

        @rtype: dict
        @return: Updated dict
        """
        if isinstance(data, dict):
            data[field_name] = owner
        else:
            raise ValueError(_('Data should be valid dict'))

    def _check_and_call_operation(self, owner, object, kwargs, single_operation, bulk_operation, current_user_name=None):
        """
        Support function to call

        @type owner: basestring
        @param owner: owner who is performing this operation

        @type object: basestring
        @param object: Target object type

        @type kwargs:dict
        @param kwargs: which contain addition parameters of controller

        @type single_operation: function
        @param single_operation: function which perform single operation

        @type bulk_operation: function
        @param bulk_operation: function which perform bulk operation

        @return: return of either function or exception
        """
        data = kwargs.get('data') or kwargs
        logger.debug('data="%s" kwargs="%s"', data, kwargs)
        if isinstance(data, list):
            return bulk_operation(owner, object, kwargs)
        elif isinstance(data, dict):
            object_instance = self._get_instance(object, owner, current_user_name=current_user_name)
            object_id = data.get(object_instance.id_key)
            return single_operation(owner, object, object_id, kwargs, object_instance=object_instance)
        else:
            raise TypeError(_('Invalid data format, data can be either dict or list. {}').format(type(data)))
