# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
Utility module for dealing with splunk Saved Searches.  Wraps the core endpoints
to make it easier to interface with
'''

import time
import json
import random

import splunk
import splunk.entity as splunk_entity
import splunk.rest as rest
from splunk.appserver.mrsparkle.lib import i18n
from splunk.util import safeURLQuote
from .setup_logging import setup_logging

class SavedSearch(object):

    """
    Utility to do CURD operation on saved/searches end point
    """
    SAVED_SEARCH_REST_URL = '/saved/searches/'
    logger = setup_logging("itsi_searches.log", "itoa.saved_searches")

    @staticmethod
    def generate_cron_schedule(interval):
        """
        Generate a cron schedule given an interval, which can then be
        consumed for the corresponding savedsearches.conf stanza.

        @type interval: number/basestring representing a number.
        @param interval: time interval for search runs. How frequently must this
        search run?

        @rtype: basestring
        @returns: string representing cron schedule
        """
        cron = ''

        interval = int(interval)
        rand_min = str(random.randint(0, 59))

        if interval == 1440:
            hour = str(random.randint(0, 23))
            cron = rand_min + " " + hour + " * * *"
        elif interval == 60:
            cron = rand_min + " * * * *"
        elif interval == 1:
            cron = "*/1 * * * *"
        elif interval < 60:
            cur_min = str(random.randint(0,interval-1))
            cron = cur_min + "-59/" + str(interval) + " * * * *"
        else:
            raise ValueError(_("alert_period must be one of 1440, 60, 15, 5, 1."))
        return cron

    @staticmethod
    def get_search(session_key, search_name, namespace='itsi', owner='nobody'):
        """
        Get existed saved searches

        @type session_key: basestring
        @param session_key: session key

        @type search_name: basestring
        @param search_name: search name

        @type namespace: basestring
        @param namespace: name space or app name

        @type owner: basestring
        @param owner: owner or user name

        @rtype:  object
        @return: splunk.entity.Entity
        """
        entity = splunk_entity.getEntity(SavedSearch.SAVED_SEARCH_REST_URL, search_name, namespace=namespace,
                                         owner=owner, sessionKey=session_key)
        SavedSearch.logger.info("Successfully fetch saved search=%s", search_name)
        return entity

    @staticmethod
    def get_all_searches(session_key, namespace='itsi', owner='nobody', search=None, count=-1, offset=0,
                         sort_key='name', sort_dir='asc', **kwargs):
        """
        Get all saved search (ideally you should pass search string so it can filter on server side

        @type session_key: basestring
        @param session_key: session_key

        @type namespace: basestring
        @param namespace: app context where search is being saved. Default to itsi

        @type owner: basestring
        @param owner: user name who is performing this operation. Default to nobody

        @type search: basestring
        @param search: search string to filter saved search on server side

        @type count: int
        @param count: count. Default to -1 (to get all saved searches)

        @type offset: int
        @param offset: offset. Default to 0

        @type sort_key: basestring
        @param sort_key: field name to short. Default is 'name'

        @type sort_dir: basestring
        @param sort_dir: sort dir

        @type kwargs: dict
        @param kwargs: other arguments to pass

        @rtype: list
        @return: list of entity object (entity object is like dict)
        """
        entities = splunk_entity.getEntitiesList(SavedSearch.SAVED_SEARCH_REST_URL, namespace=namespace, owner=owner,
                                                 search=search, count=count, offset=offset, sort_key=sort_key,
                                                 sort_dir=sort_dir, sessionKey=session_key, **kwargs)
        SavedSearch.logger.debug("Successfully fetched %s saved searches", len(entities))
        for entity in entities:
            SavedSearch.logger.debug("Fetched search name=%s", entity.name)
        return entities


    @staticmethod
    def create_saved_search_entity(session_key, search_name, namespace='itsi', owner='nobody', raise_if_exist=False):
        """
        Create or get old entity if exists

        @type session_key: basestring
        @param session_key: session_key

        @type search_name: basestring
        @param search_name: saved search name

        @type namespace: basestring
        @param namespace: app context

        @type owner: basestring
        @param owner: user name

        @type raise_if_exist: bool
        @param raise_if_exist: Raise exception if search already exist

        @rtype: entity object
        @return: entity object which is like dict object
        """
        try:
            entity = SavedSearch.get_search(session_key, search_name, namespace, owner)
            SavedSearch.logger.info("Search=%s already exists, not creating", search_name)
            if raise_if_exist:
                raise splunk.RESTException(409, msg=_('Search {0} already exists').format(search_name))
        except splunk.ResourceNotFound:
            SavedSearch.logger.info("Creating new search Search=%s", search_name)
            entity = splunk_entity.getEntity(SavedSearch.SAVED_SEARCH_REST_URL, "_new", namespace=namespace,
                                             owner=owner, sessionKey=session_key)
        entity.owner = owner
        entity.name = search_name
        entity.namespace = namespace
        entity['name'] = search_name
        return entity

    @staticmethod
    def save_entity(session_key, saved_search_entity):
        """
        Perform only save operation. Normally this is being call after creating entity (create_saved_search_entity)

        @type session_key: basestring
        @param session_key: session_key

        @type saved_search_entity: entity object
        @param saved_search_entity: entity object. Normally, user should call create_saved_search_entity function

        @rtype: bool
        @return: return True or False
        """
        SavedSearch.logger.info("Saving search=%s", saved_search_entity.name)
        ret = splunk_entity.setEntity(saved_search_entity, sessionKey=session_key)
        SavedSearch.logger.debug("Successfully saved search=%s", saved_search_entity.name)
        return ret

    @staticmethod
    def update_acl(session_key, search_name, current_user, namespace='itsi', owner='nobody', sharing='app'):
        """
        Update ACL settings for an existing saved search

        @type session_key: basestring
        @param session_key: Splunkd session key

        @type search_name: basestring
        @param search_name: Saved Search title

        @type current_user: basestring
        @param current_user: Current user's username

        @type namespace: basestring
        @param namespace: context of saved search

        @type owner: basestring
        @param owner: owner

        @type sharing: basestring
        @param sharing: sharing type. Can be either 'app', 'global' or 'user'

        @rtype: bool
        @return: True/False
        """
        error_prefix = 'Unable to set ACL for saved search: "{}"'.format(search_name)
        if not isinstance(session_key, basestring):
            SavedSearch.logger.error('%s. Invalid session key.', error_prefix)
            return False
        if not isinstance(search_name, basestring):
            SavedSearch.logger.error('%s. Invalid search name. Expecting a valid string', error_prefix)
            return False

        uri = safeURLQuote('servicesNS/{0}/{1}/saved/searches/{2}/acl'.format(current_user, namespace, search_name))
        url = rest.makeSplunkdUri() + uri

        post_args = {
            "owner":owner,
            "sharing":sharing,
            "output_mode":"json"
            }

        retries = 3
        while retries != 0:
            retries -= 1
            try:
                response, content = rest.simpleRequest(
                    url,
                    sessionKey=session_key,
                    method='POST',
                    postargs=post_args)
            except splunk.ResourceNotFound:
                SavedSearch.logger.error('%s. No such search exists. Retrying. url: %s\n', error_prefix, url)
                time.sleep(0.5)
                continue
            except Exception as exc:
                SavedSearch.logger.exception(exc)
                break

            if response.status != 200:
                SavedSearch.logger.error('%s. Response Code= %s. Content= %s', error_prefix, response.status, content)
                return False
            else:
                content = json.loads(content)
                entry = content.get('entry', [])
                if len(entry) == 0:
                    #No acl update was made.  We should return False.  In essense, we are treating this as a 404
                    SavedSearch.logger.error('Skipping ACL update. Missing entry for saved search: "%s"', search_name)
                    return False
                newacl = entry[0]['acl']
                SavedSearch.logger.info('Saved new ACL settings for saved search: "%s"', search_name)

                SavedSearch.logger.debug('New ACL settings for search "%s" are: %s',
                                        search_name, json.dumps(newacl))
            return True
        return False

    @staticmethod
    def update_search(session_key, search_name, namespace='itsi', owner='nobody', raise_if_exist=False, **kwargs):
        """
        Create new search or update existing search

        @type session_key: basestring
        @param session_key: session_key

        @type search_name: basestring
        @param search_name: saved search name

        @type namespace: basestring
        @param namespace: app context

        @type owner: basestring
        @param owner: user name

        @type raise_if_exist: bool
        @param raise_if_exist: Raise exception if search already exist

        @type kwargs: dict
        @param kwargs: properties of saved search

        @rtype: bool
        @return: True/False
        """
        # Some time SHC throws 404 for existing saved search, hence we are trying three times to save it as workaround
        original_retry = 3
        retry = original_retry
        while retry != 0:
            retry -= 1

            entity = SavedSearch.create_saved_search_entity(session_key, search_name, namespace, owner, raise_if_exist)
            for key, value in kwargs.iteritems():
                SavedSearch.logger.debug("Updating search=%s, properties key=%s, value=%s", search_name, key, value)
                entity[key] = value
                # enableSched savedsearches property has to set by is_scheduled flag of saved search end point
                # But to support older code which invoked conf end point directly passes enableSched flag
                # Hence we are setting is_scheduled property using enableSched property
                if key == 'enableSched':
                    entity['is_scheduled'] = value

            try:
                return SavedSearch.save_entity(session_key, entity)
            except splunk.ResourceNotFound as exc:
                SavedSearch.logger.warning('Unable to save the search "%s" (attempt %s of %s)',
                        search_name, str(original_retry - retry ), str(original_retry))
                time.sleep(0.5)
                if retry == 0:
                    SavedSearch.logger.exception(exc)
                    raise exc
                else:
                    continue
            except splunk.RESTException as exc:
                if exc.statusCode == 409:
                    SavedSearch.logger.warning('Unable to save the search "%s" (attempt %s of %s).  getEntityFailed',
                            search_name, str(original_retry - retry ), str(original_retry))
                    time.sleep(0.5)
                    if retry == 0:
                        SavedSearch.logger.exception(exc)
                        raise exc
                    else:
                        continue
                else:
                    raise exc
        return False

    @staticmethod
    def delete_search(session_key, search_name, namespace='itsi', owner='nobody'):
        """
        Delete search

        @type session_key: basestring
        @param session_key: session_key

        @type namespace: basestring
        @param namespace: app context

        @type owner: basestring
        @param owner: user name

        @rtype: bool
        @return: return True/False
        """
        # On SHC we get 404, even when search exists
        original_retry = 3
        retry = original_retry

        while retry != 0:
            retry -= 1
            try:
                return splunk_entity.deleteEntity(SavedSearch.SAVED_SEARCH_REST_URL, search_name, namespace, owner,
                                                  sessionKey=session_key)
            except splunk.ResourceNotFound as exc:
                # Try without any context to support older saved searches
                SavedSearch.logger.warning("Could not find=%s, search=%s in %s content, trying without any context to"
                                        " support backward compatibility", exc.message, search_name, owner)
                try:
                    return splunk_entity.deleteEntity(SavedSearch.SAVED_SEARCH_REST_URL, search_name, None, None,
                                                      sessionKey=session_key)
                except splunk.ResourceNotFound as exc:
                    SavedSearch.logger.info('Could not delete search "%s", retrying (attempt %s of %s)',
                            search_name, str(original_retry - retry), str(original_retry))
                    time.sleep(0.5)
                    if retry == 0:
                        SavedSearch.logger.exception(exc)
                        raise exc
            except splunk.BadRequest as brq:
                SavedSearch.logger.warning('Unable to delete resource search="%s" namespace="%s" owner="%s" reason="%s"',
                                             search_name, namespace, owner, brq.message)
                return False

        SavedSearch.logger.info("Deleted saved search=%s", search_name)
        return False

