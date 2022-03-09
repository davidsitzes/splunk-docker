# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Contains the main methods and base class used for generating a shared base
search (a single saved search that works with multiple kpis)
Currently we only have support for Adhoc searches
TO THE FUTURE: if reasonable, please make shared datamodel searches
a separate class
"""

# Used for the cron schdeuling
import random

from splunk import ResourceNotFound
from splunk.util import normalizeBoolean
from splunk.appserver.mrsparkle.lib import i18n

import ITOA.itoa_common as utils
from ITOA.storage import itoa_storage
from itsi.searches.itsi_filter import ItsiFilter

from ITOA.saved_search_utility import SavedSearch

#Uses the same logger as ItsiKpiSearches
logger = utils.get_itoa_logger('itsi.object.searches', 'itsi_base_searches.log')

class ItsiSharedAdhocSearch(utils.ItoaBase):
    """
    Abstraction for anything related to ITSI Shared KPI base searches
    Key component here is search generation for multiple KPIs using
    a shared base search
    """
    #Defined out here because of annoying kpi delete construction
    search_prefix = 'Indicator - Shared - '
    entity_magic = "%ENTITY_FILTER%"

    def __init__(self, session_key, bs_id, base_search=None, services=None):
        '''
        Initializes the adhoc shared saved search
        @param session_key: The splunkd session key
        @param bs_id: The base search id
        @param base_search: An optional parameter of the base search associated with the key
        @param services: A list of service objects to be used instead of going to the kvstore
        @type services: list
        '''
        super(ItsiSharedAdhocSearch, self).__init__(session_key)
        self.backend = itoa_storage.ITOAStorage().get_backend(session_key)

        self.shared_base_search_id = bs_id
        if not isinstance(bs_id, basestring):
            raise Exception(_("Base search id must be a valid string."))
        if base_search is not None:
            #If it doesnt exist, dont throw the exception
            if base_search.get('_key',bs_id) != bs_id:
                raise Exception(_("Base search passed in does not match key passed in."))
        else:
            #We need to look up the base search ourself
            base_search = self.backend.get(session_key, 'nobody', 'kpi_base_search', bs_id)
            if base_search is None:
                raise Exception(_("Base search could not be located from id=%s") % bs_id)
        self.base_search = base_search

        #At this point we have the shared base search
        #Lookup all the services and kpis that use the shared base search
        if services is None:
            services = self.backend.get_all(session_key,
                                             'nobody',
                                             'service',
                                             filter_data={"$and":[{"kpis.base_search_id": bs_id},
                                                          {"kpis.search_type": "shared_base"},
                                                            {"kpis.enabled": 1}]})
            if len(services) == 0 or services is None:
                #No services use this base search
                #This MIGHT be an error or a warning, but I'm going
                #To log it as warning for now, since this might be
                #a normal mode of operation
                logger.info("No services matched base search id %s" % bs_id)
                services = [] #Disambiguation reassignment


        #Create a structure that has all kpis from the services that we found
        #And that makes service lookups a bit easier
        self.kpis = {}
        self.services = {}
        for svc in services:
            kpis = svc.get("kpis")
            #This structure is a little easier to work with
            service_key = svc.get("_key")
            # Flag is kpis in service has shared search
            is_found = False
            for kpi in kpis:
                # Front end sometimes does not update base_search_id so check for
                # search type too
                if kpi.get("base_search_id") == bs_id and kpi.get('search_type') == 'shared_base':
                    is_found = True
                    if service_key not in self.kpis:
                        self.kpis[service_key] = [kpi]
                    else:
                        self.kpis[service_key].append(kpi)
            if is_found:
                self.services[service_key] = svc

        #Per ITOA-4442 Make a dictionary of "aliases".  We'll need to carry this around so that when the situation arises
        #We can map to the appropriate metric
        self.metric_aliases = {}

        # PBL-5786: allow splitting of base search KPI by a different field than entity filter field. To support this,
        # we need to perform pre stats calculation using 'sistats' command, since, entity aggregate values depend on
        # multiple fields (breakdown and filter)
        self.diff_entity_filter_breakdown_fields = False
        if self.base_search.get("is_entity_breakdown", False) and \
            self.base_search.get("is_service_entity_filter", False) and \
                    self.base_search.get("entity_id_fields", '') != self.base_search.get("entity_breakdown_id_fields",
                                                                                         ''):
            self.diff_entity_filter_breakdown_fields = True

        self.unique_metric_tokens = {}

    def upsert_service_for_preview(self, service):
        '''
        Used for previewing, upsert a service to the existing service list
        NOTE to be VERY careful with this, it can make invalid entries
        '''
        if service.get('_key') is None:
            #CAN BE NONE!! Unline other things
            self.services["NO-KEY"] = service
        else:
            self.services[service['_key']] = service

    @staticmethod
    def can_optimize_entities(search_string):
        '''
        Examines the base search and determines if we can insert the entity filter clause
        This is only a method because we may want to expand or fine tune the criteria
        Cause, yeah, its basic.
        @param
        '''
        #NOTE: It is also valid syntax if you have a subsearch followed by an entity filter optimization
        #Since we don't know if macros can be automatically optimized, we dont automatically optimize on those either
        if search_string.find("|") != -1 or search_string.find("`") != -1:
            #If its a compounded search string, return false
            return False
        return True

    @staticmethod
    def append_entity_filter(search_string, entity_filter):
        """
        Determines if and how we can optimize a search string with a given entity filter
        Looks for the magic number
        """
        if ItsiSharedAdhocSearch.entity_magic in search_string:
            #NOTE: Replaces ALL instances of the magic string with the entity filter
            return search_string.replace(ItsiSharedAdhocSearch.entity_magic, entity_filter)
        optimization = ItsiSharedAdhocSearch.can_optimize_entities(search_string)
        if len(entity_filter) > 0:
            if optimization:
                search_string += " " + entity_filter
            else:
                search_string += " | search " + entity_filter
        return search_string


    def get_saved_search_name(self):
        '''
        Return the name of the saved search
        TODO: Determine if this should be converted into a static method
        '''
        return 'Indicator - Shared - ' + self.shared_base_search_id + ' - ITSI Search'

    @staticmethod
    def generate_search_dispatch_times(alert_lag, search_alert_earliest):
        '''
        Generate the dispatch settings used to calculate the earliest and latest
        times to schedule the search.

        @param alert_lag: The number of seconds to skew the search range
        @type alert_lag: Int
        @param search_alert_earliest: The number of seconds back to search
        @type search_alert_earliest: Int

        @return: A dict of settings representing the dispatch times
        '''
        settings = {}
        if alert_lag == 0:
            # Real Time case we need to set latest time to now
            settings['dispatch.earliest_time'] = '-' + str(search_alert_earliest) + 's'
            settings['dispatch.latest_time'] = 'now'
        elif alert_lag <= 1800:
            # Normal Case, adjust search timing to account for the lag
            settings['dispatch.earliest_time'] = '-' + str(search_alert_earliest + alert_lag) + 's'
            settings['dispatch.latest_time'] = '-' + str(alert_lag) + 's'
        else:
            raise ValueError(_("Invalid alert_lag passed to saved search management, must be below 30 minutes"))
        return settings

##################################################################
# Splunk Search Methods
##################################################################
    def build_splunk_search(self, description=None):
        '''
        Create the shared base search parameters.  These are the generic defaults
        passed in, and used by different searches
        @param description: An alternate string description supplied
        @type description: string
        @return: The parameters of the shared base search
        '''
        saved_search_settings = {}
        #Start off with the generic settings
        saved_search_settings['name'] = self.get_saved_search_name()
        if not isinstance(description, basestring):
            saved_search_settings['description'] = 'Auto generated shared base search'
        else:
            saved_search_settings['description'] = description
        saved_search_settings['search'] = self.generate_shared_base_search_string()

        #Calculate the dispatch timing
        alert_lag = int(self.base_search.get('alert_lag', 30))
        alert_earliest = int(self.base_search.get('search_alert_earliest', 5)) * 60
        dispatch = ItsiSharedAdhocSearch.generate_search_dispatch_times(alert_lag, alert_earliest)
        saved_search_settings.update(dispatch)

        saved_search_settings['enableSched'] = '1'
        
        # Regenerate a random cron every time in order to take into account a change in the alert period
        # Technically this means on save there is a potential for a kpi to execute slightly off rhythm at
        # the point of save if the start point of the cron changes for a 5 or 15 period kpi
        crontab = SavedSearch.generate_cron_schedule(self.base_search.get('alert_period', 5))
        saved_search_settings['cron_schedule'] = crontab

        saved_search_settings['alert.suppress'] = '0'
        saved_search_settings['alert.track'] = '0'
        saved_search_settings['alert.digest_mode'] = '1'

        saved_search_settings['actions'] = 'indicator'
        saved_search_settings['action.indicator._itsi_base_search_id'] = self.shared_base_search_id
        return saved_search_settings

    #Create is also update
    def create_splunk_search(self, ignore_service_check=False, acl_update=True):
        '''
        Create the shared base search that is associated with the shared_base_search_id of this search
        @param ignore_service_check: Determine whether or not we should ignore the service check.
                                     If there are no associated services don't create the base search
        @type ignore_service_check: Boolean
        @return: The parameters of the shared base search
        '''
        if not ignore_service_check and len(self.services) == 0:
            logger.debug("Not issuing search for kpi_base_search=%s - No associated services" % self.shared_base_search_id)
            return True
        #First a very simple check, if we don't have
        settings = self.build_splunk_search()
        ret = SavedSearch.update_search(self.session_key, settings.get('name'), 'itsi', 'nobody', **settings)
        if ret:
            #Successfully updated the saved search
            logger.info("Successfully created/update saved search=%s", settings.get('name'))
            if acl_update:
                ret = SavedSearch.update_acl(
                                    self.session_key,
                                    settings.get('name'),
                                    'nobody')
                if not ret:
                    msg = _("ACL update failed for saved search %s. Manual update required.") % settings.get('name')
                    logger.error(msg)
        else:
            #Search creation failed
            message = _("Failed to create saved search %s.") % settings.get('name')
            logger.error(message)
            raise Exception(message)
        return ret


    def delete_splunk_search(self):
        '''
        Remove the associated splunk shared base search associated with the base search id
        '''
        saved_search_name = self.get_saved_search_name()
        # Delete saved search for kpi
        ret = True
        try:
            ret = SavedSearch.delete_search(self.session_key, saved_search_name)
        except ResourceNotFound:
            logger.exception(
                'Saved search "%s" was not found, ignoring delete',
                saved_search_name,
            )
        except Exception:
            logger.exception(
                'Caught exception trying to delete saved search "%s"',
                saved_search_name,
            )
            ret = False

        if not ret:
            logger.error('Failed to delete saved search="%s"', saved_search_name)
        else:
            logger.info('Successfully deleted saved search="%s"', saved_search_name)
        return ret

    def get_splunk_search(self):
        '''
        Retrieves the splunk search associated with the base_search_id
        '''
        try:
            saved_search_name = self.get_saved_search_name()
            return SavedSearch.get_search(self.session_key, saved_search_name)
        except ResourceNotFound:
            logger.exception("Unable to splunk search: %s", saved_search_name)
            return None


##################################################################
# Search String Generation
##################################################################
    def generate_shared_base_search_string(self):
        '''
        From the information provided on init,
        construct the shared base search string
        '''
        base_search = self.base_search.get("base_search")
        is_service_entity_filter = normalizeBoolean(self.base_search.get("is_service_entity_filter", False), False)
        search_string = base_search
        if is_service_entity_filter:
            entity_filter_string = self.generate_entity_filter()
            search_string = ItsiSharedAdhocSearch.append_entity_filter(search_string, entity_filter_string)

        entity_breakdown_id_fields = self.base_search.get("entity_breakdown_id_fields")
        entity_id_fields = self.base_search.get("entity_id_fields")
        if self.base_search.get("is_entity_breakdown"):
            # ITOA-4442: first, separate metrics with duplicate threshold field and entity statop.
            # so that, we generate correct aggregate entity search.
            self._identify_metrics()
            search_string += " | " + self.aggregate_raw_into_entity(
                pre_stats_operation=self.diff_entity_filter_breakdown_fields
            )
            if not self.diff_entity_filter_breakdown_fields:
                search_string += self.expand_combined_fields()
            search_string += " | eval serviceid=null() " #Make sure we don't have any residual data coming through for the results
            search_string += ' | eval sec_grp="' + self.base_search.get('sec_grp') + '"'
            # we would have to perform lookup by entity filter field as well,
            # if entity filter and breakdown fields are different in a base search
            if self.diff_entity_filter_breakdown_fields:
                search_string += ' | `match_filter_entites(' + entity_id_fields + ', sec_grp)`'
            else:
                search_string += ' | `match_entities(' + entity_breakdown_id_fields + ', sec_grp)`'

            if len(self.services) == 1 and is_service_entity_filter:
                search_string += ' | eval serviceid=if(isnull(serviceid),"'+ '","'.join(self.services.keys()) +'",serviceid)'
            elif len(self.services) > 1 and is_service_entity_filter:
                search_string += ' | eval serviceid=if(isnull(serviceid),mvappend("'+ '","'.join(self.services.keys()) +'"),serviceid)'
            elif len(self.services) == 1 and not is_service_entity_filter:
                search_string += ' | eval serviceid="' + '","'.join(self.services.keys()) +'"'
            elif len(self.services) > 1 and not is_service_entity_filter: #Redundant, but clarifying
                search_string += ' | eval serviceid=mvappend("'+ '","'.join(self.services.keys()) +'")'
            search_string += " | mvexpand serviceid"
            if self.diff_entity_filter_breakdown_fields:
                # generate stats command to aggregate entity, after pre stats calculation
                # and filter entity lookup is done above
                search_string += ' | ' + self.aggregate_raw_into_entity()
                search_string += self.expand_combined_fields()
                search_string += ' | eval sec_grp="' + self.base_search.get('sec_grp') + '"'
                search_string += ' | `match_breakdown_entities(' + entity_breakdown_id_fields + ', sec_grp)`'

            search_string += " | " + self.aggregate_entity_into_service()
        else:
            if is_service_entity_filter:
                search_string += ' | eval sec_grp="' + self.base_search.get('sec_grp') + '"'
                search_string += ' | `match_entities(' + entity_id_fields + ', sec_grp)`'
                if len(self.services) == 1:
                    search_string += ' | eval serviceid=if(isnull(serviceid),"'+ '","'.join(self.services.keys()) +'",serviceid)'
                elif len(self.services) > 1:
                    search_string += ' | eval serviceid=if(isnull(serviceid),mvappend("'+ '","'.join(self.services.keys()) +'"),serviceid)'
            else:
                #Sacrificing condensed code for readability (I hope)
                if len(self.services) == 1:
                    search_string += ' | eval serviceid="' + '","'.join(self.services.keys()) +'"'
                elif len(self.services) > 1:
                    search_string += ' | eval serviceid=mvappend("'+ '","'.join(self.services.keys()) +'")'
            search_string += " | mvexpand serviceid"
            search_string += " | " + self.aggregate_raw_into_service()

        #Now for the common pieces
        alert_period = self.base_search.get("alert_period", '5')
        search_string += ' | `assess_severity(' + self.shared_base_search_id + ')`'
        #Remove any unnecessary fields we dont need
        search_string += " | " + self.remove_extraneous_fields()
        #Finish up with a round of evals
        search_string += ' | eval alert_period=' + alert_period + ', itsi_kpi_id=kpiid, itsi_service_id=serviceid'
        return search_string

    def expand_combined_fields(self):
        """
        PER ITOA-4442 we combine the aggregate statistics, however, so that we don't have missing entries, we need to re-expand these entities
        @return search string with alias fields in it
        """
        if len(self.metric_aliases) == 0:
            return ''
        search_strings = []
        for duplicate_metric in self.metric_aliases:
            string = 'alert_value_' + duplicate_metric + '=' + 'alert_value_' + self.metric_aliases[duplicate_metric]
            search_strings.append(string)
        return ' | eval ' + ','.join(search_strings)

    def remove_extraneous_fields(self):
        """
        Remove the extraneous fields from the shared base search
        These are the fields based on the metric id fields that weren't copied over into alert_value
        """
        search_string = 'fields - alert_error'
        if self.diff_entity_filter_breakdown_fields:
            search_string += ' entity_filter_fields'
        metrics = self.base_search.get('metrics')
        for metric in metrics:
            metric_id = metric.get('_key')
            search_string += ' alert_value_%s' % metric_id
        return search_string

    def generate_entity_filter(self):
        '''
        Create the entity filter for all of the services
        '''
        #First, simple check, make sure that this isn't null and that this is filtering for entities
        if not normalizeBoolean(self.base_search.get("is_service_entity_filter", False), False):
            logger.info("entity filtering invoked with untrue is_service_entity_filter - returning empty string")
            #We are working with a straight up service filter
            #This is a "normal" working case
            return ''
        fieldname = self.base_search.get("entity_alias_filtering_fields")
        fieldnames = []
        if isinstance(fieldname,basestring):
            fieldnames = fieldname.split(',')

        alias_field = self.base_search.get("entity_id_fields")
        entities_in_services = []
        #First, get all of the matching entity filter clauses
        for svc in self.services.itervalues():
            entity_rules = svc.get('entity_rules')
            entities_in_service = ItsiFilter(entity_rules).get_filtered_objects(
                self.session_key, 'nobody')
            entities_in_services.extend(entities_in_service)

        #Next, extract the appropriate fields and dedup
        filter_string = ""
        filter_terms = set()
        for entity in entities_in_services:
            #For each entity, grab the associated fields and aliases, and smoosh them together to filter out
            #NOTE: For this case we do not care if it is an identifying field or not.  This may change
            if len(fieldnames) > 0:
                for field in fieldnames:
                    values = entity.get(field)
                    if values is None or len(values) == 0:
                        logger.warning("Entity %s had fieldnames specified with no values - skipping" % entity.get("_key"))
                        continue
                    #Using is_valid_name because of the regex protection it affords against un-splunkable aliases
                    # If the entity value contains "\", replace it with "\\\". "\" is considered special character
                    kv_pairs = [alias_field + '="' + value.replace('\\', '\\\\\\') + '"' for value in values if utils.is_valid_name(value)]
                    filter_terms.update(kv_pairs)
            else:
                #Go through all identifying fields for the entity
                identifiers = entity.get("identifier")
                if not identifiers:
                    continue
                fields = identifiers.get("fields")
                if not isinstance(fields, list):
                    continue
                #Now that we have a valid fields, go through each one, get the entity kv pairs and add them to
                #the filter terms
                for field in fields:
                    values = entity.get(field, [])
                    if isinstance(values, list) and len(values) > 0:
                        # If the entity value contains "\", replace it with "\\\". "\" is considered special character
                        filter_terms.update([alias_field + '="' + value.replace('\\', '\\\\\\') + '"' for value in values if utils.is_valid_name(value)])

        #If we are supposed to have entities, but don't - use the no match.  Since it acts as essentially a logical
        #zero, we should not apply it if any entities are present
        if len(filter_terms) == 0:
            filter_terms.add("`no_entities_matched`")
        #Now we've got a unique set of filter terms, join the string and exit
        return " OR ".join(filter_terms)

    def aggregate_raw_into_service(self, entities=False):
        '''
        Generate the aggregate string for all metrics found in the base search
        The macro for this for a single kpi is
            stats $aggregate_statop$($threshold_field$) AS alert_value |
                eval is_service_aggregate="1", is_entity_defined="0",
                entity_key="service_aggregate", entity_title="service_aggregate" |
                `gettime`
        The stats part is what we'll need to change, as the macro definition does not
        allow for a variable number of arguments.  Fortunately, just the first piece
        will need to change
        @param entities: A parameter to determine whether or not we will need to create a by clause for services
        @type entities: boolean
        @return: a string representing the search term
        '''
        ret_string = "stats "
        metrics = self.base_search.get("metrics")
        for metric in metrics:
            #There is some duplication here between this and aggregate_raw_into_entity
            #Which I'm willing to sacfirice for the sake of clarity
            aggregate_statop = metric.get("aggregate_statop")
            threshold_field = metric.get("threshold_field")
            metric_id = metric.get("_key")
            if metric_id is None:
                logger.warning("base_search %s missing a metrics key - skipping" % self.shared_base_search_id)
                continue
            if aggregate_statop is None or threshold_field is None:
                logger.warning("metric %s missing threshold_field or aggregate_statop - skipping" % metric.get("_key"))
                continue
            if entities:
                ret_string += "%s(alert_value_%s) AS alert_value_%s " % (aggregate_statop, metric_id, metric_id)
            else:
                ret_string += "%s(%s) AS alert_value_%s " % (aggregate_statop, threshold_field, metric_id)

        #The metric qualifier will change how we choose to aggregate the instances
        metric_qualifier = self.base_search.get("metric_qualifier")
        if isinstance(metric_qualifier, basestring) and len(metric_qualifier) > 0:
            #We have a metric qualifier, create a slightly different search than before
            ret_string += "by %s" % metric_qualifier
            if entities:
                ret_string += ", serviceid"
        else:
            ret_string += "by serviceid"

        # is_entity_in_maintenance field in each of the entity result row is used to determine if all entities in a
        # service is in maintenance or not.
        # In the scenario where entity breakdown and entity filtering are not configured, there will be no entity level
        # results, in that case, we need to eval is_entity_in_maintenance to 0 for the service aggregration row.
        if self.base_search.get("is_entity_breakdown", False) or self.base_search.get("is_service_entity_filter", False):
            ret_string += ', is_entity_in_maintenance | sort 0 serviceid is_entity_in_maintenance '\
                          '| dedup consecutive=t serviceid | eval is_service_aggregate="1", is_entity_defined="0", '
        else:
            ret_string += ' | eval is_entity_in_maintenance="0", is_service_aggregate="1", is_entity_defined="0", '
        ret_string += 'entity_key="service_aggregate", entity_title="service_aggregate" | `gettime`'
        return ret_string

    def aggregate_raw_into_entity(self, pre_stats_operation=False):
        """
        Generate the aggregate entity for all metrics found in the base search
        The macro this is based on for the single kpi is

        example:
        STATS = stats $entity_statop$($threshold_field$) AS alert_value by $entity_id_fields$ | `gettime`

        PRE-STATS = sistats count(log_level) values(component) by sourcetype, component

        NOTE for sistats command: PBL-5786: allow splitting of base search KPI by a different field than
        entity filter field. To support this, we need to perform pre stats calculation using 'sistats'
        command, since, entity aggregate values depend on multiple fields (breakdown and filter)

        @param pre_stats_operation: True is want to generate 'sistats` command for prestats calculation
                                of entity aggregates
        @type pre_stats_operation: bool
        """
        ret_string = 'stats '
        if pre_stats_operation:
            ret_string = 'sistats '
        # TODO: Get clarification on whether or not this should be a string, a list
        # And handle appropriately.  From my understanding, it needs to be a single field
        # And should PROBABLY be renamed to the singular
        entity_breakdown_id_fields = self.base_search.get("entity_breakdown_id_fields")
        entity_id_fields = self.base_search.get("entity_id_fields")
        if not utils.is_valid_str(entity_breakdown_id_fields):
            raise Exception(_("For an entity search, valid entity breakdown id field is required."))
        if not pre_stats_operation and self.diff_entity_filter_breakdown_fields and not utils.is_valid_str(entity_id_fields):
            raise Exception(_("For an entity search, valid entity id field is required."))

        for metric_id, metric in self.unique_metric_tokens.iteritems():
            entity_statop = metric.get('entity_statop')
            threshold_field = metric.get('threshold_field')
            if pre_stats_operation:
                ret_string += '%s(%s) ' % (entity_statop, threshold_field)
            else:
                ret_string += "%s(%s) AS alert_value_%s " % (entity_statop, threshold_field, metric_id)

        # Now add the suffix and be on our way. The metric qualifier will
        # change how we choose to aggregate the instances
        metric_qualifier = self.base_search.get("metric_qualifier")
        has_metric_qualifier = utils.is_valid_str(metric_qualifier)

        # We have a metric qualifier, create a slightly different search than before
        if has_metric_qualifier:
            if pre_stats_operation:
                ret_string += 'values(%s) by %s, %s, %s' % \
                                   (entity_id_fields, entity_breakdown_id_fields, entity_id_fields, metric_qualifier)
            else:
                if self.diff_entity_filter_breakdown_fields:
                    ret_string += 'values(%s) as entity_filter_fields by %s, serviceid, %s | `gettime`' % \
                                (entity_id_fields, entity_breakdown_id_fields, metric_qualifier)
                else:
                    ret_string += 'by %s, %s | `gettime`' % (entity_breakdown_id_fields, metric_qualifier)
        else:
            if pre_stats_operation:
                ret_string += 'values(%s) by %s, %s' % \
                                   (entity_id_fields, entity_breakdown_id_fields, entity_id_fields)
            else:
                if self.diff_entity_filter_breakdown_fields:
                    ret_string += 'values(%s) as entity_filter_fields by %s, serviceid | `gettime`' % \
                                (entity_id_fields, entity_breakdown_id_fields)
                else:
                    ret_string += 'by %s | `gettime`' % entity_breakdown_id_fields

        return ret_string

    def aggregate_entity_into_service(self):
        '''
        Generate the service aggregate based on the existing single value macro
        definition:
        appendpipe [stats $service_statop$(alert_value) AS alert_value |
          eval is_service_aggregate="1", is_entity_defined="0",
          entity_key="service_aggregate", entity_title="service_aggregate"] | `gettime`

        You'll notice that this is really really similar to the aggregate_raw_into_entity_command but using an
        appendpipe.
        '''
        return "appendpipe [" + self.aggregate_raw_into_service(entities=True) + "]"

    def gen_preview_alert_search(self, kpi):
        """
        Generate the preview alert search
        It basically means generating a normal search string, but with the kpi adjusted
        @param kpi: A kpi dictionary representing the new thing to be edited and previewed
        @type kpi: dict
        """
        service_id = kpi.get("service_id", "NEW_SERVICE_ID")
        if service_id not in self.services:
            #Add the service to the list
            service = self.backend.get(self.session_key, 'nobody', 'service', service_id)
            if service is not None:
                self.services[service_id] = service
            else:
                logger.error("No matching services found for service_id=%s", service_id)
                return None
        found = False
        for idx, old_kpi in enumerate(self.services[service_id]['kpis']):
            if kpi.get("_key") == old_kpi.get("_key"):
                #Replace the kpi
                self.services[service_id]['kpis'][idx] = kpi
                found = True
                break
        if not found:
            #We're dealing with a new kpi
            self.services[service_id]['kpis'].append(kpi)
        result = self.generate_shared_base_search_string()
        return result

    def _identify_metrics(self):
        """
        Goes through the list of metrics, stores unique metrics in a global
        variable and stores duplicate metrics in another global variable with
        appropriate aliases for metric alert_value.
        @return: None
        """
        duplicate_metric_tokens = {}
        metric_token_keys = {}
        metrics = self.base_search.get('metrics', [])
        for metric in metrics:
            entity_statop = metric.get('entity_statop')
            aggregate_statop = metric.get('aggregate_statop')
            threshold_field = metric.get('threshold_field')
            metric_id = metric.get('_key')
            if metric_id is None:
                logger.warning("kpi_base_search=%s missing a metrics key - skipping" % self.shared_base_search_id)
                continue
            if entity_statop is None or threshold_field is None:
                logger.warning("metric %s missing threshold_field or entity_statop - skipping" % metric.get("_key"))
                continue

            # For ITOA-4442, we should check and see if the "token" tuple of entity_statop, threshold_field are unique
            if (entity_statop, threshold_field) not in metric_token_keys:
                metric_token_keys[(entity_statop, threshold_field)] = metric_id
                self.unique_metric_tokens[metric_id] = {
                    'entity_statop': entity_statop,
                    'aggregate_statop': aggregate_statop,
                    'threshold_field': threshold_field
                }
            # ITOA-4442 - update the duplicate statop fields, they won't be dicts like the key field
            else:
                if (entity_statop, threshold_field) not in duplicate_metric_tokens:
                    duplicate_metric_tokens[(entity_statop, threshold_field)] = []
                duplicate_metric_tokens[(entity_statop, threshold_field)].append(metric_id)

        # ITOA-4442:  Now we iterate through the metric ids, checking for duplicates
        for tuple_key, metric_key in metric_token_keys.iteritems():
            if tuple_key not in duplicate_metric_tokens:
                continue
            duplicate_metric_ids = duplicate_metric_tokens[tuple_key]
            for duplicate_metric in duplicate_metric_ids:
                self.metric_aliases[duplicate_metric] = metric_key
