# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
"""
Provides the methods for constructing searches from KPI information.
Also provides services for the frontend for glass table and other features
"""
import json
import math

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.setup_logging import setup_logging
import ITOA.itoa_common as utils
from ITOA.itoa_exceptions import ItoaDatamodelContextError
from ITOA.storage import itoa_storage
from ITOA.datamodel_interface import DatamodelInterface
from itsi.searches.itsi_filter import ItsiFilter
from itsi.searches.itsi_shared_base_search import ItsiSharedAdhocSearch
from itsi import itsi_utils

logger = setup_logging('itsi.log', 'itsi.searches')

class ItsiKpiSearches(utils.ItoaBase):
    """
    Abstraction for anything related to ITSI KPI searches.
    Key component implemented here is search generation for KPIs
    """

    def __init__(self, session_key, kpi, service_entity_rules=None, generate_entity_filter=False, sec_grp=None):
        """
        Helper Class for generating search strings for KPI.

        @param session_key: valid session key to splunk
        @param kpi: dict representation of a kpi
        @param service_entity_rules: entity rules from service to use for entity related search generation
        @param generate_entity_filter: boolean indicating if we should generate
            the filter vs return a subsearch. False by default i.e. we'll return a subsearch.
        @param sec_grp: security group for the KPI if KPI applies to a specific security group like via service
            membership. Eg. glass table KPI searches are not restricted to a specific security group.
        @return: class instance
        """
        super(ItsiKpiSearches, self).__init__(session_key)

        self.kpi = kpi
        self.service_id = kpi.get('service_id', '')
        self.service_title = kpi.get('service_title', '')
        self.service_sec_grp = sec_grp

        # Since entities can be only in the global security group
        self.entity_sec_grp = itsi_utils.GLOBAL_SECURITY_GROUP_CONFIG.get('key')

        ItsiKpiSearches._validate(self.kpi)

        is_dm_search = ItsiKpiSearches.is_datamodel(self.kpi)
        if is_dm_search:
            self.kpi['threshold_field'] = ItsiKpiSearches._get_datamodel_threshold_field(self.kpi)

        datamodel_model = self.kpi.get('datamodel', {})
        params = {
            'generate_filter': generate_entity_filter,
            'datamodel': datamodel_model.get('datamodel') if is_dm_search else None,
            'datamodel_object_name': datamodel_model.get('object') if is_dm_search else None,
            'identifying_fields': self.kpi.get('entity_id_fields'),
            'entity_alias_filtering_fields': self.kpi.get('entity_alias_filtering_fields'),
            'service_entity_rules': service_entity_rules,
            'sec_grp': sec_grp
        }

        if self.kpi.get('is_service_entity_filter'):
            self.search_clauses = ItsiKpiSearches.get_search_clause(self.session_key, self.service_id, **params)
        else:
            self.search_clauses = None
        logger.info('Initialized ItsiKpiSearches with search_clauses="%s"', self.search_clauses)

    def get_kpi_str_attr(self, attr_name):
        """
        Get the KPI string - if its not a string default to empty
        @param attr_name: The kpi attribute name
        @type attr_name: string
        """
        attr = self.kpi.get(attr_name)
        if utils.is_valid_str(attr):
            return attr
        else:
            return ''

    @staticmethod
    def get_datamodel_context(session_key,owner,search_field,datamodel,datamodel_object_name=None, cached_datamodel_dict=None):
        """
        Given a field and a datamodel, it should return all instances of the context where the field occurs
        It should give you a string suitable for using within a splunk search. For example, if you give it
        "dest","Performance",datamodel_object_name="Storage" ... you should get back - ["All_Performance.dest"]
        (see the datamodel definition for details)
        If the search field is not found within the datamodel, then an empty array is returned
        If a datamodel object is specified and the field is not found, an empty array is returned

        @type session_key: basestring
        @param session_key: splunkd session key

        @type owner: string
        @param owner: owner context

        @type search_field: string
        @param search_field: field in the datamodel to lookup

        @type datamodel: string
        @param datamodel: datamodel to lookup the field for

        @type datamodel_object_name: string
        @param datamodel_object_name: datamodel object within the datamodel to lookup the field for

        @type cached_datamodel_dict: dict
        @param kpi: a prefetched list of datamodels

        @rtype: list of strings
        @return: list of contextual fields found for the field specified in the data model
        """
        #Validate the datamodel if one exists
        fields_array = []
        #We will not validate the datamodel object name if the datamodel isnt passed in
        if datamodel is None or len(datamodel) == 0:
            return fields_array

        #in a very special episode of a very special case
        if search_field in ['host','source','sourcetype','_time']:
            return [search_field]

        if cached_datamodel_dict:   
            datamodel_dict = cached_datamodel_dict
        else:
            datamodel_dict = DatamodelInterface.get_datamodel(
                session_key,
                '',
                itoa_storage.ITOAStorage().get_app_name(),
                datamodel
            )
        dm = datamodel_dict.get(datamodel)
        if dm is None:
            message = _("Could not locate specified datamodel %s") % datamodel
            logger.error(message)
            raise ItoaDatamodelContextError(message, logger)
        dm_objects = dm['objects']

        #Here's the thing, we don't want to filter out the datamodels based on the object
        #Because the field we're looking for could be in a parent object to the datamodel
        if len(dm_objects) == 0:
            message = _("Could not get all datamodel objects")
            logger.error(message)
            raise ItoaDatamodelContextError(message, logger)

        dm_objects_and_fields = {}
        for dm_obj in dm_objects:
            fieldnames = set()
            fields = dm_obj.get('fields',None)
            context = dm_obj.get('lineage','')
            if fields == None:
                continue
            for field in fields:
                #TODO: Here we want to add additional filter logic to determine what fields are useful to us
                if field.get('owner',None) == context:
                    fieldnames.add(field['fieldName'])

            calculated_fields = dm_obj.get('calculations',None)
            if calculated_fields == None:
                continue
            for calc in calculated_fields:
                outputFields = calc.get('outputFields',None)
                if outputFields == None:
                    #TODO: Should this be an error here?
                    continue
                for outputField in outputFields:
                    if outputField.get('owner',None) != context:
                        continue
                    if outputField.get('type',None) in ['string','number','ipv4']:
                        #If its a string or a number, or an ipv4 address
                        fieldnames.add(outputField['fieldName'])

            #Take a breather and put everything into a happy little object
            dm_objects_and_fields[dm_obj['objectName']] = {'name':dm_obj['objectName'],
                                                           'fields':fieldnames,
                                                           'parentObject':dm_obj['parentName'], #parentName can be the base event
                                                           'lineage':dm_obj['lineage']
                                                          }
        #Find the object within the fields
        if datamodel_object_name != None:
            datamodel_object = dm_objects_and_fields.get(datamodel_object_name)
            if datamodel_object is None:
                message = _("Could not find datamodel object {0} in datamodel {1}").format(datamodel_object_name,datamodel)
                logger.error(message)
                raise ItoaDatamodelContextError(message, logger)
            found = False
            while found == False and datamodel_object != None:
                if search_field not in datamodel_object['fields']:
                    datamodel_object = dm_objects_and_fields.get(datamodel_object['parentObject'])
                    continue
                found = True
            if found:
                #This loop should establish context
                field_with_context = datamodel_object['lineage'] + '.' + search_field
                fields_array.append(field_with_context)
        else:
            #Loop through all of the datamodel objects and get all of the possible representations
            for dm_object in dm_objects_and_fields.keys():
                if search_field not in dm_objects_and_fields[dm_object]['fields']:
                    continue
                #Add the datamodel and the parent context
                datamodel_object = dm_objects_and_fields[dm_object]
                field_with_context = datamodel_object['lineage'] + '.' + search_field
                fields_array.append(field_with_context)

        if len(fields_array) == 0:
            #Check the last part of the fields array and see if that can match the full context
            modified_search_field = search_field.split('.')
            if len(modified_search_field) > 1:
                fields_array = ItsiKpiSearches.get_datamodel_context(
                    session_key,
                    owner,
                    modified_search_field[-1],
                    datamodel,
                    datamodel_object_name=datamodel_object_name,
                    cached_datamodel_dict=cached_datamodel_dict
                )
                if (len(fields_array) > 0) and (fields_array[0] != search_field):
                    fields_array = []

        return fields_array

    @staticmethod
    def get_entity_filter_subsearch(service_id, entity_id_fields, entity_alias_filtering_fields,  datamodel=None, datamodel_obj_name=None):
        """
        Generate a subsearch string for entity filter string in KPI searches

        @type service_id: basestring
        @param service_id: service identifier

        @type entity_id_fields: basestring
        @param entity_id_fields: comma separated identifier fields for an entity

        @type entity_alias_filtering_fields: basestring
        @param entity_alias_filtering_fields: entity alias filtering fields from
        KPI base search

        @type datamodel: basestring
        @param datamodel: datamodel name

        @type datamodel_obj_name: basestring
        @param datamodel_obj_name: object within the datamodel

        @rtype: basestring
        @return the subsearch string, enclosed within the opening '[' and closing ']'
        """
        if not isinstance(service_id, basestring):
            raise TypeError(_('Invalid type for "service_id". Expecting non-empty string'))

        uri = '/servicesNS/nobody/SA-ITOA/itoa_interface/generate_entity_filter'
        qp = 'service_id={}'.format(service_id)

        # append entity info
        qp += '&entity_id_fields={}'.format(entity_id_fields)
        qp += '&entity_alias_filtering_fields={}'.format(entity_alias_filtering_fields)

        if datamodel and datamodel_obj_name: # we should always have both fields
            qp += '&search_type=datamodel'
            qp += '&datamodel.datamodel={}'.format(datamodel)
            qp += '&datamodel.object={}'.format(datamodel_obj_name)
        else:
            qp += '&search_type=adhoc' # this is probably not necessary FIXME

        # Subsearch resembles something like:
        #   [ 
        #   | rest
        #   "/servicesNS/nobody/SA-ITOA/itoa_interface/generate_entity_filter?service_id=1234&entity_id_fields=foo,bar&entity_alias_filtering_fields=foo,bar&search_type=datamodel&datamodel.datamodel=AppServer&datamodel.object=bar"
        #   | return $value 
        #   ]
        # Subsearch command returns two variables: "$splunk_server" & "$value".
        # We will explicitly return only "$value". "$splunk_server" is of no
        # use to us. We should also ever run only on current search head rather
        # than all search peers.
        subsearch = '[ | rest splunk_server=local "{}?{}" | return $value ]'.format(uri, qp)

        logger.info('Subsearch generated. uri=%s, query_params=%s, subsearch=%s', uri, qp, subsearch)
        return subsearch

    @staticmethod
    def _get_entity_id_fields(entity, entity_alias_filtering_fields):
        """
        get a list of id fields for this entity
        @type entity: dict
        @param entity: entity object

        @rtype: list
        @param id_fields: identifier fields for given entity
        """
        # assume a valid entity
        entity_title = entity.get('title', '')
        entity_key = entity.get('_key', '')

        # Alias fields are the list of keys for the entity, extract them
        id_fields = entity.get('identifier', {}).get('fields')

        if not isinstance(id_fields, list) or len(id_fields) < 1:
            return []

        # Filter the entity alias value to those specified in entity_alias_filtering_fields
        # Use all fields if none are specified or none are matched.
        if isinstance(entity_alias_filtering_fields, list) and len(entity_alias_filtering_fields) > 0:
            id_fields_temp = []
            for key in id_fields:
                if any(key in s for s in entity_alias_filtering_fields):
                    id_fields_temp.append(key)
            if len(id_fields_temp) > 0:
                # Only replace full list of aliases if any matching entity_alias_filtering_fields is found
                id_fields = id_fields_temp
        return id_fields

    @staticmethod
    def _gen_entity_searchterms_fieldnames(
            session_key,
            entities,
            service_has_entity_rules,
            entity_alias_filtering_fields,
            identifying_fields,
            datamodel,
            datamodel_object_name
    ):
        """
        generate entity search terms and entity fieldnames

        @type entities: list
        @param entities: entities in a service

        @type service_has_entity_rules: boolean
        @param service_has_entity_rules: indicates if corresponding service has
            entity rules configured. Doesnt imply if there are entities actually
            matching the rule

        @type entity_alias_filtering_fields: list
        @param entity_alias_filtering_fields: entity aliases on which we are to filter.

        @type identifying_fields: basestring
        @param identifying_fields: comma separated identifying fields from KPI definition

        @type datamodel: dict
        @param datamodel: datamodel model.
        
        @type datamodel_object_name: string (comma separated values)
        @param datamodel_object_name: the alias filtering fields requested in KPI. See description above for what this means

        @rtype: tuple of sets
        @return: entity_search_terms and entity_fieldnames
        """
        entity_search_terms = set()
        entity_fieldnames = set()

        for entity in entities:
            id_fields = ItsiKpiSearches._get_entity_id_fields(entity, entity_alias_filtering_fields)
            if not id_fields:
                logger.info('No id_fields found in entity="%s" key="%s". Skipping.', entity.get('title'), entity.get('_key'))
                continue

            # At this point, we have identified the keys (lhs) for aliases to use, now work on the values (rhs)
            for id_ in id_fields:
                values_for_alias = entity.get(id_, [])
                if utils.is_valid_str(values_for_alias):
                    values_for_alias = [value.strip() for value in values_for_alias.split(',')]
                entity_fieldnames.add(id_)

                # construct the kv pairs
                id_str = str(id_)
                if not utils.is_valid_str(id_str) or not isinstance(values_for_alias, list):
                    msg = _('Unable to construct eval expression')
                    logger.error('{} with LHS="{}" and RHS="{}"'.format(msg, id_str, values_for_alias))
                    raise Exception(msg)
                # If the entity value contains "\", replace it with "\\\". "\" is considered special character
                kv_pairs = [id_str + '="' + value.replace('\\', '\\\\\\') + '"' for value in values_for_alias]
                entity_search_terms.update(kv_pairs)

        # At this point we have a list of what fieldnames we should be picking from the entity
        # Now we set their value pairs according to the fields
        if service_has_entity_rules and identifying_fields is not None:
            passed_entity_search_terms = set()
            passed_entity_fieldnames = set()
            dump_fields = []
            if datamodel:
                if not datamodel_object_name:
                    raise Exception(_("`datamodel` argument requires `datamodel_object_name`"))
                for field in identifying_fields:
                    dm_fields = ItsiKpiSearches.get_datamodel_context(
                        session_key,
                        'nobody',
                        field,
                        datamodel,
                        datamodel_object_name=datamodel_object_name
                    )
                    dump_fields.append(dm_fields[0]) if dm_fields else None
            else:
                dump_fields = identifying_fields

            for i in entity_search_terms:
                # Extract value for the entity from the format alias=value specified in entity_search_terms entries
                # Note that values could contain =, so only look for the first = to identify value part
                second_part = i.split("=", 1)[1]
                for first_part in dump_fields:
                    passed_entity_search_terms.add(first_part + '=' + second_part)
            passed_entity_fieldnames.update(dump_fields)

            # Now that we have everything, reassign to the entity search terms
            entity_search_terms = passed_entity_search_terms
            entity_fieldnames = passed_entity_fieldnames
        return entity_search_terms, entity_fieldnames

    @staticmethod
    def _get_valid_entity_rules(session_key, entity_rules, service_id):
        """
        If no valid entity_rules is given, we fetch from what exists in KV
        Store.

        @type session_key: basestring
        @param session_key: splunkd session key

        @type entity_rules: list
        @param entity_rules: incoming entity rules

        @type service_id: basestring
        @param service_id: identifying field for a service corresponding to
            entity_rules

        @rtype: list
        @return a valid entity_rules
        """
        if not isinstance(entity_rules, list):
            backend = itoa_storage.ITOAStorage().get_backend(session_key)
            service = backend.get(session_key, 'nobody', 'service', service_id) #FIXME do a partial fetch.
            if not isinstance(service, dict):
                logger.warning("Could not locate record for specified service=%s", service_id)
                # TODO: We have to raise the exception one we move to aync search save
                # uncomments me and remove services = {} code
                # raise Exception(message)
                service = {}
            entity_rules = service.get('entity_rules', [])
        return entity_rules

    @staticmethod
    def _eval_entity_search_string(entity_search_terms):
        """
        Given a list of entity search terms that look like "x=y",
        return a search string

        @type entity_search_terms: list
        @param entity_search_terms: list of entity search terms

        @rtype: basestring
        @return: a consumable search string. Doesnt contain the pre-pended "search"
        """
        search_string = " OR ".join(entity_search_terms)
        if search_string == "":
            search_string = "`no_entities_matched`"
        return search_string

    @staticmethod
    def _eval_evalstring(entity_fieldnames):
        """
        Evaluate the eval_string
        @type entity_fieldnames: set
        @param entity_fieldnames: entity fieldnames

        @rtype: basestring
        @return: eval_string as requested
        """
        eval_string = "eval target_itsi_entity="
        parens = ""
        for field in entity_fieldnames:
            eval_string += "if(isnotnull('" + field + "'),'"+ field + "',"
            parens += ")"
        eval_string += '"ERROR_ALL_SEARCH_FIELDS_NULL"' + parens
        return eval_string

    @staticmethod
    def _get_entity_search_details(
            session_key,
            datamodel,
            datamodel_object_name,
            entity_rules,
            identifying_fields,
            entity_alias_filtering_fields,
            sec_grp=None
        ):
        """
        Get search details for entities given entity_rules
        @type session_key: basestring
        @param session_key: splunkd session_key

        @type datamodel: dict
        @param datamodel: datamodel model

        @type datamodel_object_name: string (comma separated values)
        @param datamodel_object_name: the alias filtering fields requested in KPI. See description above for what this means

        @type entity_rules: list
        @param entity_rules: incoming entity rules for given service_id

        @type identifying_fields: list
        @param identifying_fields: entity identifying fields from KPI definition.

        @type entity_alias_filtering_fields: basestring
        @param entity_alias_filtering_fields: comma separated string of aliases specified at config time.

        @type sec_grp: basestring
        @param sec_grp: security group for the KPI if KPI applies to a specific security group like via service
            membership. Eg. glass table KPI searches are not restricted to a specific security group.


        @rtype: dict
        @return: search details for entities
        """

        # Evaluate entity rules to identify corresponding entities. This might
        # be an expensive operation involving regexes.
        entities = ItsiFilter(entity_rules).get_filtered_objects(session_key, 'nobody')

        # We have identified entities that are associated with this service, now process the aliases
        entity_search_terms, entity_fieldnames = ItsiKpiSearches._gen_entity_searchterms_fieldnames(
                session_key,
                entities,
                isinstance(entity_rules, list) and len(entity_rules) > 0, # service_has_entity_rules 
                entity_alias_filtering_fields,
                identifying_fields,
                datamodel,
                datamodel_object_name
        )

        return {
            'entity_search_terms': entity_search_terms,
            'entity_fieldnames': entity_fieldnames,
            'has_entities': isinstance(entity_rules, list) and len(entity_rules) > 0
            }

    @staticmethod
    def get_search_clause(session_key, clause_source, **kwargs):
        """
        Goal here is to aid itsi search generation for KPIs to be able to generate
        search clauses/info that help process entity memberships for the services and KPIs

        In a service:
        > entity rules are configured to identify entities that are to be tracked
            by a service. This is the entity_rules property in service objects

        In a KPI:
        > entity identifying fields are configured to pick fields from the base
            search defined by a user for the KPI that contain the identifying
            value for the entity for the events of the search
        > entity alias filtering fields are configured to look for specific
            values to match the entity aliases to identify entities for the KPI

        The filtering fields in the KPI help filter entities relevant to the KPI
        and map them to events for the KPI

        @type session_key: basestring
        @param session_key: The splunkd session key

        @type clause_source: basestring
        @param clause_source: The ID of the service being referenced

        @type kwargs: dict
        @param kwargs: other params. Supported k-v pairs are:

            @type generate_filter: boolean
            @param generate_filter: True implies that we should generate the
            entities' filter. False implies we should not and instead return a
            consumable subsearch.

            @type datamodel: basestring
            @param datamodel: if the KPI search is a datamodel type search, the
            datamodel to validate the fields being requested

            @type datamodel_object_name: basestring
            @param datamodel_object_name: if the KPI search is a datamodel type search,
            the datamodel name to validate the fields being requested

            @type identifying_fields: basestring
            @param identifying_fields: comma separated identifying fields requested in KPI. See
            description above for what this means

            @type entity_alias_filtering_fields
            @param entity_alias_filtering_fields: entity alias filtering fields
            as specified in the KPI base search.

            @type service_entity_rules: list of dictionaries
            @param service_entity_rules: when service is created fresh with pre-configured
            KPIs like in the case with DAs creating services from templates, search
            generation cannot lookup the service from persisted store.
            In order to aid search generation in this case, pass in the entity rules from the
            service for creation case. All other cases, the entity rules should
            be looked up from persisted store since change handlers may have updated them.

        @rtype: dict
        @return: A json structure containing both the search string and the separate terms that were used
        to create the search string
        """

        if not utils.is_valid_str(clause_source):
            logger.warning('Invalid service_id="%s". Expecting non-empty string. Setting to "unknown"' % clause_source)
            clause_source = 'unknown'

        # Get all the other parameters
        generate_filter = kwargs.get('generate_filter', True)
        datamodel = kwargs.get('datamodel')
        datamodel_object_name = kwargs.get('datamodel_object_name')
        identifying_fields = kwargs.get('identifying_fields')
        entity_alias_filtering_fields = kwargs.get('entity_alias_filtering_fields')
        service_entity_rules = kwargs.get('service_entity_rules')
        sec_grp = kwargs.get('sec_grp')

        if not generate_filter:
            search = ItsiKpiSearches.get_entity_filter_subsearch(clause_source,
                identifying_fields, entity_alias_filtering_fields, datamodel, datamodel_object_name)
            logger.debug('Generated entity filter search=%s', search)
            return {"search": search}

        # hereon, lies the code to generate the entity filter search string
        # generation.
        # TODO: wrap everything below under one method. I cannot think of a good name.
        if utils.is_valid_str(identifying_fields):
            identifying_fields = identifying_fields.split(',')
        if utils.is_valid_str(entity_alias_filtering_fields):
            entity_alias_filtering_fields = entity_alias_filtering_fields.split(',')

        entity_rules = ItsiKpiSearches._get_valid_entity_rules(session_key,
                service_entity_rules, clause_source)

        entity_details = ItsiKpiSearches._get_entity_search_details(
                session_key,
                datamodel,
                datamodel_object_name,
                entity_rules,
                identifying_fields,
                entity_alias_filtering_fields,
                sec_grp=sec_grp
        )
        entity_search_terms = entity_details.get('entity_search_terms')

        # Right now we'll return both the search string we make and a list of kv search terms
        # We'll delete either one once we determine how its used/unused.
        resp = {
            "search": ItsiKpiSearches._eval_entity_search_string(entity_search_terms), # probably the only string we care about
            "search_terms": list(entity_search_terms),
            "has_entities": entity_details.get('has_entities') 
            }
        logger.debug('Search strings generated=%s', json.dumps(resp))
        return resp

    @staticmethod
    def _validate(kpi):
        """
        perform validations
        @type kpi: dict
        @param kpi: kpi object to validate
        """
        if not isinstance(kpi, dict):
            message = _('Invalid "kpi". Expecting a dictionary')
            logger.error(message)
            raise TypeError(message)

        if ItsiKpiSearches.is_datamodel(kpi):
            ItsiKpiSearches._validate_datamodel_model(kpi)

    @staticmethod
    def _validate_datamodel_model(kpi, model=None):
        """
        Validates the datamodel model has the needed fields for search generation.
        @param kpi: The kpi object
        @type kpi: dict

        @param model: dict of a datamodel model
        @type model: dict

        @param suppress_exception: if True does not raise ValueError
        @type suppress_exception: bool

        @return: True if valid, raises ValueError or TypeError otherwise
        @rtype: bool
        """
        if model is None:
            model = kpi.get('datamodel', {})
        if not isinstance(model, dict):
            raise TypeError(_('`datamodel` model must be a dict'))

        keys = ('datamodel', 'object', 'field', 'owner_field')
        prefix = _('`datamodel` model of KPI is invalid.')
        for k in keys:
            if not utils.is_valid_str(model.get(k)):
                message = _('%s. Value of "%s" field must be non-empty string.') % (prefix, k)
                logger.error(message)
                raise ValueError(message)
        return True

    @staticmethod
    def _get_datamodel_threshold_field(kpi):
        """
        Given a datamodel model return the proper threshold_field
        @param kpi: a valid kpi structure
        @type model: dict
        @return: threshold_field for use in searches
        @rtype: str
        """
        model = kpi.get('datamodel', {})
        if not isinstance(model, dict):
            raise TypeError(_('`datamodel` model must be a dict'))

        return model.get('owner_field', '')

    @staticmethod
    def is_datamodel(kpi):
        return kpi.get('search_type') == 'datamodel'

    def _get_datamodel_fields_filter_clauses(self):
        """
        KPI can pass in fields in a data model in datamodel_filter for datamodel searches
        to act as additional filters to pick events for a KPI. This method constructs
        those phrases for the where condition by ORing conditions for same field name and ANDing
        them across different field names.

        Note:
        - Invoked only for data model searches
        - If datamodel_filter_clauses is prepopulated, use that as search phrase -
            this is required by glass table which computes this phrase in the UI itself

        @return string of filter clause
        """
        if not ItsiKpiSearches.is_datamodel(self.kpi):
            return None

        # Assume caller has validated data required here
        if not len(self.kpi.get('datamodel_filter', [])) > 0:
            # Glass table computes own where clause directly, skip generation of clauses
            return self.kpi.get('datamodel_filter_clauses', '')

        # Group fields with the same name and OR them for correctness
        # Eg. (field1=condition11 OR field1=condition12) field3=condition3
        datamodel_filters = self.kpi.get('datamodel_filter', [])
        grouped_clauses = {}
        for datamodel_filter in datamodel_filters:
            field = datamodel_filter['_field']
            datamodel_filter_value = datamodel_filter['_value'].replace('\\', '\\\\\\').replace('"', '\"')
            if datamodel_filter['_operator'] != "=" and utils.is_string_numeric(datamodel_filter['_value']):
                clause = ''.join((field, datamodel_filter['_operator'], datamodel_filter_value))
            else:
                clause = ''.join((field,
                                  datamodel_filter['_operator'],
                                  '"',
                                  datamodel_filter_value,
                                  '"'))

            if field in grouped_clauses:
                grouped_clauses[field].append(clause)
            else:
                grouped_clauses[field] = [clause]

        datamodel_filter_clauses = []
        for field, clauses in grouped_clauses.items():
            if len(clauses) == 1:
                datamodel_filter_clauses.append(clauses[0])
            else:
                tmp = ''
                tmp += ' ('
                for index, clause in enumerate(clauses):
                    if index > 0:
                        tmp += ' OR '
                    tmp += clause
                tmp += ')'
                datamodel_filter_clauses.append(tmp)

        # Save this off to make future calls faster
        final_filter = ' AND '.join(datamodel_filter_clauses)
        self.kpi['datamodel_filter_clauses'] = final_filter
        return final_filter

    def _get_filtered_event_search_parts(self):
        """
        Create search pipelines that encompass the gathering and filtering of events for the search

        @return: list of search parts
        """
        search_parts = []

        # Gather Events
        inline_search_clause = False
        if not ItsiKpiSearches.is_datamodel(self.kpi):
            base_search = self.get_kpi_str_attr('base_search').rstrip(" |")
            if base_search == '':
                raise ValueError(_('Base Search of KPI must be a non-empty string'))
            #TODO: A coming refactor will make these a part of a generic base class, not an ItsiSharedAdhocSearch
            if ((self.kpi.get("is_service_entity_filter") is True and self.search_clauses is not None) and
               (ItsiSharedAdhocSearch.entity_magic in base_search or
               ItsiSharedAdhocSearch.can_optimize_entities(base_search))):
                search_parts.append(ItsiSharedAdhocSearch.append_entity_filter(base_search, self.search_clauses['search']))
                inline_search_clause = True
            else:
                search_parts.append(base_search)
        else:
            datamodel_model = self.kpi.get('datamodel', {})
            search_parts.append('| datamodel {datamodel} {object} search'.format(**datamodel_model))
        
        # Filter Events
        if not inline_search_clause and self.kpi.get("is_service_entity_filter") is True and self.search_clauses is not None:
            search_parts.append("search {0}".format(self.search_clauses['search']))
        # we need check for get_datamodel_fields_filter_clauses to handle where clause
        # strings sent from Glass Table, fixed for ITOA-3008

        if len(self.kpi.get('datamodel_filter', [])) > 0 or utils.is_valid_str(self.kpi.get('datamodel_filter_clauses')):
            datamodel_where = self._get_datamodel_fields_filter_clauses()
            if utils.is_valid_str(datamodel_where):
                search_parts.append("search {0}".format(datamodel_where))
        logger.debug('Generated filtered event search parts=%s', search_parts)
        return search_parts

    def get_filtered_event_search(self):
        """
        Compute and return the event search with all filters
        @return: filtered event search
        @rtype: str
        """
        search_parts = self._get_filtered_event_search_parts()
        return " | ".join(search_parts)

    def gen_alert_search(self):
        """
        Generate the alert search per the current KPI model
        @return: the alert search SPL
        @rtype: str
        """
        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()
        serviceid = self.service_id if self.service_id else 'N/A'
        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_into_entity({entity_statop}, {threshold_field}, {entity_breakdown_id_fields})`
                | eval sec_grp = "{entity_sec_grp}"
                | `match_entities({entity_breakdown_id_fields}, sec_grp)` 
                | eval serviceid = "{serviceid}"
                | `aggregate_entity_into_service({aggregate_statop})`
            '''.format(entity_sec_grp=self.entity_sec_grp, serviceid=serviceid, **self.kpi)
        else:
            aggregation_pipelines = '''
                `aggregate_raw_into_service({aggregate_statop}, {threshold_field})`
            '''.format(**self.kpi)
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        # Apply Thresholds and Other Augmentations
        #The service_id is set explicitly because of ITOA-5345; serviceid leakage with multiple entities
        if self.get_kpi_str_attr("service_id") and self.get_kpi_str_attr("_key") and self.get_kpi_str_attr("title"):
            augmentation_pipelines = '''
                `assess_severity({service_id}, {_key}, true, true)`
                | eval kpi="{title}", urgency="{urgency}", alert_period="{alert_period}", serviceid="{service_id}" | `assess_urgency`
            '''.format(**self.kpi)
        else:
            # Special handling for Glass Table's non-KPI usage of search generation
            aggregate_eval = self.get_kpi_str_attr("aggregate_eval").strip(" |")
            if not aggregate_eval:
                aggregate_eval = 'eval alert_color="#CCCCCC", alert_level=-1, alert_severity="unknown"'
            augmentation_pipelines = 'eval aggregate=alert_value | ' + aggregate_eval
        search_parts.append(utils.squish_whitespace(augmentation_pipelines))

        #TODO: add in the gap detection and threshold evaluation pipeline

        return ' | '.join(search_parts)

    def gen_time_series_search(self):
        """
        Generates a search for gathering the raw data of the KPI in a time series format.
        Note that a time series always returns the aggregate, not entity level information, but will aggregate entity
        level information is entity breakdown is enabled.

        @return: search string for an aggregate time series
        @rtype: str
        """
        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()

        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_into_entity_time_series({entity_statop},
                                                       {threshold_field}, {entity_breakdown_id_fields}, {search_alert_earliest})`
                | `aggregate_entity_into_service_time_series({aggregate_statop}, {search_alert_earliest})`
            '''.format(**self.kpi)
        else:
            aggregation_pipelines = '''
                `aggregate_raw_into_service_time_series({aggregate_statop}, {threshold_field}, {search_alert_earliest})`
            '''.format(**self.kpi)
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        # Apply Thresholds and Other Augmentations
        if self.get_kpi_str_attr("service_id") and self.get_kpi_str_attr("_key") and self.get_kpi_str_attr("title"):
            augmentation_pipelines = '''
                `assess_severity({service_id}, {_key})`
            '''.format(**self.kpi)
        else:
            # Special handling for Glass Table's non-KPI usage of search generation
            aggregate_eval = self.get_kpi_str_attr("aggregate_eval").strip(" |")
            if not aggregate_eval:
                aggregate_eval = ' eval alert_color="#CCCCCC", alert_level=-1, alert_severity="unknown"'
            augmentation_pipelines = 'eval aggregate=alert_value | ' + aggregate_eval

        search_parts.append(utils.squish_whitespace(augmentation_pipelines))

        return ' | '.join(search_parts)

    def gen_entity_time_series_search(self):
        """
        Generates a search for gathering the raw data of the KPI in a time series format.
        Note that this returns entity level information, but only for a limited number of entities.

        @return: search string for a limited entity time series
        @rtype: str
        """

        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()

        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_into_limited_entity_time_series({entity_statop}, {threshold_field},
                                                              {entity_breakdown_id_fields}, {search_alert_earliest})`
            '''.format(**self.kpi)
        else:
            raise ValueError(_('Cannot generate an entity time series for a KPI witout entity breakdown enabled.'))
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        return ' | '.join(search_parts)

    def gen_compare_search(self):
        """
        Generates a search for gathering the raw data of the KPI and comparing the most recent value to the previous.
        Note that this always returns the aggregate, not entity level information, but will aggregate entity
        level information is entity breakdown is enabled.

        @return: search string for an aggregate comparison search
        @rtype: str
        """

        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()

        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_and_compare({entity_statop}, {aggregate_statop}, {threshold_field},
                                           {entity_breakdown_id_fields}, {search_alert_earliest})`
            '''.format(**self.kpi)
        else:
            aggregation_pipelines = '''
                `aggregate_raw_and_compare({aggregate_statop}, {threshold_field}, {search_alert_earliest})`
            '''.format(**self.kpi)
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        # Apply Thresholds and Other Augmentations
        if self.get_kpi_str_attr("service_id") and self.get_kpi_str_attr("_key") and self.get_kpi_str_attr("title"):
            augmentation_pipelines = '''
                `assess_severity({service_id}, {_key})`
            '''.format(**self.kpi)
        else:
            # Special handling for Glass Table's non-KPI usage of search generation
            aggregate_eval = self.get_kpi_str_attr("aggregate_eval").strip(" |")
            if not aggregate_eval:
                aggregate_eval = ' eval alert_color="#CCCCCC", alert_level=-1, alert_severity="unknown"'
            augmentation_pipelines = 'eval aggregate=alert_value | ' + aggregate_eval
        search_parts.append(utils.squish_whitespace(augmentation_pipelines))

        return ' | '.join(search_parts)

    def gen_single_value_search(self):
        """
        Generates a search for gathering the raw data of the KPI and aggregates it to a single value.
        Note that this always returns the aggregate, not entity level information, but will aggregate entity
        level information is entity breakdown is enabled.

        @return: search string for an aggregate single value search
        @rtype: str
        """

        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()

        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_into_single_value({entity_statop}, {aggregate_statop}, {threshold_field},
                                           {entity_breakdown_id_fields}, {search_alert_earliest})`
            '''.format(**self.kpi)
        else:
            aggregation_pipelines = '''
                `aggregate_raw_into_single_value({aggregate_statop}, {threshold_field}, {search_alert_earliest})`
            '''.format(**self.kpi)
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        # Apply Thresholds and Other Augmentations
        if self.get_kpi_str_attr("service_id") and self.get_kpi_str_attr("_key") and self.get_kpi_str_attr("title"):
            augmentation_pipelines = '''
                `assess_severity({service_id}, {_key})`
            '''.format(**self.kpi)
        else:
            # Special handling for Glass Table's non-KPI usage of search generation
            aggregate_eval = self.get_kpi_str_attr("aggregate_eval").strip(" |")
            if not aggregate_eval:
                aggregate_eval = ' eval alert_color="#CCCCCC", alert_level=-1, alert_severity="unknown"'
            augmentation_pipelines = 'eval aggregate=alert_value | ' + aggregate_eval
        search_parts.append(utils.squish_whitespace(augmentation_pipelines))

        return ' | '.join(search_parts)

    def gen_backfill_search(self):
        """
        For the given KPI, returns the backfill search

        @return a json structure containing the search
        @retval dict
        """

        bucket_field = "itsi_backfill_bucket_string"
        kpi_monitoring_frequency_field = "alert_period"
        kpi_calculation_period_field = "search_alert_earliest"

        def _eval_ith_minly_bucket(i, offset=0):
            return "eval _bmin{i}=floor((floor(_time / 60) % 1440 + {offset}))".format(i=i, offset=offset)

        def _eval_ith_bucket(i, mf, cp):
            """
            Make an interval of X minutes where X >= cp and X is a multiple of mf.
            The most recent `cp` minly blocks will get IDs from the corresponding minly
            buckets; the remaining blocks will get an ID of -1
            """
            block_length = int(math.ceil(float(cp) / mf) * mf)
            bucket_eval = ("eval _bkt_blk{i}=_bmin{i} % {block_length}"
                           " | eval _b{i}=case(_bkt_blk{i} < {tail}, -1, 1=1, _bmin{i}-_bkt_blk{i})"
                           .format(i=i, block_length=block_length, tail=block_length - cp))
            return bucket_eval

        def _gen_bucket_clause_overlapping(mf, cp):
            """
            Search generator for the case of overlapping calculation period buckets.
            WARNING: the first `nbuckets` (see code) buckets after the `earliest` time value will be truncated.
            Clients of this search will need to set the effective earliest time to be
            `desired_earliest` - `mf` and append | search _time > `desired_earliest` at the end
            """
            nbuckets = int(math.ceil(cp / float(mf)))
            nmax = 10000           # max num buckets for which this codegen will work (no guarantees
            # that Splunk will be able to handle the resultant search though!)
            assert mf <= cp and nbuckets < nmax
            npad = len(str(nmax))
            b_string_element = lambda i: "_b{i}.\"-b{ii:0>{npad}d}\"".format(i=i, ii=nmax-i, npad=npad)
            bucket_evals = " | ".join(_eval_ith_minly_bucket(i, offset=i * mf) for i in range(nbuckets))
            bucket_evals += " | " + " | ".join(_eval_ith_bucket(i, mf, cp) for i in range(nbuckets))
            bucket_string = ".\" \".".join(b_string_element(i) for i in range(nbuckets))
            bucket_params = {
                "bucket_evals": bucket_evals,
                "bucket_string": bucket_string,
                # note: makemv/mvexpand doesn't seem to play well with _-prefixed field names, so use
                # a longer quasi-namespaced identifier itsi_backfill_bucket_string here
                "bucket_field": bucket_field
            }
            return ("   {bucket_evals}"
                    " | eval {bucket_field}={bucket_string}"
                    " | makemv {bucket_field}".format(**bucket_params))

        def _gen_bucket_clause_gaps(mf, cp):
            bucket_params = {
                "minly_eval": _eval_ith_minly_bucket(0),
                "bucket_eval": _eval_ith_bucket(0, mf, cp),
                "bucket_field": bucket_field
            }
            return ("   {minly_eval}"
                    " | {bucket_eval}"
                    " | rename _b0 as {bucket_field}".format(**bucket_params))

        def _gen_bucket_clause_even_splits(mf, cp):
            return "   bucket _time span={cp}m | eval {bucket_field}=_time ".format(cp=cp, bucket_field=bucket_field)

        monitoring_frequency = int(self.kpi.get(kpi_monitoring_frequency_field))
        calculation_period = int(self.kpi.get(kpi_calculation_period_field))

        if monitoring_frequency < calculation_period:
            bucketing_search_fn = _gen_bucket_clause_overlapping
        elif monitoring_frequency > calculation_period:
            bucketing_search_fn = _gen_bucket_clause_gaps
        else:
            bucketing_search_fn = _gen_bucket_clause_even_splits

        synthetic_bucket_clause = bucketing_search_fn(monitoring_frequency, calculation_period)

        # Gather and Filter Events
        search_parts = self._get_filtered_event_search_parts()
        # Add synthetic bucket IDs
        search_parts.append(utils.squish_whitespace(synthetic_bucket_clause))
        # Aggregate Data
        if self.kpi.get('is_entity_breakdown') is True:
            aggregation_pipelines = '''
                `aggregate_raw_into_entity_backfill(
                    {entity_statop}, {threshold_field}, {entity_breakdown_id_fields}, {alert_period}, {bucket_field}
                 )`
                | eval sec_grp = "{entity_sec_grp}"
                | `match_entities({entity_breakdown_id_fields}, sec_grp)`
                | `aggregate_entity_into_service_backfill({aggregate_statop})`
            '''.format(bucket_field=bucket_field, entity_sec_grp=self.entity_sec_grp, **self.kpi)
        else:
            aggregation_pipelines = '''
                `aggregate_raw_into_service_backfill(
                    {aggregate_statop}, {threshold_field}, {alert_period}, {bucket_field}
                 )`
            '''.format(bucket_field=bucket_field, **self.kpi)
        search_parts.append(utils.squish_whitespace(aggregation_pipelines))

        # Apply augmentations
        # (1) severity fields
        assess_severity_pipelines = '`assess_severity({service_id}, {_key}, true, false)`'.format(**self.kpi)
        search_parts.append(utils.squish_whitespace(assess_severity_pipelines))
        # (2) KPI metadata evals
        if self.get_kpi_str_attr("service_id") and self.get_kpi_str_attr("_key") and self.get_kpi_str_attr("title"):
            augmentation_pipelines = '''
                  eval itsi_kpi_id="{_key}" | eval itsi_service_id="{service_id}"
                | eval is_service_max_severity_event="0"
                | eval kpi="{title}", urgency="{urgency}", alert_period="{alert_period}" | `assess_urgency`
            '''.format(**self.kpi)
            search_parts.append(utils.squish_whitespace(augmentation_pipelines))

        # Workaround for ITOA-2949
        if not self.kpi.get('is_entity_breakdown'):
            search_parts.append(utils.squish_whitespace(' eval is_service_aggregate="1"'))

        return {'backfill_search': ' | '.join(search_parts)}


    def gen_kpi_searches(self, gen_alert_search=True):
        """
        Returns searches and other metadata generated for the KPI

        @return a json structure containing the searches
        @retval dict
        """

        # Generate our Primary Searches
        gather_filter_search = self.get_filtered_event_search()
        alert_search = None
        if gen_alert_search:
            alert_search = self.gen_alert_search()
        time_series_search = self.gen_time_series_search()
        if self.kpi.get('is_entity_breakdown'):
            entity_time_series_search = self.gen_entity_time_series_search()
        else:
            entity_time_series_search = time_series_search
        compare_search = self.gen_compare_search()
        single_value_search = self.gen_single_value_search()

        return {
            'time_series_search': time_series_search,
            'entity_time_series_search': entity_time_series_search,
            'single_value_search': single_value_search,
            'compare_search': compare_search,
            'alert_search': alert_search,
            'kpi_base_search': gather_filter_search
            }
