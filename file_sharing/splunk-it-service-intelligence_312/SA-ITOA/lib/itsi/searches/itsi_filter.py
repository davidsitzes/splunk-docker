# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import json
import re
import time

from splunk.appserver.mrsparkle.lib import i18n
from ITOA.itoa_common import is_valid_str
from ITOA.setup_logging import setup_logging
from itsi.objects.itsi_entity import ItsiEntity
from itsi.itsi_utils import GLOBAL_SECURITY_GROUP_CONFIG, ILLEGAL_CHARACTERS

logger = setup_logging('itsi.log', 'itsi.searches.filter')

class ItsiFilter(object):
    """
    The filter does a couple separate things.  First, it takes in a json filter specified
    by the UI, which can be a combination of AND's OR's and NOT operations along
    with items that may or may not be wildcarded according to the splunk wildcard specifications
    (e.g. *str, str*, *str* s*tr).
    """
    def __init__(self, source_json=None, sec_grp=None):
        """
        Construct an itsi filter object

        @type source_json: iterable (list,dict)
        @param source_json:  A parsed json object, dict or list

        @type sec_grp: basestring
        @param sec_grp: key of security group to apply filter to
        """
        self.kvstore_filter = None
        if isinstance(source_json, basestring):
            # We will need to extract the json, if they didn't read the documentation above
            self.source = json.loads(source_json)
        elif isinstance(source_json, dict) or isinstance(source_json, list):
            # We're probably dealing with the right parameters here
            self.source = source_json
        elif source_json is None:
            self.source = []
        else:
            raise Exception(_("Source data could not be recognized as a string or parsed json. Data passed in: %s") % str(source_json))
        self.sec_grp_key = sec_grp
        self.sec_grp_filter = {'$or': [{'sec_grp': self.sec_grp_key}, {'sec_grp': GLOBAL_SECURITY_GROUP_CONFIG.get('key')}]}

    @staticmethod
    def normalize_rule_value(value, rule_type):
        split_values = value.replace('\\"', '"').split(',')
        normalized_values = []
        for split_value in split_values:
            split_value = re.escape(split_value)
            split_value = split_value.replace("\\*", "*")
            for i in ILLEGAL_CHARACTERS:
                if i in split_value:
                    message = _("Illegal character %s in value %s") % (i, split_value)
                    logger.error(message)
                    raise Exception(message)

            # All done with validation, now build the filter
            if split_value.find('*') != -1:  # regex value identified
                split_value = split_value.replace('*', '.*?')
            normalized_values.append(split_value)
        return normalized_values

    def generate_filter_expression(self, source):
        """
        Generate the root filter expression given a source expression
        There are three parameters
        @param source: The source expression in a json format - defined in ITOA-2287
        @type source: A dict
        """
        if not isinstance(source, dict):
            message = _("Expected a dict for the filter expression, got something else")
            logger.error(message)
            raise Exception(message)
        rule_type = source.get('rule_type', '').lower()
        field = source.get('field', None)
        # if field is None we have bigger problems, but that's the default above...
        if field is not None:
            field = field.replace('\\"', '"')

        field_type = source.get('field_type')

        if (not is_valid_str(field_type)) or \
                (not any(field_type == allowed_type for allowed_type in ['alias', 'info', 'title', 'services'])):
            message = _("Unexpected value='{0}' specified for field type, with type='{1}'.").format(field_type,
                                                                                                type(field_type))
            logger.error(message)
            raise Exception(message)

        # Generate filter to identify presence of field in the respective field type
        field_type_filter = {} # do not filter fields by default
        if field_type == 'alias':
            field_type_filter = {'identifier.fields': field}
        elif field_type == 'info':
            field_type_filter = {'informational.fields': field}

        value = source.get('value', None)
        if not isinstance(value, basestring):
            message = _("Expected value definition in the json")
            logger.error(message)
            raise Exception(message)

        # For each value specified, construct the required filter
        split_values = ItsiFilter.normalize_rule_value(value, rule_type)
        field_name = field
        if field == 'services':
            field_name = 'services.title'
        not_equal_filter = {}
        regex_string = ''
        for split_value in split_values:
            # All done with validation, now build the filter
            # Since the only way to perform case insensitive string compare is using regex,
            # construct a regex for the single value lookup
            # KV store does not seem to support regex lookups for array membership checks correctly
            # Current "not" check works great when all entries match criteria but
            # wrongly includes entries where at least one element violates the "not" rule
            # Lets get what filtering we can from KV store and post filter the results (see self.post_filter)

            if rule_type == 'not' and len(split_value) == 0 and not not_equal_filter:
                # Regex cannot be used for empty value exclusion, so special handle it
                not_equal_filter[field_name] = {'$ne': split_value}
            else:
                # OR the field values within the regex rather than using $or kv filter for split values
                if len(regex_string) > 0:
                    regex_string += '|'
                regex_string += split_value

        kv_regex_filter = {}
        if len(regex_string) > 0:
            if rule_type == 'not':
                regex_string = '^(?!' + regex_string + ').*$'
            else:
                regex_string = '^(' + regex_string + ')$'
            kv_regex_filter[field_name] = {'$regex': regex_string, '$options': 'i'}

        if kv_regex_filter and not_equal_filter:
            field_value_filter = {'$or': [kv_regex_filter, not_equal_filter]}
        elif kv_regex_filter:
            field_value_filter = kv_regex_filter
        else:
            field_value_filter = not_equal_filter

        return {'$and': [field_type_filter, field_value_filter]}

    def generate_kvstore_filter(self, regenerate=False):
        """
        Generates the kvstore_filter from the source json
        @param regenerate:  Force a regeneration of the kvstore_filter, used more in testing
        @type regenerate: Boolean
        """
        if self.kvstore_filter is not None and regenerate is False:
            return self.kvstore_filter

        # We plan to currently support only one level of nesting as follows:
        #    > All rule items are ORed at the top level.
        #    > Only one level of Nesting is supported and all rule items in the nested level will be ANDed
        #    > Sample:
        #         key1=value1,value1.1 AND key=value2
        #         OR
        #         key3=value3 AND key4=value4
        # We will need to change the json formatting if we're expecting more nesting or combination of AND and OR

        or_expressions = []
        # Process the top level OR terms
        for rule_group in self.source:
            or_term = rule_group.get('rule_items')
            and_expressions = []
            # Process the first level nested AND terms
            if isinstance(or_term, list) and len(or_term) > 0:
                for and_term in or_term:
                    leaf = self.generate_filter_expression(and_term)
                    and_expressions.append(leaf)
                or_expressions.append({"$and": and_expressions})

        # set filter to empty if or_expressions is an empty list indicating no filters were found
        self.kvstore_filter = None if not isinstance(self.sec_grp_key, basestring) else self.sec_grp_filter
        if len(or_expressions) >= 1:
            if self.kvstore_filter is None:
                self.kvstore_filter = {'$or': or_expressions}
            else:
                self.kvstore_filter = {'$and': [self.kvstore_filter, {'$or': or_expressions}]}

        return self.kvstore_filter

    def post_filter(self, entities, kvstore_filter, offset, count):
        """
        post_filter makes up for lacking query support in KV store
        KV store queries dont support regex for $nin or $not

        As a result of this, when we issue a "not" lookup for regex values
        it works fine for other fields. But for service titles which is an
        array of dictionaries, it returns documents that have at least one
        array member violating the rule.
        Example:
        consider entities:
        ['services': [{title: 'a'}, {title: 'b}], _key: '1'],
        ['services': [{title: 'a'}, {title: 'c'], _key: '2']
        ['services': [{title: 'b}], _key: '3']
        Our filter for handling not rule type with value 'b' will return:
        ['services': [{title: 'a'}, {title: 'b}], _key: '1'], <--- Included coz title = 'a' violates not rule for 'b'
        ['services': [{title: 'a'}, {title: 'c'], _key: '2']
        but what we expect is a membership like check which should output:
        ['services': [{title: 'a'}, {title: 'c'], _key: '2']

        As a result, we will post process results to identify rules that are explicitly excluding
        specific services from an entity and to exclude the entity itself if one or more services
        are marked explicitly for exclusion

        @type: List of Dicts
        @param entities: list of entities returned by KV store query process which need to be post filtered

        @type: List of Dicts
        @param kvstore_filter: generated KV store filter

        @type: int
        @param offset: "offset"th # of entity is the starting position for page of results to return

        @type: int
        @param count: number of entities to return in page of results

        @rtype: List of Dicts
        @return: subset of entities that are still valid result set after applying post filter
        """
        def _mark_service_and_exclusion(rule_or_term, service):
            """
            Marks service as and_excluded or and_included if rule evaluation explicitly
            identified an inclusion or exclusion by and terms within the or term passed in

            @type list of dicts
            @param rule_or_term: the parent OR term in the rule comprining of 0 or more AND terms

            @type JSON dict object
            @param service: the service that needs to be evaluated for inclusion/exclusion

            @return: None, passed in service object has and exclusion and inclusion marked inline
            """
            service['and_excluded'] = False
            service['and_included'] = False

            if not isinstance(rule_or_term, list):
                return

            atleast_one_services_rule_found = False
            for rule_and_term in rule_or_term:
                if not isinstance(rule_and_term, dict):
                    continue

                if rule_and_term['field'] == 'services':
                    atleast_one_services_rule_found = True
                    rule_type = rule_and_term['rule_type'].lower()
                    normalized_values = ItsiFilter.normalize_rule_value(
                        rule_and_term['value'],
                        rule_type
                    )
                    for normalized_value in normalized_values:
                        if normalized_value == '':
                            service['and_included'] = True
                            continue

                        service_match = re.match(
                            r'^' + normalized_value + '$',
                            service.get('title'),
                            re.IGNORECASE
                        )
                        if service_match is not None:
                            if rule_type == 'not':
                                service['and_excluded'] = True
                            else:
                                service['and_included'] = True

            if not atleast_one_services_rule_found:
                # The entire OR term did not include/exclude the service based on a services rule
                # So consider it as included by some other rule
                service['and_included'] = True

        post_filtered_results = []
        for entity in entities:
            for service in entity.get('services', []):
                if not isinstance(service, dict):
                    continue
                service['excluded'] = False
                service['included'] = False
                if not isinstance(self.source, list):
                    continue
                # Process the top level OR terms
                for rule_group in self.source:
                    # Process the AND terms within the top level OR term
                    _mark_service_and_exclusion(rule_group.get('rule_items'), service)

                    # Service is marked excluded only if it has not been marked as explicitly included by an OR rule
                    if (not service['included']) and service['and_excluded']:
                         service['excluded'] = True
                    # Service is marked included if explicitly included by the and rules
                    if (not service['and_excluded']) and service['and_included']:
                         service['included'] = True

            # An entity is excluded from results if it has atleast one service marked explicitly for exclusion
            # but not included explicitly by any other OR rule
            if (('services' not in entity) or (len(entity['services']) == 0) or
                all(
                    (not isinstance(service, dict)) or (not service['excluded']) or service['included']
                    for service in entity.get('services', []))
                ):
                post_filtered_results.append(entity)

        if (count is not None) and (offset is not None):
            count = int(count)
            offset = int(offset)
            end_offset_requested = offset + count
            count_of_results = len(post_filtered_results)

            if (count_of_results < offset) or (end_offset_requested < offset):
                raise Exception(_('Invalid range requested. offset: {0}, count: {1}, result set count: {2}').format(
                        offset,
                        count,
                        count_of_results
                    ))

            range_end = end_offset_requested
            if count_of_results < end_offset_requested:
                range_end = count_of_results

            return post_filtered_results[offset : range_end]

        return post_filtered_results

    def get_filtered_objects(self, session_key, owner, **kwargs):
        """
        Gets objects filtered according to generated filter spec.

        In the end, I expect that this and the constructor are the only two methods external
        consumers will use when they aren't debugging
        @param session_key: the splunkd sessionKey
        @type session_key: string

        @param owner: collection context.  usually "nobody"
        @type owner: String

        @param kwargs: please see ItoaObject::get_bulk for a list of the parameters, includes things like
                       sortKey, direction, etc. Include current_user_name if results need to be scoped to
                       specified user.
        @type kwargs: dict
        """
        start_time = time.time()
        current_user = kwargs.get('current_user_name', 'nobody')
        logger.info("Transaction: Begin Entity Filter: start_time=%s", start_time)
        kvstore_filter = self.generate_kvstore_filter()
        logger.debug('kvstore_filter=%s', kvstore_filter)
        if kvstore_filter is None:
            # Return no entities if there is no rule specified
            return []
        # Send the filter out and down to the backend
        self.entity_object = ItsiEntity(session_key, current_user)
        results = self.entity_object.get_bulk(owner,
                                              filter_data=kvstore_filter,
                                              sort_key=kwargs.get('sort_key', None),
                                              sort_dir=kwargs.get('sort_dir', None),
                                              fields=kwargs.get('fields', None))
        post_filtered_results = self.post_filter(results, kvstore_filter, kwargs.get('skip'), kwargs.get('limit'))
        end_time = time.time()
        job_time = end_time - start_time
        logger.info("Transaction: End Entity Filter: start_time=%s end_time=%s job_time=%s current_user=%s",
                    start_time, end_time, job_time, current_user)
        return post_filtered_results

    def get_filtered_objects_count(self, session_key, owner, **kwargs):
        """
        Gets count of objects filtered according to the filter spec. If no filter spec is passed in
        Then it will invoke generate_kvstore_filter and we'll grab that

        @param session_key: the splunkd sessionKey
        @type session_key: string

        @param owner: The technical owner of the collection.  Can be nobody
        @type owner: String

        @param kwargs: please see ItsiFilter::get_filtered_objects for a list of the parameters.
        @type kwargs: dict

        @rtype: number
        @return: count of entities matching filter
        """

        results = self.get_filtered_objects(session_key, owner, **kwargs)
        return {"count": len(results)}
