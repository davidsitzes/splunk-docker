# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import splunk.util
import datetime
import re
from splunk.appserver.mrsparkle.lib import i18n
from ITOA import itoa_common

logger = itoa_common.get_itoa_logger('itsi.object.time_block_utils')

DEFAULT_POLICY_KEY = 'default_policy'

CRON_ELEMENT_TYPES = [  # matches keys in CRON_ELEMENT_TYPE_MAP
    'minute',
    'hour',
    'day_of_month',
    'month',
    'day_of_week'
]

CRON_ELEMENT_TYPE_MAP = {
    'minute': {
        'range': [0, 59],
        'disabled': False,
        'minutes': 1  # 1 minute in 1 minute
    },
    'hour': {
        'range': [0, 23],
        'disabled': False,
        'minutes': 60  # 60 minutes in 1 hour
    },
    'day_of_month': {
        'range': [0, 30],  # matches cron range [1, 31]
        'disabled': True,  # currently unsupported
        'minutes': 1440  # 1440 minutes in 1 day
    },
    'month': {
        'range': [0, 11],  # matches cron range [1, 12]
        'disabled': True,  # currently unsupported
        # Note: Need to find a way to handle different months, if and when the time comes...
        'minutes': 44640  # 44640 minutes in 1 month (31 days)
    },
    'day_of_week': {
        'range': [0, 6],  # [0 == Mon, 6 == Sun]; matches cron range [1 == Mon, 7 == Sun]
        'disabled': False,
        'minutes': 1440  # 1440 minutes in 1 day
    }
}

CRON_ELEMENT_SEPARATOR = ' '


class PolicyFilter(object):
    """
    Class that provides utility methods to map timestamp to KPI threshold policy
    """
    def __init__(self, threshold_spec):
        """
        Construct policy filter. This constructor converts and caches the policies' time blocks
        in order to make the timestamp to KPI threshold policy comparison faster.

        @type threshold_spec: dict
        @param threshold_spec: threshold policies container aka 'time_variate_thresholds_specification' in the kpi dict
        """
        if not itoa_common.is_valid_dict(threshold_spec):
            error_msg = _('Invalid KPI threshold_spec: {0}. Expected dict.').format(threshold_spec)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        policies = threshold_spec.get('policies')
        if not itoa_common.is_valid_dict(policies):
            error_msg = _('Invalid KPI policies: {0}. Expected dict.').format(policies)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        if len(policies) == 0:
            error_msg = _('Invalid KPI policies: {0}. Expected dict to not be empty.').format(policies)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        self.expanded_time_blocks = {}
        for policy_key, policy in policies.iteritems():
            policy_time_blocks = policy.get('time_blocks', [])
            time_block_ranges = []
            for time_block in policy_time_blocks:
                temp_time_block_ranges = ItsiTimeBlockUtils.expand_time_block(time_block)
                time_block_ranges += temp_time_block_ranges
            # sort ranges to make looking for conflicts faster
            time_block_ranges.sort()
            self.expanded_time_blocks[policy_key] = time_block_ranges

    @staticmethod
    def check_time_block_conflict_between(input_time_block_range, time_block_ranges):
        """
        Determine if there's a time conflict/overlap between input_time_block_range and time_block_ranges

        @type input_time_block_range: [int, int]
        @param input_time_block_range: time block range to test

        @type time_block_ranges: list of [int, int]
        @param time_block_ranges: the items in input_time_block_range will be tested against time_block_ranges

        @rtype: boolean
        @return: True if a conflict exists, False otherwise
        """
        input_time_block_start = input_time_block_range[0]
        input_time_block_end = input_time_block_range[1]
        for i in range(0, len(time_block_ranges)):
            time_block_range = time_block_ranges[i]
            time_block_start = time_block_range[0]
            time_block_end = time_block_range[1]
            # check if start time or end time falls within time block range
            if (
                (time_block_start <= input_time_block_start <= time_block_end) or
                (time_block_start <= input_time_block_end <= time_block_end)
            ):
                return True

        return False

    def get_policy_key(self, time):
        """
        Get KPI threshold policy key for given timestamp

        @type time: string, int, or float
        @param time: UTC epoch timestamp

        @rtype: str
        @return: the one policy key that is associated with provided timestamp.
        """
        # first, get current time information
        tz = splunk.util.utc
        date = datetime.datetime.fromtimestamp(float(time), tz)

        # since we only have ONE timestamp to test, we can directly get the [start_minute, end_minute] from the timestamp
        time_week_minute = date.weekday() * 1440 + date.hour * 60 + date.minute
        time_range = [time_week_minute, time_week_minute]

        # find policy associated with time block
        found_policy_key = DEFAULT_POLICY_KEY
        for policy_key, policy_time_blocks in self.expanded_time_blocks.iteritems():
            # if we find conflicting time blocks in policy_time_blocks, it means we've found our policy
            if PolicyFilter.check_time_block_conflict_between(time_range, policy_time_blocks):
                found_policy_key = policy_key
                break

        return found_policy_key


class ItsiTimeBlockUtils(object):
    """
    Class that provides utility methods related to time blocks
    aka the data structure used for KPI time variant thresholds
    """

    @staticmethod
    def validate_time_block_duration(time_block_duration):
        """
        Ensure time block duration is an int and is within range

        @type time_block_duration: int
        @param time_block_duration: duration of time block, in minutes

        @rtype: bool
        @return: True if time block duration is valid, raises exception otherwise
        """
        # ensure duration is number
        if not isinstance(time_block_duration, int):
            error_msg = _('Invalid type "{0}" for duration: {1}. Expected int.').format(type(time_block_duration), time_block_duration)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        # ensure duration is within range
        duration_min = 1  # duration must be at least 1m
        duration_max = 1440  # duration must be at most 24h aka 1440m
        if not (duration_min <= time_block_duration <= duration_max):
            error_msg = _('Invalid duration: {0}. Expected value in range: {1} - {2}.').format(time_block_duration, duration_min, duration_max)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        return True

    @staticmethod
    def expand_time_block_cron(time_block):
        """
        Ensure the cron string in time_block is valid and expand time_block into time blocks with single numbers aka no wildcards

        @type time_block: [basestring, int]
        @param time_block: time block to expand

        @rtype: list of [basestring, int]
        @return: Expanded list of time blocks if time block cron is valid, raises exception otherwise
        """
        time_block_cron = time_block[0]
        time_block_duration = time_block[1]

        if not isinstance(time_block_cron, basestring):
            error_msg = _('Invalid type "{0}" for time block cron: {1}. Expected basestring.').format(type(time_block_cron), time_block_cron)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        cron_values = time_block_cron.split(CRON_ELEMENT_SEPARATOR)
        if len(cron_values) != len(CRON_ELEMENT_TYPES):
            error_msg = _('Invalid time block cron: {0}. Expected {1} elements, received {2}.').format(time_block_cron, len(CRON_ELEMENT_TYPES), len(cron_values))
            logger.debug(error_msg)
            raise ValueError(error_msg)

        time_blocks = []
        # validate cron elements
        cron_numbers_seen = set()  # keep track of numbers we've already gone through
        # expand number ranges to create multiple time blocks
        cron_element_type = 'day_of_week'
        day_index = CRON_ELEMENT_TYPES.index(cron_element_type)
        day_numbers = ItsiTimeBlockUtils.expand_cron_element(cron_values[day_index], cron_element_type)

        if len(day_numbers) == 1:
            time_blocks.append(time_block)
        else:
            cron_numbers_seen = set()
            for day_number in day_numbers:
                if day_number not in cron_numbers_seen:
                    cron_numbers_seen.add(day_number)
                    # clone cron values
                    temp_time_block_cron = list(cron_values)
                    # update time block with single day number
                    temp_time_block_cron[day_index] = str(day_number)
                    temp_time_block = [CRON_ELEMENT_SEPARATOR.join(temp_time_block_cron), time_block_duration]
                    time_blocks.append(temp_time_block)

        return time_blocks

    @staticmethod
    def convert_time_block_to_time_ranges(time_block):
        """
        Convert time block, with all single cron numbers, into ranges of starting minute and ending minute
        Note: available number range: 0 - 10079 aka number of minutes in a week, inclusive

        @type time_block: [basestring, int]
        @param time_block: time block, with all single cron numbers, to convert

        @rtype: list of (int, int)
        @return: Expanded list of time ranges where ranges are inclusive
        """
        time_block_cron = time_block[0]
        time_block_duration = time_block[1]

        cron_values = time_block_cron.split(CRON_ELEMENT_SEPARATOR)
        starting_num = 0
        # compute starting point for range
        for i, cron_element in enumerate(cron_values):
            cron_element_type = CRON_ELEMENT_TYPES[i]
            cron_data = CRON_ELEMENT_TYPE_MAP.get(cron_element_type, {})
            # skip over unsupported values
            if cron_data.get('disabled', True):
                continue
            minutes = cron_data.get('minutes', 0)
            cron_number = ItsiTimeBlockUtils.parse_cron_number(cron_element, cron_element_type)
            starting_num += cron_number * minutes

        time_ranges = []
        # compute ending point for range
        ending_num = starting_num + time_block_duration - 1  # subtract 1 because numbers are inclusive
        max_minutes = 10079
        if ending_num > max_minutes:
            # time range overlaps end of week, so split range into 2
            overlap_minutes = ending_num - max_minutes - 1
            time_ranges.append((starting_num, max_minutes))
            time_ranges.append((0, overlap_minutes))
        else:
            time_ranges.append((starting_num, ending_num))

        return time_ranges

    @staticmethod
    def expand_time_block(time_block):
        """
        Convert time block into ranges of starting minute and ending minute

        @type time_block: [basestring, int]
        @param time_block: time block to expand

        @rtype: list of (int, int)
        @return: Expanded list of time ranges where ranges are inclusive
        """
        # validate duration (before cron because validating duration involves less work)
        ItsiTimeBlockUtils.validate_time_block_duration(time_block[1])

        time_ranges = []
        # validate and expand cron
        expanded_time_blocks = ItsiTimeBlockUtils.expand_time_block_cron(time_block)
        for expanded_time_block in expanded_time_blocks:
            # compute time range for expanded time block
            cron_time_ranges = ItsiTimeBlockUtils.convert_time_block_to_time_ranges(expanded_time_block)
            for cron_time_range in cron_time_ranges:
                time_ranges.append(cron_time_range)

        return time_ranges

    @staticmethod
    def check_time_block_conflict(time_blocks):
        """
        Determine if there's a time conflict/overlap between any of the time blocks provided

        @type time_blocks: list of [basestring, int]
        @param time_blocks: time blocks to go through to find conflict/overlap

        @rtype: boolean
        @return: True if a conflict exists, False otherwise
        """
        # validate no conflict amongst provided time blocks
        for i in range(0, len(time_blocks)):
            temp_time_blocks = []
            if i == 0:
                temp_time_blocks = time_blocks[i + 1:]
            elif i == len(time_blocks) - 1:
                temp_time_blocks = time_blocks[:i]
            else:
                temp_time_blocks = time_blocks[:i] + time_blocks[i + 1:]

            if ItsiTimeBlockUtils.check_time_block_conflict_between([time_blocks[i]], temp_time_blocks):  # conflict exists
                return True

        return False

    @staticmethod
    def check_time_block_conflict_between(input_time_blocks, time_blocks):
        """
        Determine if there's a time conflict/overlap between input_time_blocks and time_blocks

        @type input_time_blocks: list of [basestring, int]
        @param input_time_blocks: time blocks to test

        @type time_blocks: list of [basestring, int]
        @param time_blocks: the items in input_time_blocks will be tested against time_blocks

        @rtype: boolean
        @return: True if a conflict exists, False otherwise
        """
        # validate input time blocks
        input_time_block_ranges = []
        for input_time_block in input_time_blocks:
            input_time_block_range = ItsiTimeBlockUtils.expand_time_block(input_time_block)
            input_time_block_ranges += input_time_block_range
        # sort ranges to make looking for conflicts faster
        input_time_block_ranges.sort()

        # validate time blocks
        time_block_ranges = []
        for time_block in time_blocks:
            temp_time_block_ranges = ItsiTimeBlockUtils.expand_time_block(time_block)
            time_block_ranges += temp_time_block_ranges
        # sort ranges to make looking for conflicts faster
        time_block_ranges.sort()

        # at this point, we've converted the time blocks into lists of (<min_time>, <max_time>)
        # where the times are between 0 - 10079 aka number of minutes in a week, inclusive.
        # this means any overlaps between days and week overflows are already handled.
        # now, go through input_time_block_ranges to check for an overlap in time_block_ranges.
        # if we find start time or end time that falls within a time block range, that means we've found a conflict
        inner_iter = 0
        for input_time_block_range in input_time_block_ranges:
            input_time_block_start = input_time_block_range[0]
            input_time_block_end = input_time_block_range[1]
            if len(time_block_ranges) == inner_iter:
                break
            for i in range(inner_iter, len(time_block_ranges)):
                time_block_range = time_block_ranges[i]
                time_block_start = time_block_range[0]
                time_block_end = time_block_range[1]
                # check if start time or end time falls within time block range
                if (time_block_start <= input_time_block_start <= time_block_end) or (time_block_start <= input_time_block_end <= time_block_end):
                    return True
                # handle inner_iter bookkeeping
                if input_time_block_start > time_block_end:
                    inner_iter += 1

        return False

    @staticmethod
    def convert_hour_time_blocks(time_blocks):
        """
        Convert old schema (1hr-slices) of time blocks to new schema (cron-based)

        @type time_blocks: list of {time_block_key, policy_key}
        @param time_blocks: time blocks in old schema (1hr-slices)

        @rtype: dict
        @return: map of policy key to list of [basestring, int]
        """
        if not isinstance(time_blocks, list):
            logger.debug('Invalid type "%s" for time_blocks: %s. Expected list.', type(time_blocks), time_blocks)
            return {}

        if not len(time_blocks) == 168:  # there should be 24h * 7d = 168 time blocks
            logger.debug('Invalid number: %s of time_blocks: %s. Expected 168 time blocks.', len(time_blocks), time_blocks)
            return {}

        def _update_previous_entry(previous_entry, time_block_key, policy_key):
            """
            Updates previous_entry (in place) based on time_block_key and policy_key
            """
            split_time_block_key = time_block_key.split('-')
            previous_entry['policy_key'] = policy_key
            # create time block with duration 1h aka 60m
            previous_entry['time_block'] = [
                ' '.join([
                    '0',
                    str(int(split_time_block_key[1])),
                    '*',
                    '*',
                    str(int(split_time_block_key[0]))
                ]),
                60
            ]

        def _update_policy_time_block_map(policy_time_block_map, previous_entry):
            """
            Updates policy_time_block_map (in place) based on previous_entry

            policy_time_block_map is a dict with key: policy_id and value: dict of policy info
            policy_time_block_map = {'AM': policy_info_map, 'PM': policy_info_map, ...}

            policy_info_map is a dict with key: <minute>-<hour>-<duration_minutes> and value: set(<day>, <day>, ...)
            policy_info_map = {'0-12-60': set(0, 2, 4)}
            """
            previous_policy_key = previous_entry.get('policy_key')
            if not previous_policy_key == '':
                if previous_policy_key not in policy_time_block_map:
                    policy_time_block_map[previous_policy_key] = {}
                previous_map_entry = policy_time_block_map[previous_policy_key]

                # handle closing range for previous time block
                previous_time_block = previous_entry.get('time_block')
                split_previous_time_block_cron = previous_time_block[0].split(' ')
                # previous_map_entry: key is <minute>-<hour>-<duration_minutes> ie. 15-23-180 would mean 11:15PM - 2:15AM
                time_block_map_key = '-'.join([
                    '0',
                    str(int(split_previous_time_block_cron[CRON_ELEMENT_TYPES.index('hour')])),
                    str(previous_time_block[1])
                ])

                # previous_map_entry: value is set of day numbers ie. [0,2,4] would mean Mon, Wed, Fri
                if time_block_map_key not in previous_map_entry:
                    previous_map_entry[time_block_map_key] = set()
                previous_map_entry[time_block_map_key].add(
                    int(split_previous_time_block_cron[CRON_ELEMENT_TYPES.index('day_of_week')])
                )

        policy_time_block_map = {}  # dict of policy key to dict of time block info
        previous_entry = {  # keep track of previous time block to handle contiguous time blocks
            'policy_key': '',
            'time_block': ['', 0]
        }
        # sort time blocks based on time_block_key, ascending from 00-00 to 06-23
        sorted_time_blocks = sorted(time_blocks, key=lambda time_block: time_block.get('time_block_key'))

        # if a user-defined policy goes from Sun night to Mon morning, shift sorted_time_blocks to handle week overflow
        # ex. policy is associated with 06-22, 06-23, 00-00, it would be shifted so we would start at 06-22 and end at 06-21
        iter_ending_time_block_key = sorted_time_blocks[len(sorted_time_blocks) - 1].get('time_block_key')
        if sorted_time_blocks[0].get('policy_key') == sorted_time_blocks[len(sorted_time_blocks) - 1].get('policy_key'):
            overflow_policy_key = sorted_time_blocks[0].get('policy_key')
            # go backwards, starting at end of week, to find starting point of overflow policy time block
            time_block_shift_offset = 1
            iter_starting_index = len(sorted_time_blocks) - 2  # since we know 06-23 is associated with policy, start with 06-22
            iter_ending_index = 1 # since we know 00-00 is associated with the policy, end with 00-01
            for i in range(iter_starting_index, iter_ending_index, -1):
                if sorted_time_blocks[i].get('policy_key') == overflow_policy_key:
                    time_block_shift_offset += 1
                else:
                    break
            # Set limit to 6 days. Anything longer will likely be a 7 day policy
            if time_block_shift_offset < 144:
                # shift sorted_time_blocks by time_block_shift_offset
                sorted_time_blocks = sorted_time_blocks[-time_block_shift_offset:] + sorted_time_blocks[:-time_block_shift_offset]
                # update ending time block key
                iter_ending_time_block_key = sorted_time_blocks[len(sorted_time_blocks) - 1 - time_block_shift_offset]

        # first, go through old time blocks structure and populate policy_time_block_map with time blocks in new schema
        for time_block in sorted_time_blocks:
            policy_key = time_block.get('policy_key')
            time_block_key = time_block.get('time_block_key')
            if (not policy_key) or (not time_block_key):
                logger.debug('Invalid time block: %s. Expected object with keys: policy_key, time_block_key.', time_block)
                continue

            # handle contiguous time block
            if policy_key == previous_entry.get('policy_key'):
                # same time block continued, so update the duration by 1h aka 60m (if within 24h aka 1440m range)
                if previous_entry['time_block'][1] + 60 <= 1440:
                    previous_entry['time_block'][1] += 60
                else:
                    # continued time block duration exceeds 24h aka 1440m, so close previous time block and start next one
                    # close previous time block
                    _update_policy_time_block_map(policy_time_block_map, previous_entry)
                    # start next time block
                    _update_previous_entry(previous_entry, time_block_key, policy_key)

                # continue on to the next time block (unless it's the last time block)
                # last time block needs to be handled by the logic below in order to be closed
                if time_block_key != iter_ending_time_block_key:
                    continue

            # if we get here, it it means we need to close time block(s)
            previous_policy_key = previous_entry.get('policy_key')
            # special handling for first time block
            if previous_policy_key != '':
                # close previous time block
                _update_policy_time_block_map(policy_time_block_map, previous_entry)

            # special handling for last time block
            # if last time block is not part of the previous contiguous range, create a single entry for it
            if time_block_key == iter_ending_time_block_key and previous_policy_key != policy_key:
                # start next time block
                _update_previous_entry(previous_entry, time_block_key, policy_key)
                # close previous time block
                _update_policy_time_block_map(policy_time_block_map, previous_entry)
            else:
                # start next time block
                _update_previous_entry(previous_entry, time_block_key, policy_key)

        previous_time_block = previous_entry.get('time_block')
        if (int(previous_time_block[1]) != 60): # Handle scenario where function does not update time_block_map with previous entry
            _update_policy_time_block_map(policy_time_block_map, previous_entry)
        # now that the values in policy_time_block_map are in the new cron-based schema, collapse the time block entries
        # ie. ['0 0 * * 0', 120] and ['0 0 * * 4', 120] and ['0 0 * * 5', 120] should be collapsed into ['0 0 * * 0,4-5', 120]
        policies = {}
        for policy_key, time_block_map in policy_time_block_map.iteritems():
            if policy_key == DEFAULT_POLICY_KEY:  # skip over default policy since default policy time block values are inferred
                continue

            for time_block_key, time_block_days in time_block_map.iteritems():
                if policy_key not in policies:
                    policies[policy_key] = []

                # generate collapsed time block
                split_time_block_key = time_block_key.split('-')
                policies[policy_key].append([
                    ' '.join([
                        split_time_block_key[0],
                        split_time_block_key[1],
                        '*',
                        '*',
                        ItsiTimeBlockUtils.convert_numbers_to_cron_element(list(time_block_days))
                    ]),
                    int(split_time_block_key[2])
                ])

        # go through policies and ensure that none of them have more than 1 time block
        for policy_key, policy_time_blocks in policies.iteritems():
            num_time_blocks = len(policy_time_blocks)
            if num_time_blocks > 1:
                logger.debug('Invalid policy: %s with time blocks: %s. Expected 1 time block, found %s.', policy_key, policy_time_blocks, num_time_blocks)
                return {}

        return policies

    @staticmethod
    def get_cron_range(cron_element_type):
        """
        Get min and max time range values based on cron element type

        @type cron_element_type: basestring
        @param cron_element_type: available values found in CRON_ELEMENT_TYPE_MAP

        @rtype: 2 element list of <int>
        @return: Time range for cron element type
        """
        if cron_element_type not in CRON_ELEMENT_TYPE_MAP:
            error_msg = _('Invalid cron element type: {0}. Expected value in list: {1}.').format(cron_element_type, CRON_ELEMENT_TYPE_MAP.keys())
            logger.debug(error_msg)
            raise ValueError(error_msg)

        cron_range = CRON_ELEMENT_TYPE_MAP.get(cron_element_type, {}).get('range')
        if (not isinstance(cron_range, list)) or (len(cron_range) != 2) or (not isinstance(cron_range[0], int)) or (not isinstance(cron_range[1], int)):
            error_msg = _('Invalid range for cron element type: {0}. Expected [<int>, <int>], found: {1}.').format(cron_element_type, cron_range)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        return cron_range

    @staticmethod
    def parse_cron_number(cron_number, cron_element_type):
        """
        Ensure cron number can be parsed into an int and is within range

        @type cron_number: basestring
        @param cron_number: number to validate/parse

        @type cron_element_type: basestring
        @param cron_element_type: available values found in CRON_ELEMENT_TYPE_MAP

        @rtype: int
        @return: Parsed number if cron element is valid, raises exception otherwise
        """
        if not itoa_common.is_string_numeric_int(cron_number):
            error_msg = _('Invalid cron number: {0}. Expected int.').format(cron_number)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        parsed_cron_number = int(cron_number)
        cron_range = ItsiTimeBlockUtils.get_cron_range(cron_element_type)
        cron_range_start = cron_range[0]
        cron_range_end = cron_range[1]
        # ensure cron number is within range
        if not (cron_range_start <= parsed_cron_number <= cron_range_end):
            error_msg = _('Invalid cron number: {0}, for cron element type: {1}. Expected value in range: {2} - {3}.').format(parsed_cron_number, cron_element_type, cron_range_start, cron_range_end)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        return parsed_cron_number

    @staticmethod
    def expand_cron_element(cron_element, cron_element_type):
        """
        Ensure all values/ranges in cron element are valid and expand element into list of numbers

        @type cron_element: basestring
        @param cron_element: valid formats:
            '*'
            '<int>'
            '<int>,<int>,...'
            '<int>-<int>,...'
            '<int>,<int>-<int>,...'

        @type cron_element_type: basestring
        @param cron_element_type: available values found in CRON_ELEMENT_TYPE_MAP

        @rtype: list of <int>
        @return: Expanded list of cron numbers if cron element is valid, raises exception otherwise
        """
        if not isinstance(cron_element, basestring):
            error_msg = _('Invalid type "{0}" for cron element: {1}. Expected basestring.').format(type(cron_element), cron_element)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        if cron_element_type not in CRON_ELEMENT_TYPE_MAP:
            error_msg = _('Invalid cron element type: {0}. Expected value in list: {1}.').format(cron_element_type, CRON_ELEMENT_TYPE_MAP.keys())
            logger.debug(error_msg)
            raise ValueError(error_msg)

        cron_data = CRON_ELEMENT_TYPE_MAP.get(cron_element_type, {})
        # skip over unsupported values
        if cron_data.get('disabled', True):
            return []

        # ensure characters are valid
        if re.search('[^\d*,-]', cron_element):  # if we find any character that's not 0-9 or ',' or '-' or '*'
            error_msg = _('Invalid character in cron element: {0}. Expected int, "*", ",", or "-".').format(cron_element)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        # handle single number - any cron element type can be a single number
        if re.search('^[\d]+$', cron_element):  # if we find all characters to be 0-9
            cron_number = ItsiTimeBlockUtils.parse_cron_number(cron_element, cron_element_type)
            return [cron_number]

        # ensure multiple numbers are supported for cron element type
        if cron_element_type not in ['day_of_week']:
            error_msg = _('Invalid cron element: {0} for cron element type: {1}. Expected int.').format(cron_element, cron_element_type)
            logger.debug(error_msg)
            raise ValueError(error_msg)

        cron_range = cron_data.get('range')
        # handle range of numbers
        if cron_element == '*':  # handle * wildcard
            cron_range = ItsiTimeBlockUtils.get_cron_range(cron_element_type)
            return range(cron_range[0], cron_range[1] + 1)  # cron_range is inclusive, so add 1 to include max value in range

        # handle multiple numbers
        cron_numbers = set()
        split_cron_elements = cron_element.split(',')
        for split_cron_element in split_cron_elements:
            if split_cron_element:  # skip over empty string
                if re.search('-', split_cron_element):  # if we find the '-' character
                    # handle range of numbers
                    split_cron_range = split_cron_element.split('-')
                    if len(split_cron_range) != 2:
                        error_msg = _('Invalid cron element: {0}. Unable to parse range for: {1}.').format(cron_element, split_cron_element)
                        logger.debug(error_msg)
                        raise ValueError(error_msg)

                    parsed_cron_range_start = ItsiTimeBlockUtils.parse_cron_number(split_cron_range[0], cron_element_type)
                    parsed_cron_range_end = ItsiTimeBlockUtils.parse_cron_number(split_cron_range[1], cron_element_type)
                    cron_numbers.update(range(parsed_cron_range_start, parsed_cron_range_end + 1))  # cron_range is inclusive, so add 1 to include max value in range
                else:
                    # handle single number
                    parsed_cron_number = ItsiTimeBlockUtils.parse_cron_number(split_cron_element, cron_element_type)
                    cron_numbers.add(parsed_cron_number)

        return list(cron_numbers)

    @staticmethod
    def convert_numbers_to_cron_element(numbers):
        """
        Generate cron element representation of numbers

        @type numbers: list of <int>
        @param numbers: list of numbers to convert into cron element

        @rtype: basestring
        @return: cron element representation of numbers list
        """
        if not isinstance(numbers, list):
            error_msg = _('Invalid type "{0}" for cron element numbers: {1}. Expected list.').format(type(numbers), numbers)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        if len(numbers) == 0:
            error_msg = _('Invalid list of cron element numbers: {0}. Expected at least 1 number.').format(numbers)
            logger.debug(error_msg)
            raise TypeError(error_msg)

        # sort numbers so that computing range of numbers is easier
        numbers.sort()

        time_ranges = ''
        previous_range_counter = -100
        for i, number in enumerate(numbers):
            if (not isinstance(number, int)) or (not number >= 0):
                error_msg = _('Invalid cron element number: {0}. Expected positive int.').format(number)
                logger.debug(error_msg)
                raise TypeError(error_msg)

            if number == previous_range_counter + 1:  # contiguous time range
                if not time_ranges.endswith('-'):
                    time_ranges += '-'
                previous_range_counter = number
                if i < len(numbers) - 1:
                    continue

            # if we get here, it means the previous time range needs to be closed
            if time_ranges.endswith('-'):
                time_ranges += str(previous_range_counter)

            # add current number to time ranges
            if previous_range_counter != number:
                time_ranges += ',' + str(number)
            previous_range_counter = number

        return time_ranges.strip(',')
