from __future__ import print_function, division

import logging
import re
import csv
import sys
import copy
from chunked_util import read_chunk, write_chunk, add_message
import StringIO
from atad_utils import parse_input_data, clean_values, log_and_warn, log_and_die

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging
from itsi.itsi_time_block_utils import PolicyFilter

import kpi
import math

## Set this constant if you want to enable file-based KPI specification
## (useful for debugging without accessing the KV store).
## **** DO NOT SET THIS IN PRODUCTION (ITOA-3809) ****
# ENABLE_FILE_ARGUMENT = 1

##################
# itsiat
##################
# Command logs to $SPLUNK_HOME/var/log/splunk/itsi-atad.log

# contents of searchbnf.conf:
# [itsiat-command]
# syntax = itsiat (nokv) (file=<filename containing kpi json object>) (usetempcollection) (collection=<string: name of the collection>) (key=<string: object key>)
# description = Computes thresholds based on the input data and according to the schedules and policies specified in settings (in nokv mode) or found in the kv store (default). The data is partitioned according to which block of the schedule it corresponds to, then thresholds are computed for each block according to the rules in the associated policy. If any policies of any KPIs lack sufficient data to compute the thresholds as specified, the command will return no thresholds for that policy and will not update the corresponding thresholds. The _time field should be in UTC epoch time with the timezone specified in the KPI and that timezone should correspond with the timezone in which the time blocks are specified. No thresholds will be returned (or written to the KV store) for any KPIs for which an error was encountered; otherwise, the computed threhsolds will be output even if multiple thresholds have the same value. The command returns thresholds via stdout, and may additionally write them to the KV store if the appropriate arguments are passed. The empty string '' is an invalid value for all fields.
# shortdesc = Computes adaptive thresholds for the given data and kpi information (which it uses to acquire schedules and policies from the kv store).
# comment1 = An example using the command with the KV store (the 'table' command is optional):
# example1 = | table _time alert_value itsi_service_id itsi_kpi_id | itsiat
# comment2 = You can also pass a filename containing the kpi json directly to the command and receive the results as events (replace $SPLUNK_HOME with the correct path):
# example2 = | table _time alert_value itsi_service_id itsi_kpi_id | itsiat nokv file=$SPLUNK_HOME/etc/apps/SA-ITSI-ATAD/bin/test/SHKPI.json
# comment3 = You can use the command with a temporary collection in the KV store like this:
# example3 = | table _time alert_value itsi_service_id itsi_kpi_id | itsiat usetempcollection collection=temp_kpi_collection key=857d4397893137141fb6c427
# usage = public
# tags = kpi adaptive thresholding dynamic thresholds schedule blocks policy

# [itsiat-nokv-option]
# syntax = nokv
# description = When present, this flag makes the command use a file (specified in the settings argument) instead of the KV store to acquire the policies and schedules. The computed thresholds are returned as events.

# [itsiat-file-option]
# syntax = file=<filename containing KPI JSON object>
# description = In interactive mode (pass the "nokv" flag), the "file" parameter takes a filename containing the plaintext JSON of a KPI object. This has the Time Block and Threshold Policy data structures under the 'time_variate_thresholds_specification' key, which, in KV mode, the command retrieves from the KV store. If the nokv flag is not present, this argument is ignored.

# [itsiat-usetempcollection-option]
# syntax = usetempcollection
# description = When present, this flag makes the command use temporary collection in the KV store. The collection name and object key must both be provided. If the nokv flag is also present, the command throws an error.

# [itsiat-collection-option]
# syntax = collection=<string: temp collection name>
# description = The name of the temporary collection to use.

# [itsiat-key-option]
# syntax = key=<string: temp object key>
# description = The key to use for the object in the temporary collection.

# Windows will mangle our line-endings unless we do this.
if sys.platform == "win32":
    import os
    import msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

logger = setup_logging("itsi_atad.log", "itsi.at", level=logging.DEBUG)


def quantile(data, q):
    """Naive implementation of linear-interpolated quantile.

    Comparable to numpy.percentile()/pd.DataFrame.quantile().
    Author: Jacob Leverich (jleverich@splunk.com)
    """
    assert q >= 0. and q <= 1.
    m = float(len(data) - 1)
    i = m * q

    ilow = math.floor(i)
    ihigh = math.ceil(i)
    if ilow == ihigh:
        return data[int(ilow)]

    f = (i - ilow) / (ihigh - ilow)
    low = data[int(ilow)]
    high = data[int(ihigh)]
    return low + f * (high - low)


def quantiles(data, levels):
    data = sorted(data)
    out = {
        l: quantile(data, float(l))
        for l in levels
    }
    return out


# Policy Class
class Policy(object):

    def __init__(self, key, method, parameters, **kwargs):
        # validate methods and parameters
        if not isinstance(key, str):
            raise ValueError(
                "Null or non-string key sent to Policy constructor.")
        if not isinstance(method, str):
            raise ValueError(
                "Null or non-string method sent to Policy constructor. Must be a string: stdev, quantile, or range.")
        method_str = str(method)
        if method_str not in ['stdev', 'quantile', 'range']:
            raise ValueError(
                "Method must be one of stdev, quantile, or range.")
        if not parameters:  # parameters is a list of theshold levels
            raise ValueError("Null parameters sent to Policy constructor.")
        if not isinstance(parameters, list) or len(parameters) > 10:
            raise ValueError(
                "Parameters must be a list of no more than 10 levels.", parameters)
        if not all('dynamicParam' in x for x in parameters):
            raise ValueError("Every level record must have a dynamicParam attribute")

        # store policies in form amenable to computing thresholds
        self.key = key
        self.method = method_str
        self.parameters = parameters
        self.title = kwargs.get('title', key)

    @property
    def parameter_values(self):
        # property that extracts dynamic param values from parameter list
        return [float(x['dynamicParam']) for x in self.parameters]

    def get_updated_levels(self, computed_thresholds):
        """
        Returns a copy of the levels structure stored in self.parameters
        where thresholdValue field is updated from the computed levels array
        """
        if len(computed_thresholds) != len(self.parameters):
            raise ValueError("Computed thresholds and stored thresholds structures are not of the same length")
        result = []
        for computed_value, level in zip(computed_thresholds, self.parameters):
            level_copy = copy.copy(level)
            level_copy['thresholdValue'] = computed_value
            result.append(level_copy)
        logger.debug("Updated thresholdLevels for policy %s are %s", self.key, result)
        return result

    # values: a dict with ['alert_value'] = floats (possibly non-contiguous
    # and out-of-order) from all the blocks that have this policy.
    # returns a copy of threshold levels structure with thresholdValue field updated
    def get_thresholds(self, values):
        D = {'alert_value': [v for v in values if not math.isnan(v)]}

        if self.method is None:
            raise UnboundLocalError("No method set for Policy.")

        if len(D['alert_value']) < 30:
            logger.error("There are less than 30 data points in policy: %s" % self.key)
            return None

        if self.method == 'stdev':  # pretty standard, really
            # Simple two-pass algorithm for calculating stdev. Reasonably numerically stable.
            mean = sum(D['alert_value']) / len(D['alert_value'])
            sqe = sum((x - mean) ** 2. for x in D['alert_value'])
            std = math.sqrt(sqe / (len(D['alert_value']) - 1))
            return self.get_updated_levels([mean + (std * c) for c in self.parameter_values])
        # formerly iqr and same as "mass" in prior iterations
        elif self.method == 'quantile':
            T = quantiles(D['alert_value'], self.parameter_values)
            return self.get_updated_levels([T[k] for k in self.parameter_values])
        elif self.method == 'range':  # equal width bands
            # NOTE: sensitive to outliers in training data (remove first)
            dmax = max(D['alert_value'])
            dmin = min(D['alert_value'])
            span = dmax - dmin
            return self.get_updated_levels([dmin + (span * c) for c in self.parameter_values])
        else:
            ValueError("Invalid thresholding method: " + self.method)


# Schedule Class
class Schedule(object):
    # policies: dict of Policy Objects keyed by policy.key
    # schedule: dict of policy_keys keyed by block_keys

    def __init__(self, kpi_object, policies, threshold_spec):
        # validate kpi
        if kpi_object is None:
            raise ValueError("Null KPI object sent to Schedule constructor.")
        if not isinstance(kpi_object, kpi.KPIBase):
            raise ValueError("KPI parameter must be a kpi.KPI object", kpi)
        # validate policies
        if policies is None:
            raise ValueError("Null policy dict sent to Schedule constructor.")
        if not isinstance(policies, dict):
            raise ValueError(
                "Policies parameter must be a dict, got %s." % type(policies))
        if len(policies) > 169 or len(policies) == 0:
            raise ValueError(
                "Policies parameter must be a dict of no more than 168 Policy objects, got %s." % len(policies))
        if sum([1 if not isinstance(p, Policy) else 0 for p in policies.values()]) > 0:
            raise ValueError("All policies must be Policy objects.")

        self.kpi_object = kpi_object
        self.policies = policies
        self.filter = PolicyFilter(threshold_spec)

    def _get_thresholds(self, data, params):
        if data is None:
            raise ValueError("Null data sent to Schedule.")
        if not isinstance(data, dict) or 'alert_value' not in data:
            raise ValueError(
                "Data passed to Schedule must be a dict with values in column 'alert_value'.")

        # divide data based on policy: D[policy_key] = [floats]
        D = {}
        for policy_key in self.policies:
            D[policy_key] = []
        index_converted = data['_time']
        active_policies = set()
        for data_index in xrange(len(index_converted)):
            # provide a timestamp and TZ, get the policy that includes this timestamp
            policy_key = self.filter.get_policy_key(time=index_converted[data_index])
            if policy_key in D:
                D[policy_key].append(data['alert_value'][data_index])
                active_policies.add(policy_key)

        # compute and accumulate the thresholds for each Policy
        T = {}
        insufficient_data_policies = []
        for policy_key in self.policies:
            the_data = D[policy_key]
            T[policy_key] = self.policies[policy_key].get_thresholds(the_data)
            if T[policy_key] is None and policy_key in active_policies:
                insufficient_data_policies.append(self.policies[policy_key].title)
                logger.info(
                    "Insufficient data for threshold calculation: %d values." % len(D[policy_key]))

        if len(insufficient_data_policies) > 0:
            add_message(params['out_metadata'], 'WARN',
                        'insufficient data in ITSI summary index for policies %s' % str(insufficient_data_policies))
        return T

    def get_thresholds(self, data, params):
        """Computes thresholds for a KPI and this schedule.

        @param data: dict with 'alert_value': list of floats
                               '_time': list of float epoch timestamps

        Returns a dict of lists of threshold level structures, keyed by policy.key;
        the structures should have a populated `thresholdValue` field obtained from the result of the computation
        """
        metadata = params['out_metadata']
        thresholds = {}
        kpi_info = 'kpiid="%s" on serviceid="%s"' % (str(params['kpi']['service_id']), str(params['kpi']['kpi_id']))
        try:
            thresholds = self._get_thresholds(data=data, params=params)
        except ValueError as e:
            params['logger'].exception(e)
            log_and_warn(metadata=metadata, logger=params['logger'],
                         msg='Unconvertible alert_values found for ' + kpi_info,
                         search_msg="unconvertible values found (check this KPI's `alert_value` field in ITSI summary index")
        except AssertionError as e:
            # Method should probably raise a ValueError/try to convert 0-100 to 0.0-1.0, but for now log nicely
            params['logger'].exception(e)
            log_and_warn(metadata=metadata, logger=params['logger'],
                         msg='Invalid quantile specified for %s, must be between 0.0 and 1.0' % kpi_info,
                         search_msg='invalid quantile value, must be between 0.0 and 1.0')
        except Exception as e:
            params['logger'].exception(e)
            log_and_warn(metadata=metadata, logger=params['logger'],
                         msg='Unexpected exception when computing thresholds for %s' % kpi_info)

        return thresholds


def parse_args(args, in_metadata, out_metadata, logger):
    params = {}
    params['use_kv_store'] = True
    params['use_temp_collection'] = False

    if 'nokv' in args:
        params['use_kv_store'] = False
    if 'usetempcollection' in args:
        params['use_temp_collection'] = True

        r = re.search('\s*collection\s*=\s*(?P<coll>\S+)\'', str(args))
        if r is not None:
            try:
                params['temp_collection'] = r.group('coll')
                logger.debug("Temporary collection name: %s" %
                             str(params['temp_collection']))
            except:
                log_and_die(metadata=out_metadata, logger=logger,
                            msg='Failed to parse temporary collection name in parameters.')
        else:
            log_and_die(metadata=out_metadata, logger=logger,
                        msg='Must provide a temporary collection name.')

        r = re.search('\s*key\s*=\s*(?P<key>\S+)\'', str(args))
        if r is not None:
            try:
                params['temp_key'] = r.group('key')
                logger.debug("Temporary object key: %s" %
                             str(params['temp_key']))
            except:
                log_and_die(metadata=out_metadata, logger=logger,
                            msg='Failed to parse temporary object key in parameters.')
        else:
            log_and_die(metadata=out_metadata, logger=logger,
                        msg='Must provide a temporary object key.')

    params['session_key'] = str(in_metadata['searchinfo']['session_key'])

    if globals().get('ENABLE_FILE_ARGUMENT', False):
        r = re.search('\s*file\s*=\s*(?P<fname>\S+)\'', str(args))
    else:
        r = None

    if r is not None and not params['use_kv_store']:
        try:
            params['settings_file'] = r.group('fname')
            logger.debug("Settings file: %s" % str(params['settings_file']))
        except:
            log_and_die(
                metadata=out_metadata, logger=logger, msg='Failed to parse settings file in parameters.')
    elif not params['use_kv_store']:
        log_and_die(
            metadata=out_metadata, logger=logger, msg='No settings file specified.')

    if not params['use_kv_store'] and params['use_temp_collection']:
        log_and_die(
            metadata=out_metadata, logger=logger, msg="Incompatible arguments passed: nokv and usetempcollection.")

    return params


def create_schedule(params):
    policies = {}
    metadata = params['out_metadata']
    settings = params['kpi']['settings']

    # get policy settings for this KPI, create Policy objects
    for policy_key in settings['policies']:
        t_method = str(
            settings['policies'][policy_key]['policy_type'])
        t_title = str(settings['policies'][policy_key].get('title', policy_key))
        try:
            t_levels = settings['policies'][policy_key]['aggregate_thresholds']['thresholdLevels']
        except KeyError as e:
            # we just skip this policy
            logger.exception(e)
            log_and_die(metadata=metadata, logger=params[
                'logger'], msg="Failed to retrieve aggregate levels: %s" % e)

        policy_key = str(policy_key)
        if t_method == 'static':
            logger.info("Skipping static policy '%s'", policy_key)
        elif not isinstance(t_levels, list) or not t_levels:
            log_and_die(metadata=metadata, logger=params['logger'],
                        msg="Unable to apply adaptive thresholding on policy '%s': please specify threshold values for the policy" % t_title)
        else:
            for x in t_levels:
                if 'dynamicParam' not in x:
                    log_and_die(metadata=metadata, logger=params['logger'], msg="Unable to apply adaptive thresholding on policy '%s': Missing threshold value." % t_title)
                try:
                    float(x['dynamicParam'])
                except (TypeError, ValueError):
                    log_and_die(metadata=metadata, logger=params['logger'],
                                msg="Unable to apply adaptive thresholding on policy '%s': Invalid threshold value: %s" % (t_title, x['dynamicParam']))

            logger.debug("Loading settings for policy %s: method=%s levels=%s" % (
                policy_key, t_method, t_levels))
            try:
                policies[policy_key] = Policy(
                    key=policy_key, method=t_method, parameters=t_levels, title=t_title)
            except ValueError as e:
                logger.exception(e)
                log_and_die(metadata=metadata, logger=params[
                    'logger'], msg="Invalid arguments sent to Policy.")

    the_schedule = None
    if len(policies) == 0:
        return
    try:
        the_schedule = Schedule(
            kpi_object=params['kpi']['kpi_object'], policies=policies, threshold_spec=settings)
    except ValueError as e:
        logger.exception(e)
        log_and_die(metadata=metadata, logger=params[
                    'logger'], msg="Invalid arguments sent to Schedule.")

    return the_schedule


def get_kpi_object(params):
    kpi_object = None
    metadata = params['out_metadata']

    if params['use_kv_store']:
        if params['use_temp_collection'] and params['temp_collection'] is not None and params['temp_key'] is not None:
            kpi_object = kpi.TempKPI(logger=params['logger'],
                                     temp_collection_name=params['temp_collection'], temp_object_key=params['temp_key'])
        else:
            kpi_object = kpi.ServiceKPI(
                logger=logger, service_id=params['kpi']['service_id'], kpi_id=params['kpi']['kpi_id'])
        kpi_object.initialize_interface(
            params['session_key'], owner='nobody', namespace='SA-ITOA')
        kpi_object.fetch_kpi()
        logger.debug(
            "Initialized KV interface with session key %s" % params['session_key'])
    elif params['settings_file'] is not None:
        kpi_object = kpi.FileBackedKPI(
            logger=logger, filename=params['settings_file'])

    return kpi_object


def output_results(thresholds, params):
    """
    thresholds: dict of lists of threshold levels structures, keyed by policy id
    """
    settings = params['kpi']['settings']
    service_id = params['kpi']['service_id']
    kpi_id = params['kpi']['kpi_id']

    for policy_id in thresholds:
        t = thresholds[policy_id]
        if t is not None:
            if params['use_kv_store']:
                if len(t) != len(settings['policies'][policy_id]['aggregate_thresholds']['thresholdLevels']):
                    kpistr = ""
                    if service_id is not None and kpi_id is not None and service_id != "" and kpi_id != "":
                        kpistr = " for kpi %s" % str(service_id) + ":" + str(kpi_id)
                    log_and_warn(metadata=params['out_metadata'], logger=params['logger'], msg="Mismatched number of thresholdLevels%s. Generated %d but found %d." % (
                        kpistr, len(t), len(settings['policies'][policy_id]['aggregate_thresholds']['thresholdLevels'])))
                else:
                    # n.b. we assume thresholdLevels objects are
                    # sorted by increasing thresholdValue
                    params['kpi']['kpi_object'].update_thresholds(
                        policy=policy_id, thresholds=t)

            line = {
                'policy_id': policy_id, 'itsi_service_id': service_id, 'itsi_kpi_id': kpi_id}
            for thresh_index in range(len(t)):
                line['threshold_' + str(thresh_index)] = t[thresh_index].get('thresholdValue')
                line['threshold_metadata_' + str(thresh_index)] = t[thresh_index]
            params['kpi']['writer'].writerow(line)


def main():
    logger.debug(
        "\n=========\nStarting ITSI adaptive thresholding.\n=========")

    out_metadata = {}
    out_metadata['inspector'] = {'messages': []}

    # Phase 0: getinfo exchange
    metadata, body = read_chunk(sys.stdin, logger)
    # Don't run in preview.
    if metadata.get('preview', False):
        write_chunk(sys.stdout, {'finished': True}, '')
        sys.exit(0)

    args = str(metadata['searchinfo']['args'])

    params = parse_args(
        args=args, in_metadata=metadata, out_metadata=out_metadata, logger=logger)
    params['logger'] = logger
    params['out_metadata'] = out_metadata

    params['out_metadata']['finished'] = False
    fields_list = ['_time', 'itsi_service_id', 'itsi_kpi_id', 'alert_value']
    params['out_metadata']['required_fields'] = fields_list
    params['out_metadata']['type'] = 'reporting'
    write_chunk(sys.stdout, params['out_metadata'], '')
    params['out_metadata'].pop('type', None)
    params['out_metadata'].pop('required_fields', None)

    # Phase 1: gather the input data
    kpidict = dict()  # kpidict['itsi_service_id']['itsi_kpi_id']
    while True:
        params['out_metadata']['finished'] = False

        ret = read_chunk(sys.stdin, logger)
        if not ret:
            break
        metadata, body = ret

        parse_input_data(
            the_dict=kpidict, data=body, fields_list=fields_list, params=params)

        write_chunk(sys.stdout, params['out_metadata'], '')
        if metadata.get('finished', False):
            break

    def _ignore_invalid_row(warn_message):
        """
        Method to log warning and ignore read row result
        Assumes read_chunk was invoked before this method is invoked

        @type: basestring
        @param warn_message: warning message to log

        @rtype: None
        @return: None
        """
        logger.warn(warn_message)
        # Dummy response to ignore
        write_chunk(sys.stdout, {"finished": False}, '')

    # Phase 2: iterate over (serviceid, kpiid) and output scores
    for itsi_service_id in kpidict:
        for itsi_kpi_id in kpidict[itsi_service_id]:
            params['kpi'] = {}
            params['kpi']['service_id'] = itsi_service_id
            params['kpi']['kpi_id'] = itsi_kpi_id

            logger.info("Computing thresholds for %s:%s" %
                        (itsi_service_id, itsi_kpi_id))

            if not read_chunk(sys.stdin, logger):
                break

            # get the KPI object
            params['kpi']['kpi_object'] = get_kpi_object(params)
            if params['kpi']['kpi_object'] is None:
                _ignore_invalid_row('No KPI found with id %s, ignoring ...' % itsi_kpi_id)
                continue

            # get the settings
            kpi_tmp = params['kpi']['kpi_object'].get_kpi()

            if not isinstance(kpi_tmp, dict):
                _ignore_invalid_row('No valid KPI found with id %s, ignoring ...' % itsi_kpi_id)
                continue

            if 'time_variate_thresholds_specification' not in kpi_tmp:
                _ignore_invalid_row(
                    'No valid thresholds specification found for KPI with id %s, ignoring ...' % itsi_kpi_id
                )
                continue

            params['kpi']['settings'] = kpi_tmp[
                'time_variate_thresholds_specification']

            if params['kpi']['settings'] is not None:
                # create the schedule
                the_schedule = create_schedule(params=params)

                # prepare the data
                values = clean_values(
                    data=kpidict[itsi_service_id][itsi_kpi_id],
                    params=params
                )

                # compute the thresholds
                if the_schedule is not None:
                    thresholds = the_schedule.get_thresholds(
                        data=values, params=params)
                else:
                    thresholds = {}

                # prepare for generating output
                params['out_metadata']['finished'] = False
                outbuf = StringIO.StringIO()
                fields_list = ['policy_id']
                for k in range(10):
                    fields_list.append("threshold_" + str(k))
                    fields_list.append("threshold_metadata_" + str(k))
                fields_list = fields_list + ['itsi_service_id', 'itsi_kpi_id']
                params['kpi']['writer'] = csv.DictWriter(
                    outbuf, fieldnames=fields_list, dialect='excel', extrasaction='ignore')
                params['kpi']['writer'].writeheader()

                # write output to buffer
                output_results(thresholds=thresholds, params=params)

                # output the results
                write_chunk(
                    sys.stdout, params['out_metadata'], outbuf.getvalue())
            else:
                _ignore_invalid_row(
                    'No valid thresholds specification found for KPI with id %s, ignoring ...' % itsi_kpi_id
                )
                continue

    # we're done, so send dummy response to finish the session
    ret = read_chunk(sys.stdin, logger)
    if ret:
        write_chunk(sys.stdout, {"finished": True}, '')

    logger.debug(
        "\n=========\nFinished ITSI adaptive thresholding.\n=========")

if __name__ == "__main__":
    main()
