from __future__ import print_function, division

import sys
import re
import csv
import math
import logging
import logging.handlers
from chunked_util import read_chunk, write_chunk
import StringIO
from atad_utils import parse_input_data, clean_values, log_and_warn, log_and_die, get_indices_of_big_gaps

import splunk
from splunk import entity

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.setup_logging import setup_logging

import holtwinters as hw
from holtwinters_online import hw_linear_online
import tdigest
from tdigest_model import TDigestModel, get_digest_from_kv_store, put_digest_in_kv_store

##################
# itsiad
##################
# [itsiad-command]
# syntax = itsiad (usekv) (fillna) (gofast) (online) (trainingdays=<number>)
# description = Computes an anomaly score (measure of surprise) for the alert_values after the training window or after the last scored time (for usekv mode). Anomaly scores range from 0 (unsurprising) to 1 (most surprising). The taint value indicates how many values in the training window were fabricated in accordance with the fillna flag. The gofast flag removes parameter optimization in favor of hard-coded values which makes the command go significantly faster. The online flag means to use an alternative method to optimize the parameters. Must include _time, alert_value, and alert_period. For usekv mode, must also specify itsi_service_id and itsi_kpi_id. In interactive mode, note that the first 100 non-null alert_values after the training window will not be scored because those errors are needed to bootstrap the error digest. This number may be larger if missing values are in the training window and fillna is not specified, or if the prediction errors generated do not give the command sufficient information to generate scores (e.g., if all prediction errors are the same). If no score can be generated for a particular alert_value after the training window, we return anomaly_score=-1. Note that, after resampling, the exact _time and alert_values output by the command may differ from those in the input; any drilldown behavior should look for time windows rather than specific values from the input. The empty string '' is an invalid value for all fields.
# shortdesc = Computes an anomaly score (measure of surprise) for the alert_values.
# comment1 = An example using interactive mode with a 5-day training window (the 'table' command is optional):
# example1 = | table _time alert_value alert_period itsi_service_id itsi_kpi_id | itsiad trainingdays=5 | table _time alert_value anomaly_score tainted itsi_service_id itsi_kpi_id
# comment2 = An example using KV mode with missing values filled in:
# example2 = | table _time alert_value alert_period itsi_service_id itsi_kpi_id | itsiad usekv fillna trainingdays=5 | table _time alert_value anomaly_score tainted itsi_service_id itsi_kpi_id
# usage = public
# tags = kpi anomaly detection anomalies

# [itsiad-usekv-option]
# syntax = usekv
# description = When present, this flag makes the command use the KV store to acquire and store the last scored time and error digest.

# [itsiad-fillna-option]
# syntax = fillna
# description = When present, this flag makes the command fill in missing values in the data using simple forward and backward filling. The taint field in the output indicates the number of values fabricated in this manner.

# [itsiad-gofast-option]
# syntax = gofast
# description = When present, this flag makes the command go much faster by turning off parameter optimization.

# [itsiad-trainingdays-option]
# syntax = trainingdays=<number>
# description = The integer number of days of KPI data to use for training.

# Windows will mangle our line-endings unless we do this.
if sys.platform == "win32":
    import os
    import msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)

logger = setup_logging("itsi_atad.log", "itsi.ad", level=logging.DEBUG)


def find_next_index(data, params):
    logger = params['logger']
    kpi_params = params['kpi']
    metadata = params['out_metadata']
    last_scored_time = kpi_params['last_scored_time']
    training_samples_plus_one = kpi_params['training_samples_plus_one']
    params['nothing_to_do'] = False
    nextindextoscore = None

    # start scoring only after the lastscoredtime
    if last_scored_time:
        logger.debug("Found last scored time in KV store: %s", str(last_scored_time))

        # scan data for dt after last_scored_time
        for i, t in enumerate(data['dt']):
            if t > last_scored_time:
                nextindextoscore = i
                break
        if nextindextoscore is None:
            nextindextoscore = len(data['dt'])

        if training_samples_plus_one > nextindextoscore:
            log_and_warn(metadata, logger,
                         "Next time to score is inside the training window. Skipping ahead to end of training window.")
            nextindextoscore = training_samples_plus_one

        logger.debug("Computed nextindextoscore: %s", nextindextoscore)
        logger.debug("Comparing with len(data.index): %s", len(data['alert_value']))
        if (nextindextoscore + 1 > len(data['alert_value'])):
            log_and_warn(
                metadata, logger, "No new data to score.")
            params['nothing_to_do'] = True

    # we didn't find a lastscoredtime in the KV store (or are in
    # interactive mode)
    else:
        logger.debug("didn't find a lastscoredtime in the KV store")
        nextindextoscore = training_samples_plus_one
        if (nextindextoscore < len(data['alert_value'])):
            logger.debug("Next index to score = %d", nextindextoscore)
        else:
            log_and_warn(metadata, logger, "No new data to score.")
            params['nothing_to_do'] = True

    if nextindextoscore is not None:
        params['kpi']['next_index_to_score'] = nextindextoscore
    else:
        log_and_die(metadata, logger, "Unable to compute next index to score.")


def ffill(d):
    last = None
    for i, v in enumerate(d):
        if math.isnan(v) and last is not None:
            d[i] = last
        else:
            last = v
    return d


def bfill(d):
    last = None
    for i, v in reversed(list(enumerate(d))):
        if math.isnan(v) and last is not None:
            d[i] = last
        else:
            last = v
    return d


def run_ad(data, params):
    kpi_params = params['kpi']
    nextindex = kpi_params['next_index_to_score']
    training_samples_plus_one = kpi_params['training_samples_plus_one']
    metadata = params['out_metadata']

    params['kpi']['new_last_scored_time'] = None  # reset
    D = data['alert_value']
    index_converted = data['dt']

    try:
        conf = entity.getEntity('configs/conf-itsi_atad', 'itsiad', namespace='SA-ITSI-ATAD', owner='nobody')
        TAINT_MAX = float(conf['TAINT_MAX'])
        BIG_GAP = int(conf['BIG_GAP'])
    except ValueError as e:
        logger.exception(e)
        log_and_die(metadata, logger,
                    'Error parsing itsiad conf file.')

    # do the work
    taint_map = [1 if math.isnan(v) else 0 for v in D]
    if params['fill_nans']:
        big_gap_indices = get_indices_of_big_gaps(binary_list=taint_map, min_run=BIG_GAP)
        # fill big gaps with the average value
        if len(big_gap_indices) > 0:
            numbers = [v for v in D if not math.isnan(v)]
            if len(numbers) > 0:
                avg_val = float(sum(numbers)) / len(numbers)
                for i_tuple in big_gap_indices:
                    D[i_tuple[0]: i_tuple[1]] = [avg_val] * (i_tuple[1] - i_tuple[1] + 1)
        # fill remaining small gaps with the adjacent values
        D = bfill(ffill(list(D)))
    # check if there's any data to score
    if params['nothing_to_do'] and params['use_kv_store']:
        logger.warn("Nothing to do for KPI %s.", kpi_params['kpi_id'])
    elif params['nothing_to_do'] and not params['use_kv_store']:
        logger.error(
            "Insufficient or invalid data for KPI %s. Unable to generate anomaly scores.",
            kpi_params['kpi_id'])
    else:
        # finally, scoring time!
        logger.debug("Running scoring")
        logger.debug("Nextindex: %s, training_samples_plus_one: %s", nextindex, training_samples_plus_one)
        logger.debug("Range: (%s, %s)",
                     nextindex - training_samples_plus_one + 1, len(D) - training_samples_plus_one + 1)
        for i in range(nextindex - training_samples_plus_one + 1, len(D) - training_samples_plus_one + 1):
            # if we cannot generate a score, we return -1
            s = -1
            # training values from the possibly-made-up dataframe
            X = D[i:i + training_samples_plus_one]
            # need this for updating the last scored time
            Z = index_converted[i:i + training_samples_plus_one]

            taint_count = sum(
                taint_map[i:i + training_samples_plus_one])
            can_score = True
            if taint_count > 0 and not params['fill_nans']:
                # skip over training window
                logger.debug(
                    "Skipping this training window; %d missing values found.", taint_count)
                can_score = False
            elif (float(taint_count) / training_samples_plus_one) >= TAINT_MAX:
                # skip over training window
                logger.debug(
                    "Skipping this training window; %f percent of values missing.", ((float(taint_count) * 100) / training_samples_plus_one))
                can_score = False

            # grab next value from non-made-up dataframe
            next_value = data['alert_value'][
                i + training_samples_plus_one - 1]

            # if next_value is nan, can't do prediction / error
            if math.isnan(next_value):
                logger.debug(
                    "Not generating score for NaN value at %d of KPI %s", i, kpi_params['kpi_id'])
            elif not can_score:
                logger.debug(
                    "Taint exceeds acceptable limits at %d of KPI %s", i, kpi_params['kpi_id'])
            else:
                # run h-w
                if params['go_fast']:
                    prediction = hw.linear(
                        X[:-1], 1, alpha=0.5, beta=0.5)[0][0]
                elif params['online']:
                    x_hat, alpha, beta = hw_linear_online(X[:-1])
                    logger.debug("Online parameter estimates: alpha=%f, beta=%f", alpha, beta)
                    prediction = x_hat[-1]
                else:
                    prediction = hw.linear(X[:-1], 1)[0][0]

                # compute absolute error = abs(x' - x)
                err = abs(prediction - next_value)

                # add error to tdigest
                if not math.isnan(err):
                    params['kpi']['error_digest'].update(err)

                # if sufficient recorded errors, check error quantile
                if len(params['kpi']['error_digest']) > 100:
                    if not math.isnan(err):
                        s = params['kpi']['error_digest'].quantile(err)
                    else:
                        logger.error(
                            "Error value should not be NaN. Index = %d" % i)

            # return as a written chunk in proper format
            line = {'_time': Z[-1], 'itsi_service_id': kpi_params['service_id'], 'itsi_kpi_id': kpi_params['kpi_id'],
                    'alert_value': next_value, 'taint': taint_count, 'anomaly_score': s}

            params['kpi']['new_last_scored_time'] = Z[-1]
            params['kpi']['writer'].writerow(line)


def parse_args(args, in_metadata, out_metadata):
    params = {}
    params['use_kv_store'] = False
    params['fill_nans'] = False
    params['go_fast'] = False
    params['online'] = False
    params['training_days'] = None

    if 'usekv' in args:
        params['use_kv_store'] = True
    if 'fillna' in args:
        params['fill_nans'] = True
    if 'gofast' in args:
        params['go_fast'] = True
    if 'online' in args:
        params['online'] = True

    r = re.search('\S*trainingdays.*=\D*(?P<last>\d+)\D*', str(args))
    if r is not None:
        try:
            params['trainingdays'] = int(r.group('last'))
        except ValueError:
            log_and_warn(out_metadata, logger, 'Number of training days must be a number; received' +
                         r.group('last') + ' Defaulting to 7.')
            params['trainingdays'] = 7

        if params['trainingdays'] < 1 or params['trainingdays'] > 30:
            log_and_warn(out_metadata, logger, 'Invalid number of training days specified: ' + str(
                params['trainingdays']) + ' (Must be between 1 and 30, inclusive. Defaulting to 7).')
            params['trainingdays'] = 7
    else:
        log_and_warn(
            out_metadata, logger, 'Number of training days not specified in args. Defaulting to 7.')
        params['trainingdays'] = 7

    session_key = str(in_metadata['searchinfo']['session_key'])
    params['interface'] = None
    if params['use_kv_store']:
        params['interface'] = TDigestModel.initialize_interface(
            session_key, owner='nobody', namespace='SA-ITSI-ATAD')
        logger.debug(
            "Initialized KV interface with session key %s" % session_key)

    logger.debug("Args passed: %s" % str(args))

    return params


def sort_lists(data, index):
    keys = data.keys()
    sort_index = keys.index(index)
    zipped = zip(*data.values())
    _sorted = sorted(zipped, key=lambda x: x[sort_index])
    unzipped = zip(*_sorted)
    out = {
        k: unzipped[i]
        for i, k in enumerate(keys)
    }
    return out


def resample(data, mperiod=1.):
    """Naive emulation of pandas resample.

    Resamples data to "mperiod"-minutely intervals by calculating the
    mean of all points that fall within a period.

    @param data: dict of '_time': list of floats
                         'alert_value': list of floats
                         'alert_period': list of floats
                 This is a column-oriented representation of data.
                 All lists must have the same length and are assumed to
                 be aligned with _time.
    @param mperiod: sampling interval, in minutes
    @return dict of '_time', 'dt', 'alert_value', 'alert_period',
        resampled from data to be a synchronous time-series.
        'dt' is a list of starting timestamps for each interval
        '_time', 'alert_value', and 'alert_period' are the means of every
        value from the input data that fell into that interval.
    """
    period = int(mperiod * 60)
    start = int(math.floor(data['_time'][0] / period) * period)
    end = int(math.floor(data['_time'][-1] / period) * period)

    # Number of output intervals, inclusive of start and end
    n = int((end - start) / period + 1)

    out = {k: [0] * n for k in ['dt', '_time', 'alert_value', 'alert_period', 'count']}

    # Output the interval anchors
    for i in range(n):
        t = i * period + start
        out['dt'][i] = float(t)

    # Accumulate sums
    for i in range(len(data['_time'])):
        o = int(math.floor(data['_time'][i] / period)) - int(start / period)
        if data['alert_value'][i] is not None:
            out['_time'][o] += data['_time'][i]
            out['alert_period'][o] += data['alert_period'][i]
            out['alert_value'][o] += data['alert_value'][i]
            out['count'][o] += 1

    # Compute means
    for o in range(n):
        if out['count'][o] != 0:
            out['_time'][o] /= out['count'][o]
            out['alert_period'][o] /= out['count'][o]
            out['alert_value'][o] /= out['count'][o]
        else:
            out['alert_value'][o] = float('nan')
            out['alert_period'][o] = float('nan')
            out['_time'][o] = float('nan')

    del out['count']
    return out


def data_to_ts(data, params):
    logger = params['logger']
    metadata = params['out_metadata']

    # sort the data
    last = None
    for v in data['_time']:
        if last is None:
            last = v
            continue
        if v < last:
            logger.warn("Index not sorted, %f >= %f, sorting" % (last, v))
            data = sort_lists(data, '_time')
            break
        last = v

    # make into a regularly spaced timeseries
    logger.debug("Last _time = %s, alert_period = %sT",
                 str(data['_time'][-1]), str(data['alert_period'][0]))

    try:
        data = resample(data, data['alert_period'][0])
    except Exception as e:
        logger.exception(e)
        log_and_die(metadata, logger,
                    'Unable to resample. Check alert_value and alert_period fields.')

    # number of samples in a training window
    try:
        period = data['alert_period'][0]
        oneday = int(1440 / period)
        params['kpi']['training_samples_plus_one'] = int(oneday * int(params['trainingdays'])) + 1
        logger.debug("training_samples_plus_one: %d" % params['kpi']['training_samples_plus_one'])
    except Exception as e:
        log_and_die(metadata, logger,
                    'Unable to compute training_samples_plus_one: %s' % str(e))

    return data


def get_error_digest(params):
    params['kpi']['error_digest'] = None
    service_id = params['kpi']['service_id']
    kpi_id = params['kpi']['kpi_id']
    params['kpi']['last_scored_time'] = None

    if params['use_kv_store'] and service_id and kpi_id:
        params['kpi']['error_digest'], params['kpi'][
            'last_scored_time'] = get_digest_from_kv_store(params)

    # initialize history if empty
    if params['kpi']['error_digest'] is None:
        logger.debug('No digest found, creating a new one.')
        params['kpi']['error_digest'] = tdigest.TDigest()


def main():
    logger.debug("\n=========\nStarting ITSI anomaly detection.\n=========")

    out_metadata = {}
    out_metadata['inspector'] = {'messages': []}

    # Phase 0: getinfo exchange
    metadata, body = read_chunk(sys.stdin, logger)
    # Don't run in preview.
    if metadata.get('preview', False):
        write_chunk(sys.stdout, {'finished': True}, '')
        sys.exit(0)

    # setting default for grabbing conf later
    splunk.setDefault('sessionKey', metadata['searchinfo']['session_key'])

    args = str(metadata['searchinfo']['args'])

    params = parse_args(
        args=args, in_metadata=metadata, out_metadata=out_metadata)
    params['logger'] = logger
    params['out_metadata'] = out_metadata

    params['out_metadata']['finished'] = False
    # note that 'itsi_service_id' and 'itsi_kpi_id' are not required;
    # in their absence default values will be used
    fields_list = ['_time', 'itsi_service_id',
                   'itsi_kpi_id', 'alert_period', 'alert_value']
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

    # Phase 2: iterate over (serviceid, kpiid) and output scores
    for itsi_service_id in sorted(kpidict):
        for itsi_kpi_id in sorted(kpidict[itsi_service_id]):
            params['kpi'] = {}
            params['kpi']['service_id'] = itsi_service_id
            params['kpi']['kpi_id'] = itsi_kpi_id

            logger.info("Computing scores for %s:%s" %
                        (itsi_service_id, itsi_kpi_id))

            if not read_chunk(sys.stdin, logger):
                break

            # gather the data
            df = clean_values(data=kpidict[itsi_service_id][
                itsi_kpi_id], params=params)

            # turn into a well-formed timeseries
            df = data_to_ts(data=df, params=params)

            # grab the relevant error history and determine the last scored
            # time
            get_error_digest(params=params)

            # determine where to start scoring
            find_next_index(data=df, params=params)

            # prepare for generating output
            params['out_metadata']['finished'] = False
            outbuf = StringIO.StringIO()
            params['kpi']['writer'] = csv.DictWriter(outbuf, fieldnames=[
                '_time', 'anomaly_score', 'taint', 'alert_value', 'itsi_service_id', 'itsi_kpi_id'], dialect='excel', extrasaction='ignore')
            params['kpi']['writer'].writeheader()

            # run anomaly detection
            run_ad(data=df, params=params)

            # output the results
            write_chunk(
                sys.stdout, params['out_metadata'], outbuf.getvalue())

            if params['use_kv_store']:
                # if we haven't scored any new data, leave the cursor alone
                if not params['kpi']['new_last_scored_time'] and params['kpi']['last_scored_time']:
                    params['kpi']['new_last_scored_time'] = float(
                        params['kpi']['last_scored_time'])
                elif not params['kpi']['new_last_scored_time'] and not params['kpi']['last_scored_time']:
                    # don't write anything to the kv store since we haven't
                    # scored anything
                    continue

                logger.debug("Last scored time is %s for key %s" %
                             (params['kpi']['new_last_scored_time'], itsi_service_id + ":" + itsi_kpi_id))
                put_digest_in_kv_store(params)

    # we're done, so send dummy response to finish the session
    ret = read_chunk(sys.stdin, logger)
    if ret:
        write_chunk(sys.stdout, {"finished": True}, '')

    logger.debug("\n=========\nFinished ITSI anomaly detection.\n=========")

if __name__ == "__main__":
    main()
