import csv
from chunked_util import die, add_message


def log_and_warn(metadata, logger, msg, search_msg=None):
    search_msg = search_msg or msg
    logger.warn(msg)
    add_message(metadata, 'WARN', search_msg)


def log_and_die(metadata, logger, msg, search_msg=None):
    logger.error(msg)
    die(metadata, msg, search_msg)


def get_indices_of_big_gaps(binary_list, min_run):
    """
    Returns a list of tuples containing the (start_index, end_index) of all
    runs of consecutive 1s of length min_run or greater.
    """
    if len(binary_list) < min_run or len(binary_list) == 0:
        return []

    endpoints = [(j - i) for i, j in zip(binary_list, binary_list[1:])]
    i_start = [i + 1 for i, x in enumerate(endpoints) if x == 1]
    i_stop = [i + 1 for i, x in enumerate(endpoints) if x == -1]

    if binary_list[0] == 1:
        i_start = [0] + i_start
    if binary_list[-1] == 1:
        i_stop = i_stop + [len(binary_list)]

    candidates = zip(i_start, i_stop)

    return [t for t in candidates if t[1] - t[0] >= min_run]


def parse_input_data(the_dict, data, fields_list, params):
    """
        Populates the_dict with the values in data keyed by the fields in fields_list.

        @param the_dict: dict keyed by service_id and then by kpi_id into which we will write the data
        @param data: the incoming event data
        @param fields_list: list of strings containing the field names to be added as data to the appropriate list in the_dict
        @param params: Contains keys 'logger', 'use_kv_store', 'out_metadata', and 'kpi', the last of which contains 'service_id' and 'kpi_id'
    """
    use_kv_store = params['use_kv_store']
    logger = params['logger']
    reader = csv.DictReader(data.splitlines(), dialect='excel')

    for record in reader:
        if 'itsi_service_id' not in record:
            if not use_kv_store:
                log_and_warn(metadata=params[
                             'out_metadata'], logger=logger, msg="Missing Service ID: %s. Generating dummy value." % repr(record))
            record['itsi_service_id'] = 'DEFAULT_SERVICE_ID'
        if 'itsi_kpi_id' not in record:
            if not use_kv_store:
                log_and_warn(metadata=params[
                             'out_metadata'], logger=logger, msg="Missing KPI ID: %s. Generating dummy value." % repr(record))
            record['itsi_kpi_id'] = 'DEFAULT_KPI_ID'

        for f in fields_list:
            if record[f] is '' and f is not 'itsi_service_id' and f is not 'itsi_kpi_id':
                log_and_die(
                    metadata=params['out_metadata'], logger=logger, msg="Missing field %s at time %s" % (str(f), str(record['_time'])))
        itsi_service_id = record['itsi_service_id']
        itsi_kpi_id = record['itsi_kpi_id']
        if itsi_service_id not in the_dict:
            the_dict[itsi_service_id] = dict()
        if itsi_kpi_id not in the_dict[itsi_service_id]:
            tmpdict = {}
            for f in fields_list:
                tmpdict[f] = list()
            the_dict[record['itsi_service_id']][record['itsi_kpi_id']] = tmpdict
        currentdict = the_dict[itsi_service_id][itsi_kpi_id]
        for f in fields_list:
            currentdict[f].append(record[f])


def drop_dup(data, index):
    """Naive re-implementation of pd.DataFrame.drop_duplicates()"""
    out_data = {k: [] for k in data.keys()}
    last = None
    for i, v in enumerate(data[index]):
        if v != last:
            for k in data.keys():
                out_data[k].append(data[k][i])
            last = v

    return out_data


def clean_values(data, params):
    """Non-pandas replacement for atad_utils.create_dataframe().

    @param data: dict of '_time':       list(epoch timestamp strings)
                         'alert_value': list(float strings)
                         'alert_period': list(float strings) optional?
    @param params: dict with keys 'logger' and 'out_metadata'
    """
    logger = params['logger']
    metadata = params['out_metadata']

    values = dict(data)

    for i in range(len(values['_time'])):
        try:
            values['_time'][i] = float(values['_time'][i])
        except ValueError:
            log_and_warn(metadata, logger, "Can't parse _time '%s' as float" % values['_time'][i])
            values['_time'][i] = float('nan')

    # Drop duplicates
    values = drop_dup(values, '_time')

    for i in range(len(values['alert_value'])):
        try:
            values['alert_value'][i] = float(values['alert_value'][i])
        except ValueError:
            log_and_warn(metadata, logger, "Can't parse alert_value '%s' as float" % values['alert_value'][i])
            values['alert_value'][i] = float('nan')

    if 'alert_period' in values:
        for i in range(len(values['alert_period'])):
            try:
                values['alert_period'][i] = float(values['alert_period'][i])
            except ValueError:
                log_and_warn(metadata, logger, "Can't parse alert_period '%s' as float" % values['alert_period'][i])
                values['alert_period'][i] = float('nan')

    return values
