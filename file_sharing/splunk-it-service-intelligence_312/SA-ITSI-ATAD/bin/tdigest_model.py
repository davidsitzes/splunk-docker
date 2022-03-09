import sys
import logging
import json
import tdigest

try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITSI-ATAD', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.storage import itoa_generic_persistables
from ITOA.setup_logging import setup_logging

logger = setup_logging("itsi_atad.log", "itsi-at", level=logging.DEBUG)


class TDigestModel(itoa_generic_persistables.ItoaGenericModel):
    backing_collection = "itsi_anomaly_detection"
    logger = logger

    def __getitem__(self, key):
        return self.data.get(key, None)

    def __setitem__(self, key, item):
        self.data[key] = item

    def get(self, key, default=None):
        return self.data.get(key, default)


def get_digest_from_kv_store(params):
    logger = params['logger']
    tdigest_model = None

    try:
        tdigest_model = TDigestModel.fetch_from_key(
            params['kpi']['service_id'] + ':' + params['kpi']['kpi_id'], interface=params['interface'])

    except Exception as e:
        logger.warn("ITOA KV adapter raised an exception on fetch: %s" % e)
        return None, None

    if tdigest_model:
        logger.debug("tdigest_model returned with last scored time %s " % str(
            tdigest_model['lastscoredtime']))

        if 'tdigest' in tdigest_model.data and 'lastscoredtime' in tdigest_model.data:
            try:
                return tdigest.TDigest(json_str=tdigest_model.data['tdigest']), float(tdigest_model.data['lastscoredtime'])
            except:
                logger.warn("ITOA KV adapter returned a model with invalid lastscoredtime; generating an empty model.")
                return None, None
        else:
            logger.warn("ITOA KV adapter returned an empty model.")
            return None, None
    else:
        logger.warn(
            "ITOA KV adapter returned nothing; generating an empty model.")
        return None, None


def put_digest_in_kv_store(params):
    logger = params['logger']
    errordigest = params['kpi']['error_digest']
    lastscoredtime = params['kpi']['new_last_scored_time']

    try:
        existing_model = TDigestModel.fetch_from_key(
            params['kpi']['service_id'] + ':' + params['kpi']['kpi_id'], interface=params['interface'])

        if existing_model:
            logger.debug("Updating error digest %s with last scored time %d" % (
                repr(existing_model), lastscoredtime))

        existing_model.update(
            {"tdigest": errordigest.get_json(), "lastscoredtime": json.dumps(lastscoredtime)})
    except Exception as e:
        try:
            logger.debug(
                "Creating new error digest model with last scored time %d" % lastscoredtime)
            existing_model = TDigestModel({"tdigest": errordigest.get_json(), "lastscoredtime": json.dumps(
                lastscoredtime)}, key=params['kpi']['service_id'] + ':' + params['kpi']['kpi_id'], collection='itsi_anomaly_detection', logger=logger, interface=params['interface']).save()
        except Exception as e:
            logger.exception(e)
            logger.error("ITOA KV adapter raised an exception on save: %s" % e)
