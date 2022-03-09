import sys, math
import splunk
from mad_lib.mad_conf import MADConfManager
from mad_lib.mad_kv import MADKVStoreManager
from mad_lib.mad_dom import MADInstance

APP_ID = "SA-ITSI-MetricAD"

try:
    # Galaxy and up
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', APP_ID, 'lib']))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import client, binding

HOST_URL = "%s://%s:%s/servicesNS" % (splunk.getDefault('protocol'), splunk.getDefault('host'), splunk.getDefault('port'))
splunk.setDefault("namespace", binding.namespace("global", "nobody", APP_ID))


def prange(lower, upper, length):
    return [lower + x * (upper - lower) / length for x in range(length+1)]


class AlertingState:

    def __init__(self, limits):
        self.limits = limits

        self.accums = {}
        Naccum_range = prange(limits.Naccum_min, limits.Naccum_max, limits.sensitivity_max)
        for Naccum in Naccum_range:
            self.accums[Naccum] = 0.0

    def update(self, record):
        try:
            score = float(record["score"])
        except ValueError:
            score = float("nan")

        try:
            threshold = float(record["threshold"])
        except ValueError:
            threshold = float("nan")

        alerts = {}
        for Naccum, accum in self.accums.iteritems():
            if score and threshold:
                if not math.isnan(score) and not math.isnan(threshold):
                    if score > threshold:
                        if score > 0.005:
                            self.accums[Naccum] = self.accums[Naccum] + score
                        else:
                            self.accums[Naccum] = 0.0
                    else:
                        self.accums[Naccum] = 0.0

                    if self.accums[Naccum] > (Naccum * threshold):
                        alert = True
                    else:
                        alert = False
                else:
                    self.accums[Naccum] = 0.0
                    alert = False
            else:
                self.accums[Naccum] = 0.0
                alert = False

            sensitivity = MADInstance.get_sensitivity(Naccum, self.limits)
            alerts["sensitivity_"+str(sensitivity)] = str(alert).lower()

        return alerts


class MultiAlertingState:

    def __init__(self, limits, group_by):
        self.limits = limits
        self.group_by = group_by
        self.alert_states = {}

    def update(self, record):

        try:
            group_by_id = record[self.group_by]
        except KeyError:
            raise RuntimeError("required field '%s' does not exist in the record" % self.group_by)

        if group_by_id not in self.alert_states:
            self.alert_states[group_by_id] = AlertingState(self.limits)
        return self.alert_states[group_by_id].update(record)


@Configuration(distributed=False)
class NaccumCommand(StreamingCommand):

    algorithm = Option(
        require=False
    )

    group_by = Option(
        require=False
    )

    def stream(self, records):

        def get_instance(conf_mgr, kv_mgr, instance_id):
            res = kv_mgr.get("instance_config", instance_id, params={})
            return MADInstance.from_kv_json(conf_mgr, res)

        try:
            searchinfo = self._metadata.searchinfo
        except AttributeError as e:
            self.error_exit(e, "Can not read search metadata")

        if searchinfo.sid.startswith("searchparsetmp_"):
            self.finish()

        try:
            splunk_service = client.connect(host=splunk.getDefault('host'),
                                            port=splunk.getDefault('port'),
                                            scheme=splunk.getDefault('protocol'),
                                            owner=None,
                                            sharing="app",
                                            app=APP_ID,
                                            token=searchinfo.session_key)
        except Exception as e:
            self.error_exit(e, "Unable to connect to splunk, see log for details")

        conf_mgr = MADConfManager(splunk_service)
        kv_mgr = MADKVStoreManager(HOST_URL, APP_ID, searchinfo.session_key)
        cohesive_limits = conf_mgr.get_cohesive_limits()
        trending_limits = conf_mgr.get_trending_limits()

        alert_states = {}
        try:
            for record in records:
                if "score" in record and "threshold" in record:
                    # NOTE: This command wouldn't work in real time mode, because of the following
                    #       it does not check KV store periodically for instance updates, to make it work
                    #       we have to make the configuration versioned, and tag the data stream with the version
                    try:
                        instance_id = record["instance_id"]
                    except KeyError:
                        instance_id = "dummy_id"

                    if instance_id not in alert_states:

                        # In batch mode, there's no KV store instance to get the algorithm type from, so we will have to
                        # explicitly specify the algorithm type in that situation
                        group_by = None
                        if self.algorithm is not None:
                            algorithm_type = self.algorithm
                            group_by = self.group_by
                        else:
                            try:
                                instance = get_instance(conf_mgr, kv_mgr, instance_id)
                                algorithm_type = instance.instance_type
                                if algorithm_type == "cohesive":
                                    group_by = instance.selector.group_by
                            except Exception as e:
                                self.error_exit(e, "Unable to determine algorithm type of the data, please specify algorithm type explicitly with 'algorithm=<type>' parameter")

                        if algorithm_type == "trending":
                            limits = trending_limits
                            alert_states[instance_id] = AlertingState(limits)
                        elif algorithm_type == "cohesive":
                            limits = cohesive_limits
                            if group_by is None:
                                self.error_exit(Exception("'group_by' parameter is required for 'cohesive' algorithm"))
                            alert_states[instance_id] = MultiAlertingState(limits, group_by)
                        else:
                            self.error_exit(Exception("Unknown algorithm type: '%s'" % algorithm_type))

                    try:
                        alerts = alert_states[instance_id].update(record)
                        record.update(alerts)
                    except RuntimeError as e:
                        self.error_exit(e, "Error when calculating alert")

                yield record
        except Exception as e:
            self.error_exit(e, "exception during Naccum calculation")


dispatch(NaccumCommand, sys.argv, sys.stdin, sys.stdout, __name__)
