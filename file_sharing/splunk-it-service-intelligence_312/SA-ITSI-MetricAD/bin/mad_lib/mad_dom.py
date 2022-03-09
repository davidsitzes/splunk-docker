import json
import uuid
import time
import math
import logging
import re

from mad_util import get_field, MADRESTException, check_flag, check_allowed_params, check_valid_uuid, check_int
from mad_util import check_long, check_duration, check_float, update_or_keep

AVAILABLE_ALGORITHMS = ["trending", "cohesive"]


class MADContext(object):

    def __init__(self, name, search, output_dest, managed_saved_search, alert_url, metric_limit_url, disabled):
        self.name                 = MADContext.check_name(name)
        self.search               = search
        self.output_dest          = output_dest
        self.managed_saved_search = check_flag("managed_saved_search", managed_saved_search)
        self.alert_url            = alert_url
        self.metric_limit_url     = metric_limit_url
        self.disabled             = check_flag("disabled", disabled)

    @staticmethod
    def check_name(name):
        if re.match("^[a-zA-Z0-9][a-zA-Z_0-9]*$", name):
            return name
        else:
            raise MADRESTException("'%s' is not a valid context name" % name, logging.ERROR, status_code=400)

    @staticmethod
    def from_json(context_json):
        try:
            return MADContext(
                context_json["name"],
                context_json["search"],
                context_json["output_dest"],
                context_json["managed_saved_search"],
                context_json.get("alert_url"),
                context_json.get("metric_limit_url"),
                context_json["disabled"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in context" % e.message, logging.ERROR, status_code=400)

    @staticmethod
    def from_kv_json(context_kv_json):
        context_kv_json["name"] = context_kv_json["_key"]
        context_kv_json.pop("_key", None)
        return MADContext.from_json(context_kv_json)

    @staticmethod
    def from_args(args):
        check_allowed_params(args, ['name', 'search', 'output_dest', 'managed_saved_search', 'alert_url', 'metric_limit_url'])

        name                 = get_field(args, "name")
        search               = get_field(args, "search")
        output_dest          = get_field(args, "output_dest")
        managed_saved_search = get_field(args, "managed_saved_search", is_optional=True, default=True)
        alert_url            = get_field(args, "alert_url",            is_optional=True)
        metric_limit_url     = get_field(args, "metric_limit_url",     is_optional=True)

        return MADContext(
            name                 = name,
            search               = search,
            output_dest          = output_dest,
            managed_saved_search = managed_saved_search,
            alert_url            = alert_url,
            metric_limit_url     = metric_limit_url,
            disabled             = True
        )

    def update(self, args):
        check_allowed_params(args, ['search', 'output_dest', 'disabled', 'alert_url', 'metric_limit_url'])

        return MADContext(
            name                 = self.name,
            search               = get_field(args, "search",           is_optional=True, default=self.search),
            output_dest          = get_field(args, "output_dest",      is_optional=True, default=self.output_dest),
            managed_saved_search = self.managed_saved_search,
            alert_url            = get_field(args, "alert_url",        is_optional=True, default=self.alert_url),
            metric_limit_url     = get_field(args, "metric_limit_url", is_optional=True, default=self.metric_limit_url),
            disabled             = get_field(args, "disabled",         is_optional=True, default=self.disabled)
        )

    def to_json(self):
        context_json = {
            "name": self.name,
            "output_dest": self.output_dest,
            "search": self.search,
            "disabled": self.disabled,
            "managed_saved_search": self.managed_saved_search
        }
        if self.alert_url is not None:
            context_json["alert_url"] = self.alert_url
        if self.metric_limit_url is not None:
            context_json["metric_limit_url"] = self.metric_limit_url
        return context_json

    def to_kv_json(self):
        kv_json = self.to_json()
        kv_json["_key"] = kv_json["name"]
        kv_json.pop("name", None)
        return kv_json

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADInstance(object):

    def __init__(self, instance_id, context_name, selector, instance_type, sensitivity, sensitivity_max, config, disabled, resolution, last_modified):

        self.instance_id     = check_valid_uuid(instance_id)
        self.context_name    = MADContext.check_name(context_name)
        self.instance_type   = instance_type
        self.sensitivity     = check_int("'sensitivity' in instance config", sensitivity)
        self.sensitivity_max = check_int("'sensitivity_max' in instance config", sensitivity_max)
        self.selector        = selector
        self.config          = config
        self.disabled        = check_flag("'disabled' in instance config", disabled)
        self.resolution      = check_duration("'resolution' in instance config", resolution)
        self.last_modified   = check_long("'lastModified' in instance config", last_modified)

        if self.sensitivity > sensitivity_max or self.sensitivity < 0:
            raise MADRESTException("sensitivity must be between 0 and %d" % self.sensitivity_max, logging.ERROR, status_code=400)

    @staticmethod
    def get_Naccum_step(limits):
        return (limits.Naccum_max - limits.Naccum_min) / limits.sensitivity_max

    @staticmethod
    def get_sensitivity(Naccum, limits):
        Naccum_step = MADInstance.get_Naccum_step(limits)
        return limits.sensitivity_max - int(math.floor((Naccum - limits.Naccum_min) / Naccum_step))

    @staticmethod
    def update_algo_configs(config, config_str, sensitivity, limits):
        # if we have a sensitivity value, then we first update the default config's Naccum
        if sensitivity is not None:
            sensitivity = check_int("'sensitivity' in instance config", sensitivity)

            if sensitivity > limits.sensitivity_max or sensitivity < 0:
                raise MADRESTException("sensitivity must be between 0 and %d" % limits.sensitivity_max, logging.ERROR, status_code=400)

            Naccum_new = limits.Naccum_min + (limits.sensitivity_max - sensitivity) * MADInstance.get_Naccum_step(limits)
            config = config.update({"alertConfig": {"Naccum": Naccum_new}}, limits)

        # if we have ANY algorithm config update, then we perform the update here
        # NOTE: Naccum calculated from sensitivity is overriden here, if Naccum is specified
        if config_str is not None:
            try:
                config_json = json.loads(config_str)
            except:
                raise MADRESTException("unable to deserialize algorithm configuration json", logging.ERROR, status_code=400)
            config = config.update(config_json, limits)

        # we can skip calculating the sensitivity when "sensitivity is set" and "config_str is not set"
        if not (sensitivity is not None and config_str is None):
            sensitivity = MADInstance.get_sensitivity(config.alertConfig.Naccum, limits)

        return config, sensitivity

    @staticmethod
    def from_json(conf_mgr, instance_json):
        try:
            algorithm_type = MADInstance.check_algorithm_type(instance_json["type"])
            if algorithm_type == "trending":
                selector = MADTrendingSelector.from_json(instance_json["selector"])
                limits   = conf_mgr.get_trending_limits()
                config   = MADTrendingConfig.from_json(instance_json["config"], limits)
            elif algorithm_type == "cohesive":
                selector = MADCohesiveSelector.from_json(instance_json["selector"])
                limits   = conf_mgr.get_cohesive_limits()
                config   = MADCohesiveConfig.from_json(instance_json["config"], limits)
            else:
                raise MADRESTException("unknown algorithm type: %s" % algorithm_type, logging.ERROR, status_code=400)

            sensitivity = MADInstance.get_sensitivity(config.alertConfig.Naccum, limits)

            return MADInstance(
                instance_id     = instance_json["id"],
                context_name    = instance_json["contextName"],
                selector        = selector,
                instance_type   = algorithm_type,
                sensitivity     = sensitivity,
                sensitivity_max = limits.sensitivity_max,
                config          = config,
                disabled        = instance_json["disabled"],
                resolution      = instance_json["resolution"],
                last_modified   = instance_json["lastModified"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in instance config" % e.message, logging.ERROR, status_code=400)

    @staticmethod
    def from_kv_json(conf_mgr, instance_kv_json):
        instance_kv_json["id"] = instance_kv_json["_key"]
        instance_kv_json.pop("_key", None)
        instance_kv_json.pop("_user", None)
        return MADInstance.from_json(conf_mgr, instance_kv_json)

    @staticmethod
    def from_args(conf_mgr, args, context_name):
        check_allowed_params(args, ['selector', 'type', 'config', 'sensitivity', 'disabled', 'resolution'])

        instance_id    = str(uuid.uuid4())
        algorithm_type = get_field(args, "type")
        selector_str   = get_field(args, "selector")
        config_str     = get_field(args, "config",   is_optional=True)
        sensitivity    = get_field(args, "sensitivity", is_optional=True)
        disabled       = get_field(args, "disabled", is_optional=True, default=False)
        resolution     = get_field(args, "resolution")
        last_modified  = int(time.time())

        algorithm_type = MADInstance.check_algorithm_type(algorithm_type)

        try:
            selector_json = json.loads(selector_str)
        except:
            raise MADRESTException("unable to deserialize 'selector' json\n%s" % selector_str, logging.ERROR, status_code=400)

        if algorithm_type == "trending":
            selector = MADTrendingSelector.from_json(selector_json)
            default_config, limits = conf_mgr.get_trending_defaults()
        elif algorithm_type == "cohesive":
            selector = MADCohesiveSelector.from_json(selector_json)
            default_config, limits = conf_mgr.get_cohesive_defaults()
        else:
            raise MADRESTException("unknown algorithm type: %s" % algorithm_type, logging.ERROR, status_code=400)

        config = default_config

        config, sensitivity = MADInstance.update_algo_configs(config, config_str, sensitivity, limits)

        return MADInstance(
            instance_id     = instance_id,
            context_name    = context_name,
            selector        = selector,
            instance_type   = algorithm_type,
            sensitivity     = sensitivity,
            sensitivity_max = limits.sensitivity_max,
            config          = config,
            disabled        = disabled,
            resolution      = resolution,
            last_modified   = last_modified
        )

    @staticmethod
    def check_algorithm_type(algorithm_type):
        if algorithm_type not in AVAILABLE_ALGORITHMS:
            raise MADRESTException("unrecognized algorithm '%s'" % algorithm_type, logging.ERROR, status_code=400)
        else:
            return algorithm_type

    def update(self, args, conf_mgr):
        check_allowed_params(args, ['selector', 'type', 'config', 'sensitivity', 'disabled', 'resolution'])

        instance_type = get_field(args, "type"        , is_optional=True)
        selector_str  = get_field(args, "selector"    , is_optional=True)
        sensitivity   = get_field(args, "sensitivity" , is_optional=True)
        config_str    = get_field(args, "config"      , is_optional=True)

        if instance_type is None or instance_type == self.instance_type:
            instance_type = self.instance_type

            # instance type has not changed, we're just updating the existing one
            selector = self.selector
            if selector_str is not None:
                try:
                    selector_json = json.loads(selector_str)
                except:
                    raise MADRESTException("unable to deserialize 'selector' json\n%s" % selector_str, logging.ERROR, status_code=400)
                selector = selector.update(selector_json)

            config = self.config

            if instance_type == "trending":
                limits = conf_mgr.get_trending_limits()
            elif instance_type == "cohesive":
                limits = conf_mgr.get_cohesive_limits()
            else:
                raise MADRESTException("unknown algorithm type: %s" % instance_type, logging.ERROR, status_code=400)

        else:
            # we're changing the type of our instance, old algorithm config is useless
            try:
                selector_json = json.loads(selector_str)
            except:
                raise MADRESTException("unable to deserialize 'selector' json\n%s" % selector_str, logging.ERROR, status_code=400)

            if instance_type == "trending":
                selector = MADTrendingSelector.from_json(selector_json)
                default_config, limits = conf_mgr.get_trending_defaults()
            elif instance_type == "cohesive":
                selector = MADCohesiveSelector.from_json(selector_json)
                default_config, limits = conf_mgr.get_cohesive_defaults()
            else:
                raise MADRESTException("unknown algorithm type: %s" % instance_type, logging.ERROR, status_code=400)

            config = default_config

        config, sensitivity = MADInstance.update_algo_configs(config, config_str, sensitivity, limits)

        return MADInstance(
            instance_id     = self.instance_id,
            context_name    = self.context_name,
            selector        = selector,
            instance_type   = instance_type,
            sensitivity     = sensitivity,
            sensitivity_max = limits.sensitivity_max,
            config          = config,
            disabled        = get_field(args, "disabled"  , is_optional=True, default=self.disabled),
            resolution      = get_field(args, "resolution", is_optional=True, default=self.resolution),
            last_modified   = long(time.time())
        )

    def to_json(self):
        return {
            "id"              : self.instance_id,
            "selector"        : self.selector.to_json(),
            "type"            : self.instance_type,
            "config"          : self.config.to_json(),
            "sensitivity"     : self.sensitivity,
            "sensitivity_max" : self.sensitivity_max,
            "disabled"        : self.disabled,
            "resolution"      : self.resolution,
            "contextName"     : self.context_name,
            "lastModified"    : self.last_modified
        }

    def to_kv_json(self):
        kv_json = self.to_json()
        kv_json["_key"] = kv_json["id"]
        kv_json.pop("id", None)
        return kv_json

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADInstanceSelector(object):

    def __init__(self, selector_type, filters, spl_filter, value_key):
        self.selector_type = selector_type
        self.filters       = filters
        self.spl_filter    = spl_filter
        self.value_key     = value_key

    def to_json_common(self):
        selector_common_json = {
            "type":       self.selector_type,
            "filters":    self.filters,
            "value_key":  self.value_key
        }

        if self.spl_filter is not None:
            selector_common_json["spl_filter"] = self.spl_filter

        return selector_common_json


class MADTrendingSelector(MADInstanceSelector):

    def __init__(self, selector_type, filters, spl_filter, value_key):
        super(MADTrendingSelector, self).__init__(selector_type, filters, spl_filter, value_key)

    @staticmethod
    def from_json(selector_json):
        try:
            return MADTrendingSelector(
                selector_type = selector_json["type"],
                filters       = selector_json["filters"],
                spl_filter    = selector_json.get("spl_filter"),
                value_key     = selector_json["value_key"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in selector config" % e.message, logging.ERROR, status_code=400)

    def update(self, selector_json):
        return MADTrendingSelector(
            selector_type = get_field(selector_json, "type",       is_optional=True, default=self.selector_type),
            filters       = get_field(selector_json, "filters",    is_optional=True, default=self.filters),
            spl_filter    = get_field(selector_json, "spl_filter", is_optional=True, default=self.spl_filter),
            value_key     = get_field(selector_json, "value_key",  is_optional=True, default=self.value_key)
        )

    def to_json(self):
        return self.to_json_common()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADCohesiveSelector(MADInstanceSelector):

    def __init__(self, selector_type, filters, spl_filter, value_key, group_by):
        super(MADCohesiveSelector, self).__init__(selector_type, filters, spl_filter, value_key)
        self.group_by = group_by

    @staticmethod
    def from_json(selector_json):
        try:
            return MADCohesiveSelector(
                selector_type = selector_json["type"],
                filters       = selector_json["filters"],
                spl_filter    = selector_json.get("spl_filter"),
                value_key     = selector_json["value_key"],
                group_by      = selector_json["group_by"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in selector config" % e.message, logging.ERROR, status_code=400)

    def update(self, selector_json):
        return MADCohesiveSelector(
            selector_type = get_field(selector_json, "type",       is_optional=True, default=self.selector_type),
            filters       = get_field(selector_json, "filters",    is_optional=True, default=self.filters),
            spl_filter    = get_field(selector_json, "spl_filter", is_optional=True, default=self.spl_filter),
            value_key     = get_field(selector_json, "value_key",  is_optional=True, default=self.value_key),
            group_by      = get_field(selector_json, "group_by",   is_optional=True, default=self.group_by)
        )

    def to_json(self):
        selector_json = self.to_json_common()
        selector_json["group_by"] = self.group_by
        return selector_json

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADTrendingConfig(object):

    def __init__(self, limits, trainingPeriod, maxNAratio, NArm, currentWindowIx, trendingNtrend, periodsConfig, selfComparison, alertConfig, thresholdConfig, windowConfig):
        self.trainingPeriod  = check_duration("'trainingPeriod' in trending algorithm config", trainingPeriod)
        self.maxNAratio      = check_float("'maxNAratio' in trending algorithm config", maxNAratio)
        self.NArm            = check_flag("'NArm' in trending algorithm config", NArm)
        self.currentWindowIx = currentWindowIx # string name
        self.trendingNtrend  = check_int("'trendingNtrend' in trending algorithm config", trendingNtrend)
        self.periodsConfig   = MADTrendingConfig.check_period_config(periodsConfig)
        self.selfComparison  = check_flag("'selfComparison' in trending algorithm config", selfComparison)
        self.alertConfig     = alertConfig
        self.thresholdConfig = thresholdConfig
        self.windowConfig    = windowConfig

    @staticmethod
    def check_period_config(period_config):
        valid_period_config = {}
        if isinstance(period_config, dict):
            for k, v in period_config.iteritems():
                nk = check_duration("'periodConfigs' key %s in trending algorithm config" % k, k)
                nv = check_int("'periodConfigs' value %s for key %s in trending algorithm config" % (v, k), v)
                valid_period_config[nk] = nv
            return valid_period_config
        else:
            raise MADRESTException("'periodConfigs' in trending algorithm config is not a dictionary", logging.ERROR, status_code=400)

    @staticmethod
    def from_json(trending_json, limits):
        try:
            return MADTrendingConfig(
                limits          = limits,
                trainingPeriod  = trending_json["trainingPeriod"],
                maxNAratio      = trending_json["maxNAratio"],
                NArm            = trending_json["NArm"],
                currentWindowIx = trending_json["currentWindowIx"],
                trendingNtrend  = trending_json["trendingNtrend"],
                periodsConfig   = trending_json["periodsConfig"],
                selfComparison  = trending_json["selfComparison"],
                alertConfig     = MADAlgoAlertConfig.from_json(trending_json["alertConfig"], limits),
                thresholdConfig = MADAlgoThresholdConfig.from_json(trending_json["thresholdConfig"], limits),
                windowConfig    = MADAlgoWindowConfig.from_json(trending_json["windowConfig"], limits)
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in trending algorithm config" % e.message, logging.ERROR, status_code=400)

    def update(self, trending_config_json, limits):
        return MADTrendingConfig(
            limits          = limits,
            trainingPeriod  = get_field(trending_config_json, "trainingPeriod",  is_optional=True, default=self.trainingPeriod),
            maxNAratio      = get_field(trending_config_json, "maxNAratio",      is_optional=True, default=self.maxNAratio),
            NArm            = get_field(trending_config_json, "NArm",            is_optional=True, default=self.NArm),
            currentWindowIx = get_field(trending_config_json, "currentWindowIx", is_optional=True, default=self.currentWindowIx),
            trendingNtrend  = get_field(trending_config_json, "trendingNtrend",  is_optional=True, default=self.trendingNtrend),
            periodsConfig   = get_field(trending_config_json, "periodsConfig",   is_optional=True, default=self.periodsConfig),
            selfComparison  = get_field(trending_config_json, "selfComparison",  is_optional=True, default=self.selfComparison),
            alertConfig     = update_or_keep(get_field(trending_config_json, "alertConfig",     is_optional=True), self.alertConfig, limits),
            thresholdConfig = update_or_keep(get_field(trending_config_json, "thresholdConfig", is_optional=True), self.thresholdConfig, limits),
            windowConfig    = update_or_keep(get_field(trending_config_json, "windowConfig",    is_optional=True), self.windowConfig, limits)
        )

    def to_json(self):
        return {
            "trainingPeriod"  : self.trainingPeriod,
            "maxNAratio"      : self.maxNAratio,
            "NArm"            : self.NArm,
            "currentWindowIx" : self.currentWindowIx,
            "trendingNtrend"  : self.trendingNtrend,
            "periodsConfig"   : self.periodsConfig,
            "selfComparison"  : self.selfComparison,
            "alertConfig"     : self.alertConfig.to_json(),
            "thresholdConfig" : self.thresholdConfig.to_json(),
            "windowConfig"    : self.windowConfig.to_json()
        }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADCohesiveConfig(object):
    def __init__(self, limits, trainingPeriod, maxNAratio, NArm, maxNumberOfMetrics, alertConfig, thresholdConfig, windowConfig, normalizationConfig):
        self.trainingPeriod      = check_duration("'trainingPeriod' in cohesive algorithm config", trainingPeriod)
        self.maxNAratio          = check_float("'maxNAratio' in cohesive algorithm config", maxNAratio)
        self.NArm                = check_flag("'NArm' in cohesive algorithm config", NArm)
        self.maxNumberOfMetrics  = check_int("'maximumNumberOfMetrics' in cohesive algorithm config", maxNumberOfMetrics)
        self.alertConfig         = alertConfig
        self.thresholdConfig     = thresholdConfig
        self.windowConfig        = windowConfig
        self.normalizationConfig = normalizationConfig

    @staticmethod
    def from_json(cohesive_json, limits):
        try:
            return MADCohesiveConfig(
                limits              = limits,
                trainingPeriod      = cohesive_json["trainingPeriod"],
                maxNAratio          = cohesive_json["maxNAratio"],
                NArm                = cohesive_json["NArm"],
                maxNumberOfMetrics  = cohesive_json["maximumNumberOfMetrics"],
                alertConfig         = MADAlgoAlertConfig.from_json(cohesive_json["alertConfig"], limits),
                thresholdConfig     = MADAlgoThresholdConfig.from_json(cohesive_json["thresholdConfig"], limits),
                windowConfig        = MADAlgoWindowConfig.from_json(cohesive_json["windowConfig"], limits),
                normalizationConfig = MADAlgoNormalizationConfig.from_json(cohesive_json["normalizationConfig"], limits)
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in cohesive algorithm config" % e.message, logging.ERROR, status_code=400)

    def update(self, cohesive_config_json, limits):
        return MADCohesiveConfig(
            limits              = limits,
            trainingPeriod      = get_field(cohesive_config_json, "trainingPeriod",         is_optional=True, default=self.trainingPeriod),
            maxNAratio          = get_field(cohesive_config_json, "maxNAratio",             is_optional=True, default=self.maxNAratio),
            NArm                = get_field(cohesive_config_json, "NArm",                   is_optional=True, default=self.NArm),
            maxNumberOfMetrics  = get_field(cohesive_config_json, "maximumNumberOfMetrics", is_optional=True, default=self.maxNumberOfMetrics),
            alertConfig         = update_or_keep(get_field(cohesive_config_json, "alertConfig",         is_optional=True), self.alertConfig, limits),
            thresholdConfig     = update_or_keep(get_field(cohesive_config_json, "thresholdConfig",     is_optional=True), self.thresholdConfig, limits),
            windowConfig        = update_or_keep(get_field(cohesive_config_json, "windowConfig",        is_optional=True), self.windowConfig, limits),
            normalizationConfig = update_or_keep(get_field(cohesive_config_json, "normalizationConfig", is_optional=True), self.normalizationConfig, limits)
        )

    def to_json(self):
        return {
            "trainingPeriod"         : self.trainingPeriod,
            "maxNAratio"             : self.maxNAratio,
            "NArm"                   : self.NArm,
            "maximumNumberOfMetrics" : self.maxNumberOfMetrics,
            "alertConfig"            : self.alertConfig.to_json(),
            "thresholdConfig"        : self.thresholdConfig.to_json(),
            "windowConfig"           : self.windowConfig.to_json(),
            "normalizationConfig"    : self.normalizationConfig.to_json()
        }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADAlgoWindowConfig(object):
    def __init__(self, limits, step_size, window_size):
        self.step_size   = check_int("'stepSize' in 'windowConfig'", step_size)
        self.window_size = check_int("'windowSize' in 'windowConfig", window_size)

    @staticmethod
    def from_json(window_cfg_json, limits):
        try:
            return MADAlgoWindowConfig(
                limits      = limits,
                step_size   = window_cfg_json["stepSize"],
                window_size = window_cfg_json["windowSize"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in window config" % e.message, logging.ERROR, status_code=400)

    def update(self, window_cfg_json, limits):
        return MADAlgoWindowConfig(
            limits      = limits,
            step_size   = get_field(window_cfg_json, "stepSize",   is_optional=True, default=self.step_size),
            window_size = get_field(window_cfg_json, "windowSize", is_optional=True, default=self.window_size))

    def to_json(self):
        return {
            "stepSize"   : self.step_size,
            "windowSize" : self.window_size
        }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADAlgoThresholdConfig(object):
    def __init__(self, limits, pct_outlier, slope_threshold, diff_sigma, Nkeep):
        self.pct_outlier     = check_float("'pctOutlier' in 'thresholdConfig'", pct_outlier)
        self.slope_threshold = check_float("'slopeThreshold' in 'thresholdConfig'", slope_threshold)
        self.diff_sigma      = check_float("'diffSigma' in 'thresholdConfig'", diff_sigma)
        self.Nkeep           = check_duration("'Nkeep' in 'thresholdConfig'", Nkeep)

    @staticmethod
    def from_json(threshold_cfg_json, limits):
        try:
            return MADAlgoThresholdConfig(
                limits          = limits,
                pct_outlier     = threshold_cfg_json["pctOutlier"],
                slope_threshold = threshold_cfg_json["slopeThreshold"],
                diff_sigma      = threshold_cfg_json["diffSigma"],
                Nkeep           = threshold_cfg_json["Nkeep"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in threshold config" % e.message, logging.ERROR, status_code=400)

    def update(self, threshold_cfg_json, limits):
        return MADAlgoThresholdConfig(
            limits          = limits,
            pct_outlier     = get_field(threshold_cfg_json, "pctOutlier",     is_optional=True, default=self.pct_outlier),
            slope_threshold = get_field(threshold_cfg_json, "slopeThreshold", is_optional=True, default=self.slope_threshold),
            diff_sigma      = get_field(threshold_cfg_json, "diffSigma",      is_optional=True, default=self.diff_sigma),
            Nkeep           = get_field(threshold_cfg_json, "Nkeep",          is_optional=True, default=self.Nkeep)
        )

    def to_json(self):
        return {
            "pctOutlier"     : self.pct_outlier,
            "slopeThreshold" : self.slope_threshold,
            "diffSigma"      : self.diff_sigma,
            "Nkeep"          : self.Nkeep
        }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADAlgoAlertConfig(object):
    def __init__(self, limits, Naccum):
        self.Naccum = check_float("'Naccum' in 'alertConfig'", Naccum)
        if self.Naccum < limits.Naccum_min or self.Naccum > limits.Naccum_max:
            raise MADRESTException(
                "'Naccum' in 'alertConfig' must be a number between %d - %d" % (limits.Naccum_min, limits.Naccum_max),
                level=logging.ERROR,
                status_code=400
            )

    @staticmethod
    def from_json(alert_cfg_json, limits):
        try:
            return MADAlgoAlertConfig(
                limits=limits,
                Naccum=alert_cfg_json["Naccum"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in alert config" % e.message, logging.ERROR, status_code=400)

    def update(self, alert_cfg_json, limits):
        return MADAlgoAlertConfig(limits, get_field(alert_cfg_json, "Naccum", is_optional=True, default=self.Naccum))

    def to_json(self):
        return {"Naccum": self.Naccum}

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented


class MADAlgoNormalizationConfig(object):
    def __init__(self, limits, batch, Ninit, Nshift, Nwindow, MAratio, Ntrend, NArm, maxNAratio, trendOnly):
        self.batch      = check_flag("'batch' in 'normalizationConfig'", batch)
        self.Ninit      = check_int("'Ninit' in 'normalizationConfig'", Ninit)
        self.Nshift     = check_int("'Nshift' in 'normalizationConfig'", Nshift)
        self.Nwindow    = check_int("'Nwindow', in 'normalizationConfig'", Nwindow)
        self.MAratio    = check_float("'MAratio' in 'normalizationConfig'", MAratio)
        self.Ntrend     = check_int("'Ntrend' in 'normalizationConfig'", Ntrend)
        self.NArm       = check_flag("'NArm' in 'normalizationConfig'", NArm)
        self.maxNAratio = check_float("'maxNAratio' in 'normalizationConfig'", maxNAratio)
        self.trendOnly  = check_flag("'trendOnly' in 'normalizationConfig'", trendOnly)

    @staticmethod
    def from_json(norm_cfg_json, limits):
        try:
            return MADAlgoNormalizationConfig(
                limits     = limits,
                batch      = norm_cfg_json["batch"],
                Ninit      = norm_cfg_json["Ninit"],
                Nshift     = norm_cfg_json["Nshift"],
                Nwindow    = norm_cfg_json["Nwindow"],
                MAratio    = norm_cfg_json["MAratio"],
                Ntrend     = norm_cfg_json["Ntrend"],
                NArm       = norm_cfg_json["NArm"],
                maxNAratio = norm_cfg_json["maxNAratio"],
                trendOnly  = norm_cfg_json["trendOnly"]
            )
        except KeyError as e:
            raise MADRESTException("%s field missing in normalization config" % e.message, logging.ERROR, status_code=400)

    def update(self, norm_cfg_json, limits):
        return MADAlgoNormalizationConfig(
            limits     = limits,
            batch      = get_field(norm_cfg_json, "batch",      is_optional=True, default=self.batch),
            Ninit      = get_field(norm_cfg_json, "Ninit",      is_optional=True, default=self.Ninit),
            Nshift     = get_field(norm_cfg_json, "Nshift",     is_optional=True, default=self.Nshift),
            Nwindow    = get_field(norm_cfg_json, "Nwindow",    is_optional=True, default=self.Nwindow),
            MAratio    = get_field(norm_cfg_json, "MAratio",    is_optional=True, default=self.MAratio),
            Ntrend     = get_field(norm_cfg_json, "Ntrend",     is_optional=True, default=self.Ntrend),
            NArm       = get_field(norm_cfg_json, "NArm",       is_optional=True, default=self.NArm),
            maxNAratio = get_field(norm_cfg_json, "maxNAratio", is_optional=True, default=self.maxNAratio),
            trendOnly  = get_field(norm_cfg_json, "trendOnly",  is_optional=True, default=self.trendOnly)
        )

    def to_json(self):
        return {
            "batch"      : self.batch,
            "Ninit"      : self.Ninit,
            "Nshift"     : self.Nshift,
            "Nwindow"    : self.Nwindow,
            "MAratio"    : self.MAratio,
            "Ntrend"     : self.Ntrend,
            "NArm"       : self.NArm,
            "maxNAratio" : self.maxNAratio,
            "trendOnly"  : self.trendOnly
        }

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return NotImplemented
