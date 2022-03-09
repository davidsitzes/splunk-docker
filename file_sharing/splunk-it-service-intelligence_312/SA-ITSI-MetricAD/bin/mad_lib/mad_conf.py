import logging
from mad_dom import MADCohesiveConfig, MADTrendingConfig, MADAlgoAlertConfig, MADAlgoNormalizationConfig
from mad_dom import MADAlgoThresholdConfig, MADAlgoWindowConfig
from mad_util import check_int, check_float, MADRESTException

'''
THIS IS A MIRROR OF MADConfFile.scala IN PYTHON
WHEN MODIFYING THIS FILE, PLEASE MAKE SURE ALL CHANGES IS REFLECTED IN MADConfFile.scala
'''

class AlgorithmLimits(object):

    def __init__(self, Naccum_max, Naccum_min, sensitivity_max):
        self.Naccum_max = check_float("Naccum_max", Naccum_max)
        self.Naccum_min = check_float("Naccum_min", Naccum_min)
        self.sensitivity_max = check_int("sensitivity_max", sensitivity_max)

        if self.sensitivity_max <= 0:
            raise MADRESTException("invalid sensitivity_max value: %s" % str(self.sensitivity_max), logging.ERROR, status_code=500)

        if self.Naccum_max <= 0:
            raise MADRESTException("invalid Naccum_max value: %s" % str(self.Naccum_max), logging.ERROR, status_code=500)

        if self.Naccum_min <= 0:
            raise MADRESTException("invalid Naccum_min value: %s" % str(self.Naccum_min), logging.ERROR, status_code=500)

        if self.Naccum_max <= self.Naccum_min:
            raise MADRESTException("invalid Naccum_max must be larger than Naccum_min", logging.ERROR, status_code=500)


class MADConfManager(object):

    def __init__(self, service):
        self.service = service

    def get_optional(self, stanza, key, default):
        try:
            return stanza[key]
        except AttributeError:
            return default

    def _get_threshold_config(self, stanza, limits):
        return MADAlgoThresholdConfig(
            limits=limits,
            pct_outlier=self.get_optional(stanza, "pct_outlier", 0.2),  # welp need to be compatible with old mad.conf, it doesn't have this
            slope_threshold=self.get_optional(stanza, "slope_threshold", 0.4),
            diff_sigma=self.get_optional(stanza, "diff_sigma", 3.0),
            Nkeep=stanza['Nkeep']
        )

    def _get_window_config(self, stanza, limits):
        return MADAlgoWindowConfig(
            limits=limits,
            step_size=stanza["step_size"],
            window_size=stanza["window_size"]
        )

    def _get_alert_config(self, stanza, limits):
        return MADAlgoAlertConfig(
            limits=limits,
            Naccum=stanza["Naccum"]
        )

    def _get_norm_config(self, stanza, limits):
        return MADAlgoNormalizationConfig(
            limits=limits,
            batch=stanza["norm_batch"],
            Ninit=stanza["norm_Ninit"],
            Nshift=stanza["norm_Nshift"],
            Nwindow=stanza["norm_Nwindow"],
            MAratio=stanza["norm_MAratio"],
            Ntrend=stanza["norm_Ntrend"],
            NArm=stanza["norm_NArm"],
            maxNAratio=stanza["norm_maxNAratio"],
            trendOnly=stanza["norm_trendOnly"]
        )

    def get_cohesive_defaults(self):
        limits = self.get_cohesive_limits()
        stanza = self.service.confs["mad"]["cohesive"]

        default_cohesive = MADCohesiveConfig(
            limits=limits,
            trainingPeriod=stanza["training_period"],
            maxNAratio=stanza["max_NA_ratio"],
            NArm=stanza["na_rm"],
            maxNumberOfMetrics=stanza["metrics_maximum"],
            alertConfig=self._get_alert_config(stanza, limits),
            thresholdConfig=self._get_threshold_config(stanza, limits),
            windowConfig=self._get_window_config(stanza, limits),
            normalizationConfig=self._get_norm_config(stanza, limits)
        )

        return default_cohesive, limits

    def get_trending_defaults(self):
        limits = self.get_trending_limits()
        stanza = self.service.confs["mad"]["trending"]

        default_trending = MADTrendingConfig(
            limits=limits,
            trainingPeriod=stanza["training_period"],
            maxNAratio=stanza["max_NA_ratio"],
            currentWindowIx="current",
            trendingNtrend=5,
            periodsConfig={
                "1 day": stanza["periods.days"],
                "7 days": stanza["periods.weeks"]
            },
            NArm=stanza["na_rm"],
            alertConfig=self._get_alert_config(stanza, limits),
            selfComparison=False,
            thresholdConfig=self._get_threshold_config(stanza, limits),
            windowConfig=self._get_window_config(stanza, limits)
        )

        return default_trending, limits

    def get_trending_limits(self):
        stanza = self.service.confs["mad"]["trending:limits"]
        return AlgorithmLimits(
                Naccum_max=stanza["Naccum_max"],
                Naccum_min=stanza["Naccum_min"],
                sensitivity_max=stanza["sensitivity_max"]
                )

    def get_cohesive_limits(self):
        stanza = self.service.confs["mad"]["cohesive:limits"]
        
        return AlgorithmLimits(
                Naccum_max=stanza["Naccum_max"],
                Naccum_min=stanza["Naccum_min"],
                sensitivity_max=stanza["sensitivity_max"]
                )
