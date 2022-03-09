import json
import sys
try:
    # Galaxy-only
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    # Ember and earlier releases
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))
from ITOA.itoa_factory import instantiate_object
from ITOA.storage import itoa_generic_persistables

# KPI Class
# Backed either by a file or the KV store


class KPIBase(object):

    """
    Provides an interface between the threshold generation logic and KPI objects.

    KPI can be backed by
    - one of the KPIs stored in the ITSI service object
    - a temporary object in the KV store (e.g. in case a service KPI has not yet been saved)
    - a file
    """

    def __init__(self, logger=None):
        if logger is None:
            raise ValueError("Must supply a logger.")
        self.logger = logger
        self._kpi = None

    def initialize_interface(self, session_key, owner="nobody", namespace=None, **kwargs):
        raise NotImplementedError

    def fetch_kpi(self):
        raise NotImplementedError

    def get_kpi(self):
        if self._kpi is None:
            self.fetch_kpi()
        return self._kpi

    def _update_thresholds(self, policy=None, thresholds=None):
        """
        The mechanism for updating thresholds is common for any mode of operation:
        retrieve the fetched KPI object, and update it by reference using provided
        policy and thrsholds.  Mode-specific methods are responsible for persisiting
        the KPI object.

        @param policy: policy ID
        @param thresholds: list of threshold levels structures;
                           each structure is a dict with 'thresholdValue' field populated
        """
        threshold_spec = self.get_kpi()[
            'time_variate_thresholds_specification']
        threshold_spec['policies'][
            policy]['aggregate_thresholds']['thresholdLevels'] = thresholds

    def update_thresholds(self, policy=None, thresholds=None):
        """
        Persist updated thresholds

        @param policy: policy ID
        @param thresholds: list of threshold levels structures;
                           each structure is a dict with 'thresholdValue' field populated
        """
        raise NotImplementedError

    def get_tzoffset(self):
        """
        Returns a timezone offset in the format expected by splunk.util.parseISOOffset(tzoffset)
        """
        default = '+00:00'
        if isinstance(self._kpi, dict):
            return self._kpi.get('tz_offset', default)
        else:
            return default


class ServiceKPI(KPIBase):

    def __init__(self, logger=None, service_id=None, kpi_id=None):
        if not isinstance(service_id, str):
            raise ValueError(
                "Null or non-string service ID sent to KPI constructor.")
        if not isinstance(kpi_id, str):
            raise ValueError(
                "Null or non-string KPI ID sent to KPI constructor.")
        self.service_id = str(service_id)
        self.kpi_id = str(kpi_id)
        # KPI load/save operations are performed via different interface classes
        # depending on how exactly threshold data are being passed.
        # interface class instance if passing data in a saved ITSI service
        self._service_object = None
        # store fetched object so that it's easy to update
        self._kvstore_data = None
        self.session_key = None
        self.owner = None
        super(ServiceKPI, self).__init__(logger)

    def initialize_interface(self, session_key, owner="nobody", namespace=None, **kwargs):
        self.session_key = session_key
        self.owner = owner
        self._service_object = instantiate_object(self.session_key, 'nobody', 'service')

    def fetch_kpi(self):
        self.logger.debug("Loading settings from saved KPI in KV store.")
        self._kvstore_data = self._service_object.get(
            self.owner, self.service_id)
        if self._kvstore_data is None:
            self.logger.warn('Could not lookup KPIs for a seemingly stale service with id: %s', self.service_id)
            return None
        for kpi in self._kvstore_data.get("kpis", []):
            if kpi["_key"] == self.kpi_id:
                self._kpi = kpi
                return kpi
        self.logger.warn('Could not lookup KPI for a seemingly stale KPI with id: %s', self.kpi_id)
        return None

    def update_thresholds(self, policy=None, thresholds=None):
        self._update_thresholds(policy, thresholds)
        self._service_object.update(
            self.owner, self.service_id, self._kvstore_data)


class TempKPI(KPIBase):

    def __init__(self, logger=None, temp_collection_name=None, temp_object_key=None):
        if not isinstance(temp_collection_name, str):
            raise ValueError(
                "Null or non-string collection name sent to KPI constructor.")
        if not isinstance(temp_object_key, str):
            raise ValueError(
                "Null or non-string object ID sent to KPI constructor.")
        self.temp_collection_name = str(temp_collection_name)
        self.temp_object_key = str(temp_object_key)
        # KPI load/save operations are performed via different interface classes
        # depending on how exactly threshold data are being passed.
        # interface class instance if passing data in a temp collection
        self._temp_kpi_model = None
        self._temp_kpi_collection_interface = None
        # since we didn't know the collection name up front, create
        # TempKpiModel class here
        self.TempKpiModel = type("TempKpiModel", (itoa_generic_persistables.ItoaGenericModel,), {
            'backing_collection': temp_collection_name,
            'logger': logger
        })
        super(TempKPI, self).__init__(logger)

    def initialize_interface(self, session_key, owner="nobody", namespace=None, **kwargs):
        self._temp_kpi_collection_interface = self.TempKpiModel.initialize_interface(
            session_key, owner=owner, namespace=namespace, **kwargs)

    def fetch_kpi(self):
        self.logger.debug("Loading settings from temporary object with key=%s in collection %s.",
                          self.temp_object_key, self.temp_collection_name)
        self._temp_kpi_model = self.TempKpiModel.fetch_from_key(
            self.temp_object_key, interface=self._temp_kpi_collection_interface)
        self._kpi = self._temp_kpi_model.data
        return self._kpi

    def update_thresholds(self, policy=None, thresholds=None):
        self._update_thresholds(policy, thresholds)
        self._temp_kpi_model.save()


class FileBackedKPI(KPIBase):

    def __init__(self, logger=None, filename=None):
        if filename is None:
            raise ValueError(
                "Must supply a filename if not using the KV store.")
        self.kpi_file = filename
        super(FileBackedKPI, self).__init__(logger)

    def initialize_interface(self, session_key, owner="nobody", namespace=None, **kwargs):
        pass  # no-op for file-backed KPIs

    def fetch_kpi(self):
        self.logger.debug("Loading settings from file %s.", self.kpi_file)
        with open(self.kpi_file) as data_file:
            self._kpi = json.load(data_file)
        return self._kpi

    def update_thresholds(self, policy=None, thresholds=None):
        self._update_thresholds(policy, thresholds)
        with open(self.kpi_file, 'w') as data_file:
            json.dump(self._kpi, data_file)
