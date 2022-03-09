#!/usr/bin/env python

# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import sys
import csv

from splunk.util import normalizeBoolean
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ITOA', 'lib']))

from ITOA.splunk_search_chunk_protocol import SearchChunkProtocol
from ITOA.itoa_common import is_string_numeric
from itsi.set_severity_fields import SetSeverityFields, CollectKpiInfo, logger as setup_logger

# just use the logger from set_severity_fields
logger = setup_logger

class SetSeverityFieldsCommand(SearchChunkProtocol):

    is_service_max_severity_event_field = 'is_service_max_severity_event'
    is_service_aggregate_field = "is_service_aggregate"

    def __init__(self):

        hand_shake_output_data = {
            'type': 'reporting'
        }
        super(SetSeverityFieldsCommand, self).__init__(output_meta_data=hand_shake_output_data, logger=logger)

        # TODO at some point refactor identification of fields to add to the result set
        # Its currently littered and saved in additon to being split into fields_to_add and new_fieldnames
        self.fields_to_add = ['alert_severity', 'alert_color', 'alert_level', 'kpiid', 'serviceid']
        self.new_fieldnames = [
            'alert_value',
            'alert_error',
            'kpi',
            'alert_period',
            'urgency',
            'kpibasesearch',
            'is_service_in_maintenance',
            'is_all_entities_in_maintenance',
            'is_entity_in_maintenance'
        ]

        # kpiid
        self.kpiid = self.args.get('kpiid')
        self.serviceid = self.args.get('serviceid')
        self.kpibasesearchid = self.args.get('kpibasesearch')

        default_no_data_max_event = False
        if self.kpibasesearchid is not None:
            logger.info('Initialized setseverityfield with serviceid=%s kpiid=%s', self.serviceid, self.kpiid)
            default_no_data_max_event = True
            self.fields_to_add.append('kpibasesearch')
        else:
            logger.info('Initialized setseverityfield with kpibasesearchid=%s', self.kpibasesearchid)
        # Flag to avoid no data scenario and max event generation
        self.is_handle_no_data = normalizeBoolean(self.args.get('handle_no_data', default_no_data_max_event))
        self.is_generate_max_result = normalizeBoolean(
            self.args.get('generate_max_severity_event', default_no_data_max_event))

        # Field needs to be added for max severity event and no data scenario
        if self.is_handle_no_data or self.is_generate_max_result:
            self.fields_to_add.append(self.is_service_max_severity_event_field)
            self.fields_to_add.append(self.is_service_aggregate_field)

        self.collect_kpi_data = CollectKpiInfo(self.session_key)

        self.set_severity_fields = SetSeverityFields(self.is_handle_no_data, self.is_generate_max_result,
                                                     self.earliest_time)

        self.kpidata = {}
        self.servicedata = {}

        #We need this for kpi base searches to determine when we have a no-data scenario
        #Coming in with data
        #We currently don't need to do this at the kpi level because all of the entities filtering
        #Is done at the service level
        self.passedServices = set()
        self.lastTime = None

    def validate_search_args(self):
        """
        Validate search argument
        @rtype: tuple
        @return: return boolean flag and messages
        """
        kpibasesearchid = self.args.get('kpibasesearch')
        kpiid = self.args.get('kpiid')
        serviceid = self.args.get('serviceid')

        msgs = []
        if kpibasesearchid is None and kpiid is None and serviceid is None:
            message = _("Invalid options passed to command; must have service and kpi or kpi base search")
            logger.error(message)
            msgs.append(message)

        if kpibasesearchid is None:
            # Validate the kpiid and the serviceid if we ware NOT using the kpibasesearch
            if kpiid is None:
                message = _("Invalid kpiid argument")
                logger.error(message)
                msgs.append(message)

            if serviceid is None:
                message = _('Invalid serviceid argument')
                logger.error(message)
                msgs.append(message)
        if len(msgs) > 0:
            return False, msgs
        else:
            return True, msgs

    def get_itsi_meta_data(self, is_max_result_event=False):
        """
        Return dict with kpiid and serviceid

        @type is_max_result_event: boolean
        @param is_max_result_event: pass to true if this meta data belong to max value events of service
        @rtype: dict
        @return: return dict
        """
        meta_data = {
            'kpiid': self.kpiid,
            'serviceid': self.serviceid
        }
        if self.kpibasesearchid:
            meta_data['kpibasesearch'] = self.kpibasesearchid
        if self.is_generate_max_result:
            meta_data[self.is_service_max_severity_event_field] = 1 if is_max_result_event else 0

        return meta_data

    def _get_csv_dict_writer(self, out_buf, fieldnames, is_write_header=True):
        """
        Get csvWriter object after initializing header

        @type out_buf: cStringIO object (refer self.get_string_buffer for more info)
        @param out_buf: output buffer object

        @type fieldnames: list
        @param fieldnames: csv header field names

        @type is_write_header: bool
        @param is_write_header: flag to write header into buffer
        @return:
        """
        writer = csv.DictWriter(out_buf, fieldnames=fieldnames)
        if is_write_header:
            writer.writeheader()
        return writer

    def _get_value_and_write(self, writer, result, kpidata):
        """
        Call get_severity_info and get severity value for given result set (alert_value)
            result must have alert_value key

        @type writer: csvDictWriter refer self._get_csv_dict_writer()
        @param writer: csv dict writer object

        @type result: dict
        @param result: dict which hold alert_value information

        @type kpidata: dict or single object
        @param kpidata: kpi meta data

        @return: None
        """
        if isinstance(kpidata, dict) and self.kpibasesearchid is not None:
            # This is the shared base search KPI scenario
            # So take the search result and look to see which entity it references
            last_time = result.get("_time", None)
            is_service_aggregate = normalizeBoolean(result.get("is_service_aggregate", False))
            is_all_entities_in_maintenance = normalizeBoolean(result.get("is_entity_in_maintenance", False))
            if last_time is not None:
                self.lastTime = last_time

            svc_id = result.get('serviceid')
            svc_data = kpidata.get(svc_id)
            if not svc_data or not svc_id:
                logger.debug('Found search results for service: %s, but this service has been deleted', svc_id)
            else:
                #Add this to indicate that we have seen the service and therefore the kpi
                self.passedServices.add(svc_id)

                if is_service_aggregate:
                    result.update(
                        {'is_all_entities_in_maintenance': is_all_entities_in_maintenance}
                    )

                for kpi in svc_data["kpis"]:
                    metric = kpi.get("base_search_metric")
                    if metric is None:
                        continue
                    alert_value = result.get("alert_value_" + metric)
                    if alert_value is None:
                        result["alert_value"] = _("N/A")
                        result["alert_error"] = _("Not found for metric %s") % metric
                    else:
                        result["alert_value"] = alert_value

                    # Check for the count override
                    if not is_string_numeric(result["alert_value"]) and \
                            self.collect_kpi_data.check_kpi_for_count_override(kpi):
                        # We need to set the value to 0 because it is a count of nothing
                        result["alert_value"] = 0

                    values = self.set_severity_fields.get_severity_info(result, kpi=kpi, service_info=svc_data)
                    self.serviceid = svc_id
                    self.kpiid = kpi.get('_key')
                    result.update(values)
                    is_service_in_maintenance = normalizeBoolean(result.get('is_service_in_maintenance'))
                    result.update({"alert_period": kpi.get("alert_period"),
                                   "kpi": kpi.get("title"),
                                   "urgency": kpi.get("urgency") if not is_service_in_maintenance else 0,
                                   "serviceid": self.serviceid #We do this here for ITOA-5345, prevents serviceid leakage
                                   })
                    result.update(self.get_itsi_meta_data())
                    writer.writerow(result)
        elif self.serviceid is not None and self.kpiid is not None:
            # This is the standard KPI handling scenario
            if not is_string_numeric(result.get("alert_value")) and \
                    self.collect_kpi_data.check_kpi_for_count_override(self.kpidata):
                # We need to set the value to 0 because it is a count of nothing
                result["alert_value"] = 0
            self.servicedata['in_maintenance'] = (
                self.servicedata.get('in_maintenance', False) or
                normalizeBoolean(result.get('is_service_in_maintenance', False))
            )
            values = self.set_severity_fields.get_severity_info(result, kpi=self.kpidata, service_info=self.servicedata)
            result.update(values)
            result.update(self.get_itsi_meta_data())
            if 'alert_value' not in result:
                # no alert_value fields most likely means no data, thus set to 'N/A'
                result.update({'alert_value': _('N/A')})
            writer.writerow(result)
        else:
            # This is the we have no idea what this data is scenario
            result["alert_value"] = _("N/A")
            result["alert_error"] = _("No matching services found for entity")
            writer.writerow(result)

    def pre_processing(self):
        """
        Override function
        Collect kpi meta from kv store (one time task)
        @return:
        """
        if self.kpibasesearchid is not None:
            # Gather the KPI data from the base search
            self.kpidata = self.collect_kpi_data.get_kpis_from_shared_base(self.kpibasesearchid)
            if self.kpidata is None:
                logger.warning("Could not find kpi data, could be called by preview before kpi or service creation,"
                            " kpibasesearchid=%s", self.kpibasesearchid)
                # Avoid failure in run and post_processing
                self.kpidata = {}
                return
        else:  # We are getting info for a single KPI
            kpidata, servicedata = self.collect_kpi_data.get_kpi(self.serviceid, self.kpiid)
            if kpidata is None:
                logger.warning("Could not find kpi data, could be called by preview before kpi or service creation,"
                            " kpiid=%s, serviceid=%s", self.kpiid, self.serviceid)
            else:
                self.kpidata = kpidata
                self.servicedata = servicedata

    def run(self, metadata, body, chunk):
        """
        Read the chunk data and get severity values for each events of chunk data
        @return:
        """
        if not self.is_generate_max_result:
            out_metadata = {'finished': metadata.get('finished', False)}
        else:
            out_metadata = {'finished': False}

        output_buf = self.get_string_buffer()

        reader = csv.DictReader(body.splitlines())

        # Make sure it is first chunk and with no data
        if not reader.fieldnames and self.is_handle_no_data and chunk == 0:
            writer = self._get_csv_dict_writer(output_buf, fieldnames=self.new_fieldnames + self.fields_to_add)
            if self.kpibasesearchid is None:
                logger.info("No data scenario for kpiid=%s, serviceid=%s", self.kpiid, self.serviceid)
                result = {'alert_value': 'N/A', 'is_service_aggregate': 1}
                self._get_value_and_write(writer, result, self.kpidata)
            else:
                logger.info("No data scenario for kpibasesearchid=%s", self.kpibasesearchid)
                for svc_id in self.kpidata.keys():
                    result = {'alert_value': 'N/A', 'is_service_aggregate': 1, 'serviceid': svc_id}
                    self._get_value_and_write(writer, result, self.kpidata)
        else:
            fields = reader.fieldnames if reader.fieldnames else []
            writer = self._get_csv_dict_writer(output_buf, fieldnames=self.new_fieldnames + fields + self.fields_to_add)
            for result in reader:
                self._get_value_and_write(writer, result, self.kpidata)

        self.write_chunk(out_metadata, output_buf.getvalue())

    def post_processing(self):
        """
        Perform post processing
        @return: None
        """
        if self.is_generate_max_result and self.kpibasesearchid is None:
            logger.debug("setseverityfields post processing for serviceid=%s kpiid=%s", self.serviceid, self.kpiid)
            max_result = self.set_severity_fields.get_max_value_event(self.kpiid)
            if max_result:
                out_new_buf = self.get_string_buffer()
                if 'alert_value' not in max_result:
                    # No data case with no alert_value field, just populate the field with a default value
                    max_result.update({'alert_value': 'N/A'})
                writer_max = self._get_csv_dict_writer(out_new_buf, fieldnames=max_result.keys() + self.fields_to_add)
                max_result.update(self.get_itsi_meta_data(is_max_result_event=True))
                writer_max.writerow(max_result)
                self.write_chunk({'finished': True}, out_new_buf.getvalue())
            else:
                logger.warning("Could not get max value event for service=%s kpi=%s", self.serviceid, self.kpiid)
                self.write_chunk({'finished': True}, '')
        elif self.kpibasesearchid is not None and self.is_generate_max_result:
            logger.debug("setseverityfields post processing for kpibasesearchid=%s", self.kpibasesearchid)
            #Deal with any kpis that had no matching events due to entity rules
            # Saw exception where self.kpidata is NoneType
            existing_matches = set(self.kpidata.keys()) if self.kpidata else set()
            empty_services = existing_matches.difference(self.passedServices)
            for svc_id in empty_services:
                out_metadata = {'finished': False}
                out_new_buf = self.get_string_buffer()
                result = {'alert_value': 'N/A',
                          'is_service_aggregate': 1,
                          'entity_title' : 'service_aggregate',
                          'entity_key' : 'service_aggregate',
                          'is_entity_defined': 0,
                          'serviceid': svc_id}
                if self.lastTime is not None:
                    result['_time'] = self.lastTime
                writer = self._get_csv_dict_writer(
                                out_new_buf, fieldnames=result.keys() + self.new_fieldnames + self.fields_to_add)
                self._get_value_and_write(writer, result, self.kpidata)
                self.read_chunk(sys.stdin)
                self.write_chunk(out_metadata, out_new_buf.getvalue())
            # Fire off one event per kpi
            if not isinstance(self.kpidata, dict):
                return
            last_service = -1
            if self.kpidata is not None and len(self.kpidata) > 0:
                last_service = self.kpidata.keys()[-1]
            for svc_id, svc_data in self.kpidata.iteritems():
                kpis = svc_data.get("kpis")
                if not isinstance(kpis, list):
                    logger.error("Critical error, kpis invalid for serviceid=%s", svc_id)
                    continue
                for kpi in kpis:
                    self.kpiid = kpi['_key']
                    logger.debug("max severity chunk on kpiid=%s", self.kpiid)
                    final_chunk = False
                    if svc_id == last_service and self.kpiid == kpis[-1]['_key']:
                        # If we are on the very last KPI, then set the finished flag
                        logger.debug("final chunk on kpiid=%s", self.kpiid)
                        final_chunk = True
                    self.serviceid = svc_id
                    max_result = self.set_severity_fields.get_max_value_event(self.kpiid)
                    if max_result:
                        max_result["kpi"] = kpi.get("title")
                        is_service_in_maintenance = normalizeBoolean(max_result.get('is_service_in_maintenance', False))
                        max_result["urgency"] = kpi.get("urgency") if not is_service_in_maintenance else 0
                        out_new_buf = self.get_string_buffer()
                        writer_max = self._get_csv_dict_writer(
                            out_new_buf, fieldnames=max_result.keys() + self.fields_to_add)
                        max_result.update(self.get_itsi_meta_data(is_max_result_event=True))
                        writer_max.writerow(max_result)
                        self.read_chunk(sys.stdin)
                        self.write_chunk({'finished': final_chunk}, out_new_buf.getvalue())
                    else:
                        logger.warning("Could not get max value event for kpi=%s serviceid=%s using kpibasesearchid=%s",
                                self.kpiid,
                                svc_id,
                                self.kpibasesearchid)
                        self.read_chunk(sys.stdin)
                        self.write_chunk({'finished': final_chunk}, '')

if __name__ == "__main__":
    if not logger:
        logger = setup_logger
    sc = None
    try:
        sc = SetSeverityFieldsCommand()
        sc.execute()
    except Exception as e:
        logger.exception(e)
        if sc is not None:
            sc.exit_with_error({'finished': True}, [e.message])
        else:
            raise
