# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import copy
import json
import re
from splunk.appserver.mrsparkle.lib import i18n
import splunk.rest as rest
from migration.migration import MigrationFunctionAbstract
from itsi.objects.itsi_service import ItsiService


class MigrateModuleKPIsToSharedBaseSearch(MigrationFunctionAbstract):
    '''
    Updates datamodel-based KPIs generated from module KPI templates, to using
    their base search equivalents.
    '''

    ############
    # Whitelists
    ############
    # KPI template ID conversion whitelist
    # This is for the Database module, where KPI template KPI IDs were changed. The conversion
    # ensures that the KPIs get picked up and migrated for database.
    KPI_TEMPLATE_ID_CONVERSION_WHITELIST = {
        "DA-ITSI-DATABASE-DB_Instance_Active_Connection": "DA-ITSI-DATABASE-Database_Active_Connection",
        "DA-ITSI-DATABASE-DB_Server_Deadlock_Rate": "DA-ITSI-DATABASE-Database_Deadlock_Rate",
        "DA-ITSI-DATABASE-DB_Server_Read_IO/s": "DA-ITSI-DATABASE-Database_Read_IO/s",
        "DA-ITSI-DATABASE-DB_Server_Write_IO/s": "DA-ITSI-DATABASE-Database_Write_IO/s",
        "DA-ITSI-DATABASE-DB_Server_Query_Response_Time": "DA-ITSI-DATABASE-Database_Query_Response_Time",
        "DA-ITSI-DATABASE-DB_Instance_Connection_Pool_Used_%": "DA-ITSI-DATABASE-Database_Connection_Pool_Used_%",
        "DA-ITSI-DATABASE-DB_Instance_Transaction_Rate": "DA-ITSI-DATABASE-Database_Transaction_Rate"
    }

    # AppServer Module KPI templates were shipped as adhoc KPIs, but will still need to be migrated.
    # This is the list of KPI templates that should be migrated.
    ACCEPTABLE_ADHOC_CONVERSION_WHITELIST = [
        "DA-ITSI-APPSERVER-Errors_(4xx)",
        "DA-ITSI-APPSERVER-Errors_(5xx)",
        "DA-ITSI-APPSERVER-Active_Threads_Count",
        "DA-ITSI-APPSERVER-Average_Transaction_Response_Time",
        "DA-ITSI-APPSERVER-Hung_Threads_Count"
    ]

    # For certain KPIs, critical fields have been modified to consolidate the number of base searches.
    # For the migration, we want to force migration even if these changes have happened.
    ACCEPTABLE_FIELD_MODIFICATIONS_WHITELIST = {
        "DA-ITSI-APPSERVER-Active_Threads_Count": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Count_of_Active_Sessions": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Errors_(4xx)": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1440"
            }
        },
        "DA-ITSI-APPSERVER-Errors_(5xx)": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1440"
            }
        },
        "DA-ITSI-APPSERVER-Garbage_Collection_Time": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1440"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Garbage_Collections_(GCs)_Count": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Hung_Threads_Count": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Memory_Heap_Size": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Memory_Heap_Used": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Memory_Pool_Size": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Memory_Used": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Perm_Gen_Usage": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            },
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-APPSERVER-Request_Count": {
            "search_alert_earliest": {
                "kpi_template_value": "5",
                "kpi_value": "1440"
            }
        },
        "DA-ITSI-DATABASE-Database_Deadlock_Rate": {
            "entity_alias_filtering_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "database_server"
            },
            "entity_id_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "Performance.database_server"
            }
        },
        "DA-ITSI-DATABASE-Database_Query_Response_Time": {
            "entity_alias_filtering_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "database_server"
            },
            "entity_id_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "Performance.database_server"
            },
            "datamodel": {
                "owner_field": {
                    "kpi_template_value": "Performance.Query.response_time",
                    "kpi_value": "Performance.Server_Stats.Query.response_time"
                }
            }
        },
        "DA-ITSI-DATABASE-Database_Read_IO/s": {
            "entity_alias_filtering_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "database_server"
            },
            "entity_id_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "Performance.database_server"
            }
        },
        "DA-ITSI-DATABASE-Database_Write_IO/s": {
            "entity_alias_filtering_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "database_server"
            },
            "entity_id_fields": {
                "kpi_template_value": "database_instance",
                "kpi_value": "Performance.database_server"
            }
        },
        "DA-ITSI-LB-Availability": {
            "metric": {
                "entity_statop": {
                    "kpi_template_value": "min",
                    "kpi_value": "avg"
                },
                "aggregate_statop": {
                    "kpi_template_value": "min",
                    "kpi_value": "avg"
                }
            }
        },
        "DA-ITSI-LB-CPU_Utilization_%_By_System": {
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-LB-Failover": {
            "metric": {
                "entity_statop": {
                    "kpi_template_value": "min",
                    "kpi_value": "avg"
                },
                "aggregate_statop": {
                    "kpi_template_value": "min",
                    "kpi_value": "avg"
                }
            }
        },
        "DA-ITSI-LB-Memory_Used_%_By_System": {
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-LB-System_Storage_Used_%_By_System": {
            "alert_period": {
                "kpi_template_value": "5",
                "kpi_value": "1"
            }
        },
        "DA-ITSI-OS-Storage_Operations:_Latency": {
            "entity_alias_filtering_fields": {
                "kpi_template_value": "host",
                "kpi_value": "None"
            }
        }
    }

    def __init__(self, session_key, logger, simulate_update=False, owner="nobody", app="itsi"):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.logger = logger
        self.simulate_update = simulate_update

    def _parse_kpi_template_response(self, content):
        '''
        Parses the response from the KPI templates endpoint

        @param content: the response from the REST endpoint
        @return: dictionary of KPI template KPI ID to KPI
        '''
        json_contents = json.loads(content)
        kpi_templates = [json.loads(entry.get("content", {}).get("kpis", "")) for entry in json_contents.get("entry", [])]
        kpi_template_kpis = sum(kpi_templates, [])
        kpi_template_kpis_dict = dict(zip([kpi.get("kpi_template_kpi_id", "") for kpi in kpi_template_kpis], kpi_template_kpis))
        self.logger.debug("Successfully fetched KPI templates from conf.")
        return kpi_template_kpis_dict

    def _parse_base_search_response(self, kpis_dict, content):
        '''
        Parses the response from the base search endpoint

        @param kpis_dict: A dictionary of KPI template KPIs
        @param content: the response from the REST endpoint
        @return: dictionary of KPI template KPI ID to base search
        '''
        json_contents = json.loads(content)
        base_searches = [[entry.get("name"), entry.get("content", {})] for entry in json_contents.get("entry", [])]
        base_searches_dict = dict(base_searches)
        # Convert the metrics string to a dictionary
        for base_search_id, base_search in base_searches_dict.items():
            base_search["metrics"] = json.loads(base_search.get("metrics", ""))
            base_search["metrics"] = dict([[metric.get("_key"), metric] for metric in base_search.get("metrics")])
        kpi_base_search_dict = dict([[kpi_id, base_searches_dict.get(kpi.get("base_search_id"), None)] for kpi_id, kpi in kpis_dict.items()])
        self.logger.debug("Successfully fetched KPI base searches from conf.")
        return kpi_base_search_dict

    def _trim_modified_fields(self, modified_fields):
        '''
        Trims down modified fields dictionary to only populated ones.
        Makes the status easier to read and compare against whitelist.

        @param modified_fields: A dictionary of modified fields
        @return: the trimmed dictionary
        '''
        for key in modified_fields.keys():
            if len(modified_fields[key]) == 0:
                del modified_fields[key]

    def get_kpi_templates_kpis_by_id(self):
        '''
        Fetches all KPI templates from conf files and converts to a dictionary
        @return: dictionary of KPI template KPI ID to KPI
        '''
        # Get KPI templates from conf since there's no guarantee configure ran before migration.
        uri = "/servicesNS/nobody/SA-ITOA/configs/conf-itsi_kpi_template"
        response, content = rest.simpleRequest(
            uri,
            sessionKey=self.session_key,
            getargs={
                "output_mode": "json",
                "search": "source_itsi_da=DA-ITSI-*"
            })

        if response.status == 200:
            return self._parse_kpi_template_response(content)
        else:
            self.logger.error("Failed to fetch KPI templates using url=%s, response=%s, content=%s", uri, response, content)
            return {}

    def get_base_searches_for_kpis_by_id(self, kpis_dict):
        '''
        Fetches all KPI base searches from conf files and maps to a template KPI id

        @param kpis_dict: A dictionary of KPI template KPIs
        @return: dictionary of KPI template KPI ID to base search
        '''
        uri = "/servicesNS/nobody/SA-ITOA/configs/conf-itsi_kpi_base_search"
        response, content = rest.simpleRequest(
            uri,
            sessionKey=self.session_key,
            getargs={
                "output_mode": "json",
                "search": "source_itsi_da=DA-ITSI-*"
            })

        if response.status == 200:
            return self._parse_base_search_response(kpis_dict, content)
        else:
            self.logger.error("Failed to fetch KPI base searches using url=%s, response=%s, content=%s", uri, response, content)
            return {}

    def get_module_created_kpis(self, service):
        '''
        Find all KPIs that were likely created using a module

        @param service: The service
        @return: collection of KPIs in the service
        '''
        kpis = service.get("kpis")
        if kpis is None:
            return []

        return [kpi for kpi in kpis if kpi.get("kpi_template_kpi_id", None)]

    def has_kpi_been_modified(self, kpi, kpi_templates_dict, base_searches_dict):
        '''
        Determines if a KPI has been modified when compared to the template. If it has, the modified fields are also returned.

        @param kpi: the KPI being checked
        @param kpi_templates_dict: the dictionary of KPIs by template ID
        @param base_searches_dict: the dictionary of base searches by template ID
        @return: boolean indicating if any field was modified, a dictionary of information containing what was modified

        '''
        has_been_modified = False
        modified_fields = {
            "metric": {},
            "datamodel": {},
            "datamodel_filter": {}
        }

        kpi_id = kpi.get("kpi_template_kpi_id")
        kpi_id = self.KPI_TEMPLATE_ID_CONVERSION_WHITELIST.get(kpi_id, kpi_id)
        kpi_template_kpi = kpi_templates_dict.get(kpi_id)
        base_search_metric = base_searches_dict.get(kpi_id, {}).get("metrics", {}).get(kpi_template_kpi.get("base_search_metric"), {})
        kpi_datamodel_object = kpi.get("datamodel", {})
        kpi_template_datamodel_object = kpi_template_kpi.get("datamodel", {})
        kpi_datamodel_filter_object = kpi.get("datamodel_filter", {})
        kpi_template_datamodel_filter_object = kpi_template_kpi.get("datamodel_filter", {})

        base_search_fields_to_check = [
            ["alert_period", lambda a, b: str(a) == str(b)],
            ["search_alert_earliest", lambda a, b: str(a) == str(b)],
            ["alert_lag", lambda a, b: str(a) == str(b)],
            ["is_entity_breakdown", lambda a, b: bool(a) == bool(b)],
            ["is_service_entity_filter", lambda a, b: bool(a) == bool(b)],
            ["entity_id_fields", lambda a, b: str(a).split(".")[-1] == str(b).split(".")[-1]],
            ["entity_alias_filtering_fields", lambda a, b: str(a) == str(b)]
        ]

        # Skipping threshold_field check because the datamodel field check will cover it
        metric_fields_to_check = [
            ["aggregate_statop", lambda a, b: str(a) == str(b)],
            ["entity_statop", lambda a, b: str(a) == str(b)],
            ["unit", lambda a, b: str(a) == str(b)]
        ]

        datamodel_fields_to_check = [
            ["datamodel", lambda a, b: str(a) == str(b)],
            ["object", lambda a, b: str(a) == str(b)],
            ["field", lambda a, b: str(a) == str(b)],
            ["owner_field", lambda a, b: str(a) == str(b)]
        ]

        # Check field changes against base search
        for field, comparator in base_search_fields_to_check:
            value_from_kpi = kpi.get(field, "")
            value_from_base_search = base_searches_dict.get(kpi_id).get(field, "")
            if not comparator(value_from_kpi, value_from_base_search):
                modified_fields[field] = {"kpi_value": str(value_from_kpi), "kpi_template_value": str(value_from_base_search)}
                has_been_modified = True

        # Check field changes against base search metric
        for field, comparator in metric_fields_to_check:
            value_from_kpi = kpi.get(field, "")
            value_from_base_search_metric = base_search_metric.get(field, "")
            if not comparator(value_from_kpi, value_from_base_search_metric):
                modified_fields["metric"][field] = {"kpi_value": str(value_from_kpi), "kpi_template_value": str(value_from_base_search_metric)}
                has_been_modified = True

        # Datamodel and datamodel filter checks work because the module developers maintain the
        # existing datamodel settings to allow for this migration to be possible
        # Check field changes against the datamodel object
        for field, comparator in datamodel_fields_to_check:
            value_from_kpi = kpi_datamodel_object.get(field, "")
            value_from_kpi_template = kpi_template_datamodel_object.get(field, "")
            if not comparator(value_from_kpi, value_from_kpi_template):
                modified_fields["datamodel"][field] = {"kpi_value": str(value_from_kpi), "kpi_template_value": str(value_from_kpi_template)}
                has_been_modified = True

        # Check datamodel filter field changes
        # Since we know field names already, we'll skip using the OrderedDict
        kpi_filters_as_string = [
            "_value:{0},_operator:{1};_field:{2}".format(item.get("_value"), item.get("_operator"), item.get("_field"))
            for item in kpi_datamodel_filter_object
        ]
        kpi_template_filters_as_string = [
            "_value:{0},_operator:{1};_field:{2}".format(item.get("_value"), item.get("_operator"), item.get("_field"))
            for item in kpi_template_datamodel_filter_object
        ]
        kpi_filters_as_string.sort()
        kpi_template_filters_as_string.sort()

        if kpi_filters_as_string != kpi_template_filters_as_string:
            modified_fields["datamodel_filter"] = {"kpi_value": kpi_datamodel_filter_object, "kpi_template_value": kpi_template_datamodel_filter_object}
            has_been_modified = True

        return has_been_modified, modified_fields

    def update_kpi(self, kpi, kpi_templates_dict, base_searches_dict):
        '''
        Updates a KPI based on information from the KPI template and the base search

        @param kpi: the KPI to be updated
        @param kpi_templates_dict: the dictionary of KPIs by template ID
        @param base_searches_dict: the dictionary of base searches by template ID
        '''

        kpi_id = kpi.get("kpi_template_kpi_id")
        kpi_id = self.KPI_TEMPLATE_ID_CONVERSION_WHITELIST.get(kpi_id, kpi_id)
        kpi_template_kpi = kpi_templates_dict.get(kpi_id)
        base_search_metric = base_searches_dict.get(kpi_id, {}).get("metrics", {}).get(kpi_template_kpi.get("base_search_metric"), {})

        kpi["search_type"] = "shared_base"
        kpi["base_search_id"] = kpi_template_kpi.get("base_search_id")
        kpi["base_search_metric"] = kpi_template_kpi.get("base_search_metric")
        kpi["threshold_field"] = base_search_metric.get("threshold_field")
        kpi["entity_statop"] = base_search_metric.get("entity_statop")
        kpi["aggregate_statop"] = base_search_metric.get("aggregate_statop")
        if kpi.get("target_field", None):
            kpi["target_field"] = base_search_metric.get("threshold_field")

        # Update datamodel fields as well
        if kpi.get("datamodel", None) and kpi_template_kpi.get("datamodel", None):
            kpi["datamodel"]["datamodel"] = kpi_template_kpi["datamodel"]["datamodel"]
            kpi["datamodel"]["object"] = kpi_template_kpi["datamodel"]["object"]
            kpi["datamodel"]["field"] = kpi_template_kpi["datamodel"]["field"]
            kpi["datamodel"]["owner_field"] = kpi_template_kpi["datamodel"]["owner_field"]

    def update_kpis_for_service(self, service, kpi_templates_dict, base_searches_dict):
        '''
        Updates the KPIs in the service

        @param service: the service to be updated
        @param kpi_templates_dict: the dictionary of KPIs by template ID
        @param base_searches_dict: the dictionary of base searches by template ID
        @return: a dictionary containing the status of the service migration
        '''

        service_title = service.get("title", "")
        service_migration_status = {
            "migrate": {},
            "skip_migrate": {},
            "service_updated": False
        }
        self.logger.info("Migrating KPIs for service: %s", service_title)
        kpis = self.get_module_created_kpis(service)
        for kpi in kpis:
            ok_to_migrate = False
            kpi_id = kpi.get("kpi_template_kpi_id")
            kpi_id = self.KPI_TEMPLATE_ID_CONVERSION_WHITELIST.get(kpi_id, kpi_id)
            kpi_title = kpi.get("title", "")
            kpi_template_kpi = kpi_templates_dict.get(kpi_id)
            self.logger.info("Checking KPI %s for service %s", kpi_title, service_title)
            if not (kpi.get("search_type", "") == "datamodel" or
                    (kpi.get("search_type", "") == "adhoc" and kpi_id in self.ACCEPTABLE_ADHOC_CONVERSION_WHITELIST)):
                service_migration_status["skip_migrate"][kpi_title] = {
                    "kpi_template_id": kpi_id,
                    "status": "Migration skipped",
                    "reason": "KPI not datamodel-based or adhoc",
                    "search_type": kpi.get("search_type", "")
                }
                self.logger.info("Skipping migration of KPI %s for service %s. KPI not datamodel-based", kpi_title, service_title)
            elif not base_searches_dict.get(kpi_id, None):
                service_migration_status["skip_migrate"][kpi_title] = {
                    "kpi_template_id": kpi_id,
                    "status": "Migration skipped",
                    "reason": "No base search defined for this KPI"
                }
                self.logger.info("Skipping migration of KPI %s for service %s. No base search defined for this KPI", kpi_title, service_title)
            elif not base_searches_dict.get(kpi_id, {}).get("metrics", {}).get(kpi_template_kpi.get("base_search_metric"), None):
                service_migration_status["skip_migrate"][kpi_title] = {
                    "kpi_template_id": kpi_id,
                    "status": "Migration skipped",
                    "reason": "No base search metric defined for this KPI"
                }
                self.logger.info("Skipping migration of KPI %s for service %s. No base search metric defined for this KPI", kpi_title, service_title)
            else:
                has_been_modified, modified_fields = self.has_kpi_been_modified(kpi, kpi_templates_dict, base_searches_dict)
                whitelisted_field_modifications = self.ACCEPTABLE_FIELD_MODIFICATIONS_WHITELIST.get(kpi_id, None)
                if has_been_modified:
                    self._trim_modified_fields(modified_fields)
                    if whitelisted_field_modifications == modified_fields:
                        service_migration_status["migrate"][kpi_title] = {
                            "kpi_template_id": kpi_id,
                            "status": "OK for migration",
                            "reason": "Acceptable fields were modified",
                            "modified_fields": modified_fields
                        }
                        ok_to_migrate = True
                        service_migration_status["service_updated"] = True
                        self.logger.info("Migrating KPI %s for service %s, with acceptable field modifications: %s", kpi_title, service_title, json.dumps(modified_fields))
                    else:
                        service_migration_status["skip_migrate"][kpi_title] = {
                            "kpi_template_id": kpi_id,
                            "status": "Migration skipped",
                            "reason": "KPI settings modification not congruent with KPI template",
                            "modified_fields": modified_fields
                        }
                        self.logger.info("Skipping migration of KPI %s for service %s. Critical fields have been modified: %s", kpi_title, service_title, json.dumps(modified_fields))
                else:
                    service_migration_status["migrate"][kpi_title] = {
                        "kpi_template_id": kpi_id,
                        "status": "OK for migration"
                    }
                    ok_to_migrate = True
                    service_migration_status["service_updated"] = True
                    self.logger.info("Migrating KPI %s for service %s.", kpi_title, service_title)
                if not self.simulate_update and ok_to_migrate:
                    self.update_kpi(kpi, kpi_templates_dict, base_searches_dict)
        return service_migration_status

    def execute(self):
        '''
        Perform action

        @rtype: bool
        @return: True/False
        '''
        try:
            kpis_from_templates = self.get_kpi_templates_kpis_by_id()
            base_searches_by_kpi = self.get_base_searches_for_kpis_by_id(kpis_from_templates)
            if not kpis_from_templates:
                self.logger.warning("No KPI templates found. Skipping KPI migration.")
                return False
            if not base_searches_by_kpi:
                self.logger.warning("No base searches were found. Skipping KPI migration.")
                return False
            service_obj = ItsiService(self.session_key, self.owner)
            all_services = service_obj.get_bulk(self.owner, req_source="base_search_migration")
            modified_services = []
            full_status = {}
            for service in all_services:
                service_title = service.get("title", "")
                service_migration_status = self.update_kpis_for_service(service, kpis_from_templates, base_searches_by_kpi)
                full_status[service_title] = service_migration_status
                if service_migration_status["service_updated"]:
                    modified_services.append(service)

            # Save all changes
            self.logger.info("Migration status: %s", json.dumps(full_status))
            if not self.simulate_update and len(modified_services) > 0:
                service_obj.save_batch(self.owner, modified_services, False, req_source="base_search_migration")
        except Exception as exc:
            self.logger.exception('Base search migration unsuccessful: %s', str(exc))
            return False
        return True


class AddItsiRoleEntityRuleToServices(MigrationFunctionAbstract):
    '''
    Services created from module service templates contain entity rules that carry the
    'role' field. Since modules have gone from using 'role' to 'itsi_role' for entities,
    this task updates those services to handle both roles to ensure continuity.
    '''
    def __init__(self, session_key, logger, simulate_update=False, owner="nobody", app="itsi"):
        """
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name

        @return:
        """
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.logger = logger
        self.simulate_update = simulate_update

        # Known set of roles to be migrated
        self.module_roles = [
            "application_server",
            "database_server",
            "database_instance",
            "loadbalancer",
            "operating_system_host",
        ]

    def get_role_rules_for_service(self, service):
        '''
        Gets the set of rules that contain a role-related field for a service

        @param service: the service
        @return: a dictionary of rules based on the role field
        '''

        role_rules = {
            "role": [],
            "itsi_role": []
        }

        # Filter out any rules that don't contain role related info
        entity_rules = service.get("entity_rules")
        entity_rules = entity_rules if entity_rules else []
        filtered_entity_rules = []
        for entity_rule in entity_rules:
            # Returns a list of the values related to the role or itsi_role field
            role_field_values = [
                rule.get("value", "").split(",")
                for rule
                in entity_rule.get("rule_items", [])
                if (
                    rule.get("field_type", "") == "info"
                    and (
                        rule.get("field", "") == "role" or
                        rule.get("field", "") == "itsi_role"
                        )
                    )]
            # For each rule value, run a regex match against known module roles
            # If any of the values match a module role, then return true.
            module_matched = sum([
                [
                    any([re.match(value, role) for role in self.module_roles])
                    for value
                    in value_array]
                for value_array in role_field_values], [])

            # If any of the values match a known module role, then include it for migration
            if any(module_matched):
                filtered_entity_rules.append(entity_rule)

        # Categorize each rule by the role field
        for entity_rule in filtered_entity_rules:
            fields = [rule.get("field", "") for rule in entity_rule.get("rule_items", [])]
            if "role" in fields:
                role_rules["role"].append(entity_rule)
            else:
                role_rules["itsi_role"].append(entity_rule)

        return role_rules

    def create_migrated_role_rule(self, entity_rule):
        '''
        For an entity rule, create an equivalent migrated entity rule

        Example input:
        -----------------------------------------------------------------------------------
        |   Alias v    x host        matches v   x BillServer*                            |
        |   Info v     x role        matches v   x operating_system_host, billing_server  |
        | + Add Rule (AND)                                                                |
        -----------------------------------------------------------------------------------

        Example output:
        -----------------------------------------------------------------------------------
        |   Alias v    x host        matches v   x BillServer*                            |
        |   Info v     x itsi_role   matches v   x operating_system_host                  |
        | + Add Rule (AND)                                                                |
        -----------------------------------------------------------------------------------

        @param entity_rule: the entity rule to migrate
        @return: a migrated entity rule
        '''
        migrated_rule = copy.deepcopy(entity_rule)
        for rule_item in migrated_rule.get("rule_items", []):
            # For any rule that contains a "role" field, update it to be "itsi_role"
            # Make sure to only include values that are module roles
            if rule_item.get("field") == "role" and rule_item.get("field_type") == "info":
                rule_item["field"] = "itsi_role"
                values_array = rule_item.get("value").split(",")
                module_role_values = [value for value in values_array if any([re.match(value, role) for role in self.module_roles])]
                rule_item["value"] = ",".join(module_role_values)

        return migrated_rule

    def add_service_entity_rules(self, service):
        '''
        Adds need entity rules for a service role rules, if applicable

        Instead of updating the existing rules, a new rule is created with itsi_role to avoid filtering out entities accidentally.
        Example:
        Before:
        -----------------------------------------------------------------------------------
        |   Alias v    x host        matches v   x BillServer*                            |
        |   Info v     x role        matches v   x operating_system_host, billing_server  |
        | + Add Rule (AND)                                                                |
        -----------------------------------------------------------------------------------

        After:
        -----------------------------------------------------------------------------------
        |   Alias v    x host        matches v   x BillServer*                            |
        |   Info v     x role        matches v   x operating_system_host, billing_server  |
        | + Add Rule (AND)                                                                |
        -----------------------------------------------------------------------------------
        -----------------------------------------------------------------------------------
        |   Alias v    x host        matches v   x BillServer*                            |
        |   Info v     x itsi_role   matches v   x operating_system_host                  |
        | + Add Rule (AND)                                                                |
        -----------------------------------------------------------------------------------

        @param service: the service

        @rtype: tuple
        @return: a tuple where:
            - first item indicates whether a service was updated
            - second item is the list of added rules, if updated. Otherwise, a status message
        '''
        role_rules = self.get_role_rules_for_service(service)
        if len(role_rules["role"]) == 0:
            return (False, "No role related rules to migrate.")

        rules_added = []
        for rule in role_rules["role"]:
            migrated_rule = self.create_migrated_role_rule(rule)
            # If this migrated rule already exists, then don't add it
            if migrated_rule not in role_rules["itsi_role"]:
                rules_added.append(migrated_rule)
                service["entity_rules"].append(migrated_rule)

        # No rules are ever removed so that check isn't needed
        return (True, rules_added) if len(rules_added) > 0 else (False, "Service already migrated")

    def execute(self):
        '''
        Perform action

        @rtype: bool
        @return: True/False
        '''
        try:
            service_obj = ItsiService(self.session_key, self.owner)
            all_services = service_obj.get_bulk(self.owner, req_source="itsi_role_migration")
            modified_services = []
            full_status = {}
            for service in all_services:
                service_title = service.get("title", "")
                added_rules = self.add_service_entity_rules(service)
                full_status[service_title] = added_rules[1]
                if added_rules[0]:
                    modified_services.append(service)

            # Save all changes
            self.logger.debug("Migration status: %s", json.dumps(full_status))
            if not self.simulate_update and len(modified_services) > 0:
                service_obj.save_batch(self.owner, modified_services, False, req_source="itsi_role_migration")
        except Exception as exc:
            self.logger.exception('Module-related role update in services unsuccessful: %s', str(exc))
            return False
        return True


class UpdateChangedDatamodelKPIs(MigrationFunctionAbstract):
    '''
    Base class used to update KPIs that are using datamodels that have been changed in a release.
    This assumes that during general service migration, the KPIs could get switched to adhoc type.
    '''

    def __init__(self, session_key, logger, simulate_update=False, owner="nobody", app="itsi"):
        '''
        @type session_key: basestring
        @param session_key: session key

        @type owner: basestring
        @param owner: owner

        @type app: basestring
        @param app: app name

        @return:
        '''
        self.session_key = session_key
        self.owner = owner
        self.app = app
        self.logger = logger
        self.simulate_update = simulate_update

    def get_datamodel_migration_mapping(self):
        '''
        Returns a mapping between datamodel objects and fields for migration purposes.

        @return:
        The return value should be an array of 2-tuples. Each tuple/pair is a before and after
        of the datamodel fields and filters

        Example output:
        [
            ({
                'datamodel': {
                    'datamodel': 'Host_OS',
                    'object': 'CPU',
                    'field': 'cpu_load_percent',
                    'owner_field': 'Performance.CPU.cpu_load_percent'
                },
                'datamodel_filter': []
            }, {
                'datamodel': {
                    'datamodel': 'Host_OS',
                    'object': 'Some other object',
                    'field': 'Some other field',
                    'owner_field': 'Some other owner field'
                },
                'datamodel_filter': [{
                    _operator: ">",
                    _field: "Performance.CPU.cpu_load_percent",
                    _value: "50"
                }]
            })...
        ]

        '''
        raise NotImplementedError(_("This method need to be implemented in version specific migrations."))

    def _serialize_datamodel_filters(self, filters):
        '''
        Serializes datamodel filters into a string array for comparison purposes

        @param filter: the list of datamodel filter objects
        @return a serialized string list
        '''
        serialized_filters = [
            "_value:{0},_operator:{1},_field:{2}".format(item.get("_value"), item.get("_operator"), item.get("_field"))
            for item in filters
        ]
        serialized_filters.sort()
        return serialized_filters

    def validate_migration_mapping(self, migration_mapping):
        '''
        Validates the migration mappings by checking for duplicates. Throws an exception, if there
        are any errors.
        '''
        # Check if there are duplicates "keys"
        first_half = [mapping[0] for mapping in migration_mapping]
        duplicates = [mapping for mapping in first_half if first_half.count(mapping) > 1]
        if len(duplicates) > 0:
            raise ValueError(_("Duplicate source datamodels found: %s") % json.dumps(duplicates))

    def update_datamodel_settings(self, service, migration_mapping):
        '''
        Updates KPIs that have a mapping that is applicable

        @param service: the service to be migrated
        @param migration_mapping: the list of mappings to be used for migration
        @return: the status of the migrated KPIs for this service
        '''
        status = {
            "service_updated": False
        }
        kpis = service.get("kpis")
        for kpi in kpis:
            if "Invalid datamodel search" not in kpi["base_search"]:
                continue
            kpi_title = kpi.get("title")
            dm_item = kpi.get("datamodel")
            dm_filter_item = kpi.get("datamodel_filter")
            mapped_dm_item = [
                mapping for mapping in migration_mapping
                if mapping[0]["datamodel"] == dm_item
                and self._serialize_datamodel_filters(mapping[0]["datamodel_filter"]) == self._serialize_datamodel_filters(dm_filter_item)]
            if len(mapped_dm_item) > 0:
                new_settings = mapped_dm_item[0][1]
                kpi["datamodel"] = copy.deepcopy(new_settings["datamodel"])
                kpi["datamodel_filter"] = copy.deepcopy(new_settings["datamodel_filter"])
                kpi["threshold_field"] = new_settings["datamodel"]["owner_field"]
                kpi["search_type"] = "datamodel"
                status[kpi_title] = {
                    "status": "Updated with new datamodel settings",
                    "old_settings": {"datamodel": dm_item, "datamodel_filter": dm_filter_item},
                    "new_settings": new_settings
                }
                status["service_updated"] = True
            else:
                status[kpi_title] = {
                    "status": "Mismatch in datamodel settings. Skipping migration.",
                    "old_settings": {"datamodel": dm_item, "datamodel_filter": dm_filter_item}
                }

        return status

    def execute(self):
        '''
        Perform action

        @rtype: bool
        @return: True/False
        '''
        try:
            service_obj = ItsiService(self.session_key, self.owner)
            all_services = service_obj.get_bulk(self.owner, req_source="datamodel_change_migration")
            modified_services = []
            migration_mapping = self.get_datamodel_migration_mapping()
            self.validate_migration_mapping(migration_mapping)
            full_status = {}
            for service in all_services:
                service_title = service.get("title", "")
                migrated_kpis = self.update_datamodel_settings(service, migration_mapping)
                full_status[service_title] = migrated_kpis
                if migrated_kpis["service_updated"]:
                    modified_services.append(service)

            # Save all changes
            self.logger.debug("Migration status: %s", json.dumps(full_status))
            if not self.simulate_update and len(modified_services) > 0:
                service_obj.save_batch(self.owner, modified_services, False, req_source="datamodel_change_migration")
        except Exception as exc:
            self.logger.exception('Datamodel settings update for services failed: %s', str(exc))
            return False
        return True


class UpdateChangedDatamodelKPIs_2_2_0_to_2_3_0(UpdateChangedDatamodelKPIs):
    '''
    Implements the datamodel mappings from ITSI 2.2.0 to 2.3.0
    '''
    def get_datamodel_migration_mapping(self):
        return [({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Instance_Stats.connections',
                'field': 'connections',
                'object': 'Instance_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.connections',
                'field': 'connections',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Instance_Stats.connection_pool_used_percent',
                'field': 'connection_pool_used_percent',
                'object': 'Instance_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.connection_pool_used_percent',
                'field': 'connection_pool_used_percent',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Instance_Stats.transaction_rate',
                'field': 'transaction_rate',
                'object': 'Instance_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.transaction_rate',
                'field': 'transaction_rate',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Server_Stats.server_read_iops',
                'field': 'server_read_iops',
                'object': 'Server_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.instance_read_iops',
                'field': 'instance_read_iops',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Server_Stats.server_write_iops',
                'field': 'server_write_iops',
                'object': 'Server_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.instance_write_iops',
                'field': 'instance_write_iops',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Server_Stats.deadlock_rate',
                'field': 'deadlock_rate',
                'object': 'Server_Stats'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.deadlock_rate',
                'field': 'deadlock_rate',
                'object': 'Performance'
            },
            'datamodel_filter': []
        }), ({
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Server_Stats.Query.response_time',
                'field': 'response_time',
                'object': 'Query'
            },
            'datamodel_filter': []
        }, {
            'datamodel': {
                'datamodel': 'Database',
                'owner_field': 'Performance.Query.response_time',
                'field': 'response_time',
                'object': 'Query'
            },
            'datamodel_filter': []
        })]
