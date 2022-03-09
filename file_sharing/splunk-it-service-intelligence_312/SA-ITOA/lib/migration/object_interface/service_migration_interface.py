# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

import glob
from ITOA.itoa_factory import instantiate_object
from ITOA import itoa_common as utils
from .itoa_migration_interface import ITOAMigrationInterface
from ITOA.datamodel_interface import DatamodelInterface
from ITOA.storage import itoa_storage

class ServiceMigrationInterface(ITOAMigrationInterface):
    """
        Migration class to handle ITOA service objects
    """
    def migration_save_single_object_to_kvstore(self, object_type, validation=True, dupname_tag=None):
        """
            Method to save service content to the kvstore for a single object.
            The coming data are coming from the local storage.
            @type object_type: basestring
            @param object_type: ITSI object types
            @type validation: boolean
            @param validation: require validation when saving to kvstore
            @type dupname_tag: basestring
            @param dupname_tag: a special tag to the duplicated titles.
            @return: boolean
        """
        self.logger.info("single object save, object: %s" % object_type)
        target_file_list = self._get_object_file_list(object_type)

        # Fetch all datamodels for datamodel conversions
        self.cached_datamodel_dict = DatamodelInterface.get_all_datamodels(
            self.session_key,
            '',
            itoa_storage.ITOAStorage().get_app_name())

        for target_file in target_file_list:
            data = utils.FileManager.read_data(target_file)
            if len(data) > 0:
                self.convert_invalid_datamodel_kpis_to_adhoc(data)
                mi_obj = instantiate_object(self.session_key,
                                            "nobody",
                                            object_type,
                                            logger=self.logger)
                if validation:
                    mi_obj.skip_service_template_update = True
                    mi_obj.force_update_savedsearch = True
                    utils.save_batch(mi_obj,
                                     "nobody",
                                     data,
                                     no_batch=False,
                                     dupname_tag=dupname_tag)
                else:
                    mi_obj.batch_save_backend("nobody", data)
                self.logger.info("%s %s saved to kvstore successfully", len(data), object_type)
            else:
                self.logger.info("no objects of type %s to be saved", object_type)

    def convert_invalid_datamodel_kpis_to_adhoc(self, data):
        """
            Converts any possible invalid datamodel KPIs to adhoc
            @type object_type: array
            @param object_type: the service objects from local storage
            @return: None
        """
        kpi_obj = instantiate_object(self.session_key,
                                    "nobody",
                                    "kpi",
                                    logger=self.logger)

        for service in data:
            for kpi in service.get('kpis', []):
                if kpi.get('search_type', '') == 'datamodel':
                    if kpi_obj.convert_invalid_datamodel_kpi_to_adhoc(kpi, self.cached_datamodel_dict):
                        self.logger.warning('Found KPI (Id: %s) in service "%s" with stale datamodel specification. Auto converting ' \
                            'this KPI to adhoc search type to prevent service failures.', kpi.get('title', ''), service.get('title'))
                    else:
                        self.logger.info('KPI (Id: %s) in service "%s" was not converted', kpi.get('title', ''), service.get('title'))

