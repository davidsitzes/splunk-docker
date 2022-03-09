# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from itsi_module_kpi_base_search import ItsiModuleKpiBaseSearch
from itsi_module_kpi_group import ItsiModuleKpiGroup
from itsi_module_entity_source_template import ItsiModuleEntitySourceTemplate
from itsi_module_service_template import ItsiModuleServiceTemplate
from itsi_module_data_model import ItsiModuleDataModel

"""
Object manifest is used currently to control which objects are supported in module interface.
"""

object_manifest = {
    'kpi_base_search': ItsiModuleKpiBaseSearch,
    'kpi_group': ItsiModuleKpiGroup,
    'entity_source_template': ItsiModuleEntitySourceTemplate,
    'service_template': ItsiModuleServiceTemplate,
    'data_models': ItsiModuleDataModel,
    # When a request is made with object type "-", the response should contain ALL object types
    '-': [
        ItsiModuleKpiBaseSearch,
        ItsiModuleKpiGroup,
        ItsiModuleEntitySourceTemplate,
        ItsiModuleServiceTemplate,
        ItsiModuleDataModel
    ]
}
