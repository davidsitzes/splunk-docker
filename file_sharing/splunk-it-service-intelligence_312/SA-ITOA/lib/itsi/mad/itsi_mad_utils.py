import ITOA.itoa_common as utils
from itsi.mad.itsi_mad_trending_searches import ItsiMADTrendingContextManager
from itsi.mad.itsi_mad_cohesive_searches import ItsiMADCohesiveContextManager

ITSI_MAD_CONTEXT_NAME = 'itsi_mad_context'
ITSI_MAD_COHESIVE_CONTEXT_NAME = 'itsi_mad_cohesive_context'


def _delete_mad_instances(session_key, context_type, mad_instances_list):
    """
    Utility function to delete all mad instances of specific context.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type context_type: basestring
    @param context_type: mad context name

    @type mad_instances_list: list
    @param mad_instances_list: list of the mad instances

    @return: True if no exceptions, False otherwise
    """
    if not utils.is_valid_list(mad_instances_list):
        return False
    try:
        if context_type == ITSI_MAD_CONTEXT_NAME:
            context_mgr = ItsiMADTrendingContextManager(session_key)
        elif context_type == ITSI_MAD_COHESIVE_CONTEXT_NAME:
            context_mgr = ItsiMADCohesiveContextManager(session_key)
        else:
            # Not a supported context type. Hence nothing to delete.
            return True

        if not context_mgr.get_mad_context(context_type):
            # No context, nothing to delete
            return True

        for instance_id in mad_instances_list:
            context_mgr.delete_mad_instance(context_type, instance_id)

        # Delete the context if there are no more active instances for the context
        all_instance = context_mgr.get_mad_instances(context_type)
        if len(all_instance) == 0:
            context_mgr.delete_mad_context(context_type)
        return True
    except:
        return False

def delete_mad_trending_instances(session_key, mad_instances_list):
    """
    Utility function to delete instances of trending context.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type mad_instances_list: list
    @param mad_instances_list: list of the mad instance

    @return: True if no exceptions, False otherwise
    """
    return _delete_mad_instances(session_key, ITSI_MAD_CONTEXT_NAME, mad_instances_list)

def delete_mad_cohesive_instances(session_key, mad_instances_list):
    """
    Utility function to delete instances of cohesive context.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type mad_instances_list: list
    @param mad_instances_list: list of the mad instance

    @return: True if no exceptions, False otherwise
    """
    return _delete_mad_instances(session_key, ITSI_MAD_COHESIVE_CONTEXT_NAME, mad_instances_list)

def delete_mad_instances(session_key, mad_instances_list):
    """
    Utility function for mad deletion operation.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type mad_instances_list: list
    @param mad_instances_list: list of the mad instance which may contain both trending and cohesive instances

    @return: True if no exceptions, False otherwise
    """
    if not utils.is_valid_list(mad_instances_list):
        return False

    trending_instance_ids = []
    cohesive_instance_ids = []
    try:
        trending_context_mgr = ItsiMADTrendingContextManager(session_key)
        cohesive_context_mgr = ItsiMADCohesiveContextManager(session_key)
        trending_context = trending_context_mgr.get_mad_context(ITSI_MAD_CONTEXT_NAME)
        cohesive_context = cohesive_context_mgr.get_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME)

        if not trending_context and not cohesive_context:
            # No context, nothing to delete
            return True

        if trending_context:
            trending_instance_ids = get_all_mad_trending_instance_ids(session_key)
        if cohesive_context:
            cohesive_instance_ids = get_all_mad_cohesive_instance_ids(session_key)

        for instance_id in mad_instances_list:
            if instance_id in trending_instance_ids:
                trending_context_mgr.delete_mad_instance(ITSI_MAD_CONTEXT_NAME, instance_id)
                trending_instance_ids.remove(instance_id)
            if instance_id in cohesive_instance_ids:
                cohesive_context_mgr.delete_mad_instance(ITSI_MAD_COHESIVE_CONTEXT_NAME, instance_id)
                cohesive_instance_ids.remove(instance_id)

        if trending_context and len(trending_instance_ids) == 0:
            trending_context_mgr.delete_mad_context(ITSI_MAD_CONTEXT_NAME)
        if cohesive_context and len(cohesive_instance_ids) == 0:
            cohesive_context_mgr.delete_mad_context(ITSI_MAD_COHESIVE_CONTEXT_NAME)
        return True
    except:
        return False

def get_all_mad_trending_instance_ids(session_key):
    """
    Utility function to obtain all mad trending instance ids.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: List of all trending instance ids
    """
    instance_ids = []
    trending_instances = get_all_trending_instances(session_key)
    if trending_instances:
        for instance in trending_instances:
            instance_ids.append(instance['id'])
    return instance_ids

def get_all_mad_cohesive_instance_ids(session_key):
    """
    Utility function to obtain all mad cohesive instance ids.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: List of all cohesive instance ids
    """
    instance_ids = []
    cohesive_instances = get_all_cohesive_instances(session_key)
    if cohesive_instances:
        for instance in cohesive_instances:
            instance_ids.append(instance['id'])
    return instance_ids

def get_mad_trending_instances(session_key, kpi_id):
    """
    Utility function to obtain mad trending instance id associated with a kpi id
    Currently only one MAD instance is expected for each corresponding KPI
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: Instance id
    """
    try:
        context_mgr = ItsiMADTrendingContextManager(session_key)
        mad_instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_CONTEXT_NAME, kpi_id)
    except:
        mad_instance_id = None

    return mad_instance_id

def get_mad_cohesive_instances(session_key, kpi_id):
    """
    Utility function to obtain mad cohesive instance id associated with a kpi id
    Currently only one MAD cohesive instance is expected for each corresponding KPI
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: Instance id
    """
    try:
        context_mgr = ItsiMADCohesiveContextManager(session_key)
        mad_instance_id = context_mgr.get_mad_instance_id_for_kpi(ITSI_MAD_COHESIVE_CONTEXT_NAME, kpi_id)
    except:
        mad_instance_id = None

    return mad_instance_id

def get_mad_trending_instance_kpi_mapping(session_key):
    """
    Utility function to obtain all mad trending instance and return
    a key value json blob with the kpi-instance_id mapping.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: kpi->instance_id mapping for the trending context.
    """
    mapping = {}
    trending_instances = get_all_trending_instances(session_key)
    if trending_instances:
        for instance in trending_instances:
            kpi_id = instance.get('selector',{}).get('filters',{}).get('itsi_kpi_id','')
            instance_id = instance.get('id', '')
            if kpi_id in mapping:
                mapping[kpi_id].append(instance_id)
            else:
                mapping.update({kpi_id:[instance_id]})

    return mapping

def get_mad_cohesive_instance_kpi_mapping(session_key):
    """
    Utility function to obtain all mad cohesive instance and return
    a key value json blob with the kpi-instance_id mapping.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: kpi->instance_id mapping for the cohesive context.
    """
    mapping = {}
    cohesive_instances = get_all_cohesive_instances(session_key)
    if cohesive_instances:
        for instance in cohesive_instances:
            kpi_id = instance.get('selector',{}).get('filters',{}).get('itsi_kpi_id','')
            instance_id = instance.get('id', '')
            if kpi_id in mapping:
                mapping[kpi_id].append(instance_id)
            else:
                mapping.update({kpi_id:[instance_id]})
    return mapping

def get_mad_instances(session_key, kpi_id):
    """
    Utility function to obtain mad instance ids (both trending and cohesive) for a given kpi id
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type kpi_id: basestring
    @param kpi_id: kpi _key value

    @return: List of instance ids (both trending and cohesive) associated with kpi_id, else empty list
    """
    mad_instance_list = []
    try:
        trending_instances = get_mad_trending_instances(session_key, kpi_id)
        cohesive_instances = get_mad_cohesive_instances(session_key, kpi_id)
        if trending_instances:
            mad_instance_list.append(trending_instances)
        if cohesive_instances:
            mad_instance_list.append(cohesive_instances)
    except:
        mad_instance_list = None

    return mad_instance_list

def get_all_trending_instances(session_key):
    """
    Utility function to obtain mad trending instances.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: List of all trending instances, None otherwise
    """
    try:
        context_mgr = ItsiMADTrendingContextManager(session_key)
        trending_instances = context_mgr.get_mad_instances(ITSI_MAD_CONTEXT_NAME)
    except:
        trending_instances = None

    return trending_instances

def get_all_cohesive_instances(session_key):
    """
    Utility function to obtain mad cohesive instances.
    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: List of all cohesive instances, None otherwise
    """
    try:
        context_mgr = ItsiMADCohesiveContextManager(session_key)
        cohesive_instances = context_mgr.get_mad_instances(ITSI_MAD_COHESIVE_CONTEXT_NAME)
    except:
        cohesive_instances = None

    return cohesive_instances

def get_mad_instance_kpi_mapping(session_key):
    """
    Utility function to obtain all mad instance (both trending and cohesive) and return
    a key value json blob with the kpi-instance_id mapping.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @return: kpi->[instance_ids] mapping for the whole context.
    """
    mapping = {}
    trending_instances = get_all_trending_instances(session_key)
    cohesive_instances = get_all_cohesive_instances(session_key)
    if trending_instances:
        for instance in trending_instances:
            kpi_id = instance.get('selector',{}).get('filters',{}).get('itsi_kpi_id','')
            instance_id = instance.get('id', '')
            if kpi_id in mapping:
                mapping[kpi_id].append(instance_id)
            else:
                mapping.update({kpi_id:[instance_id]})

    if cohesive_instances:
        for instance in cohesive_instances:
            kpi_id = instance.get('selector',{}).get('filters',{}).get('itsi_kpi_id','')
            instance_id = instance.get('id', '')
            if kpi_id in mapping:
                mapping[kpi_id].append(instance_id)
            else:
                mapping.update({kpi_id:[instance_id]})

    return mapping

def update_mad_instance_time_resolution(session_key, mad_instances_list, resolution):
    """
    Utility function to set the resolution value within a MAD instance.
    The resolution value is the calculation window for MAD to calculate AD value
    for a particular KPI.

    Instance_id is an uuid which MAD generated for each of the KPI if that
    KPI has AD enabled. This is an unique ID for each instance.
    Instance is created under the MAD context. There is only one context
    for ITSI, there will be multiple instances for the ITSI context.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type instance_id: basestring, in uuid format
    @param instance_id: instance _key value, instances are created under the MAD context
                        each instance is corresponding to an KPI (if AD is enabled for that kpi)

    @type resolution: basestring, in the format of number + unit, etc: 5m
    @param resolution: MAD calculation resolution window which is equivalent to period_alert in ITSI

    @return: True if the all the updates are successfully, False if anyone fails
    """
    trending_instances = get_all_trending_instances(session_key)
    cohesive_instances = get_all_cohesive_instances(session_key)
    try:
        for instance_id in mad_instances_list:
            if trending_instances and instance_id in trending_instances:
                if not update_mad_trending_instance_time_resolution(session_key, instance_id, resolution):
                    return False

            if cohesive_instances and instance_id in cohesive_instances:
                if not update_mad_cohesive_instance_time_resolution(session_key, instance_id, resolution):
                    return False

        return True
    except:
        return False

def update_mad_trending_instance_time_resolution(session_key, instance_id, resolution):
    """
    Utility function to set/update the resolution value within a MAD trending instance.
    The resolution value is the calculation window for MAD to calculate AD value
    for a particular KPI.

    Instance_id is an uuid which MAD generated for each of the KPI if that
    KPI has AD enabled. This is an unique ID for each instance.
    Instance is created under the MAD context. There is only one trending context
    for ITSI, there will be multiple instances for the context.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type instance_id: basestring, in uuid format
    @param instance_id: instance _key value, instances are created under the MAD context
                        each instance is corresponding to an KPI (if AD is enabled for that kpi)

    @type resolution: basestring, in the format of number + unit, etc: 5m
    @param resolution: MAD calculation resolution window which is equivalent to period_alert in ITSI

    @return: True if the all the updates are successfully, False if anyone fails
    """
    try:
        context_mgr = ItsiMADTrendingContextManager(session_key)
        data = {'resolution': resolution}
        if context_mgr.update_mad_instance(ITSI_MAD_CONTEXT_NAME, instance_id, data):
            return True
        else:
            return False
    except:
        return False

def update_mad_cohesive_instance_time_resolution(session_key, instance_id, resolution):
    """
    Utility function to set/update the resolution value within a MAD cohesive instance.
    The resolution value is the calculation window for MAD to calculate AD value
    for a particular KPI.

    Instance_id is an uuid which MAD generated for each of the KPI if that
    KPI has AD enabled. This is an unique ID for each instance.
    Instance is created under the MAD context. There is only one cohesive context
    for ITSI, there will be multiple instances for the context.

    @type session_key: basestring
    @param session_key: session key to use in itoa_object for backend operations

    @type instance_id: basestring, in uuid format
    @param instance_id: instance _key value, instances are created under the MAD context
                        each instance is corresponding to an KPI (if AD is enabled for that kpi)

    @type resolution: basestring, in the format of number + unit, etc: 5m
    @param resolution: MAD calculation resolution window which is equivalent to period_alert in ITSI

    @return: True if the all the updates are successfully, False if anyone fails
    """
    try:
        context_mgr = ItsiMADCohesiveContextManager(session_key)
        data = {'resolution': resolution}
        if context_mgr.update_mad_instance(ITSI_MAD_COHESIVE_CONTEXT_NAME, instance_id, data):
            return True
        else:
            return False
    except:
        return False