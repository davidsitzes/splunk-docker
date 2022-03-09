def _get_object_order(object_type):
    """
        Return the weight of different object types.
        This is needed when perform copying object back to kvstore.
        In order to restore the service object, certain set of objects have to be
        restored first, the following order indicates such dependencies.
        @type object_type: basestring
        @param object_type: object_type
        @return: int, priority of the object type
    """
    if object_type == 'team':
        return 0
    elif object_type == 'entity':
        return 1
    elif object_type == 'kpi_template':
        return 2
    elif object_type == 'kpi_base_search':
        return 3
    elif object_type == 'kpi_threshold_template':
        return 4
    elif object_type == 'base_service_template':
        return 5
    elif object_type == 'service':
        return 6
    elif object_type == 'maintenance_calendar':
        return 7
    elif object_type == 'glass_table_images':
        return 99
    elif object_type == 'glass_table_icons':
        return 100
    else:
        return 6
