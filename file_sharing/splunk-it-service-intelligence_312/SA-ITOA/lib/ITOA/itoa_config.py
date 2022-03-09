"""
This module contains configuration tying the generic implementations in current package (itoa package) to
app specific uses. For example when used for ITSI, specify itsi modules to load for itoa to find ITSI specific
implementations
"""

_itoa_supported_objects = {} # Store object manifest to prevent repeated imports
def get_supported_objects():
    """
    Specification for object types (derived implementations of ItoaObject) supported by an app

    @return: array of app specific objects that ITOA should support
    """
    global _itoa_supported_objects
    if _itoa_supported_objects == {}:
        from itsi.objects.object_manifest import object_manifest as itsi_object_manifest
        from maintenance_services.objects.object_manifest import object_manifest as maintenance_object_manifest
        from event_management.event_management_object_manifest import object_manifest as event_management_object_manifest
        _itoa_supported_objects = dict(
            itsi_object_manifest.items() +
            maintenance_object_manifest.items() +
            event_management_object_manifest.items()
        )
    return _itoa_supported_objects

_itoa_handler_manifest = None # Store handler manifest to prevent repeated imports
def get_registered_change_handlers():
    """
    ITOA provides a generic refresh queue implementation for object change management.
    Apps consuming this feature need to provide app specific change handlers.
    This method is a means for apps to register config for specific change handlers.

    @return: array of app specific change handlers that itoa refresh can handle
    """
    global _itoa_handler_manifest
    if _itoa_handler_manifest is None:
        from itsi.objects.changehandlers.handler_manifest import handler_manifest
        _itoa_handler_manifest = handler_manifest
    return _itoa_handler_manifest

_itoa_collection_map_for_itoa_object = {} # Store collection mapping to prevent repeated imports
def get_collection_name_for_itoa_object(object_type):
    """
    Method returns a collection name given an object type
    @param object_type: ITOA object type
    @param type: string
    @return collection_name: collection where objects of object_type is stored
    @return type: string
    """
    global _itoa_collection_map_for_itoa_object
    if _itoa_handler_manifest is None:
        from itsi.itsi_utils import OBJECT_COLLECTION_MATRIX
        from maintenance_services.objects.utils import object_collection_mapping as maintenance_object_collection_mapping
        _itoa_collection_map_for_itoa_object = dict(
            OBJECT_COLLECTION_MATRIX.items() +
            maintenance_object_collection_mapping.items()
        )
    return _itoa_collection_map_for_itoa_object.get(object_type)

_itoa_secure_object_enforcer_cls = None
def get_secure_object_enforcer_cls():
    """
    Method to provide the class in ITSI implementation that will enforce security on securable objects.
    In ITSI this is done via security groups.

    @rtype: class
    @return: class that implement security enforcement
    """
    global _itoa_secure_object_enforcer_cls
    if _itoa_secure_object_enforcer_cls is None:
        from itsi.objects.itsi_security_group import ItsiSecGrp
        _itoa_secure_object_enforcer_cls = ItsiSecGrp
    return _itoa_secure_object_enforcer_cls
