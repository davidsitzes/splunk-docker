# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.

from splunk.appserver.mrsparkle.lib import i18n
import copy
import logging
import time

from ITOA.itoa_common import is_valid_dict, is_valid_list, is_valid_str
from ITOA.storage.itoa_storage import ITOAStorage 

class ItoaGenericCrudException(Exception):
    pass

class ItoaStorageInterfaceAdapter(object):
    """
    State store interface adapter

    Proxies the state store CRUD operations. Most of the time, returns
    the statestore response directly; for the `get` method, normalize the
    response to always be a list.
    """

    def __init__(self, session_key, collection_name, owner="nobody", namespace=None, object_type=None, **kwargs):
        """
        @param session_key: splunkd session key
        @param collection_name: collection name as configured in collections.conf
        @param owner: owner (defaults to `nobody`)
        @param namespace: app namespace where the collection is defined
        @param object_type: [optional] ITSI object type; ITOA kv crud methods expect this argument; defaults to `itoa_generic_object`
        @param **kwargs: arguments to pass on to itoa_storage initializer; allowed args: `splunkd_host_path`, `splunkd_port`
        """
        self._session_key = session_key
        self._owner = owner
        self._object_type = object_type or "itoa_generic_object"
        self._itoa_storage = ITOAStorage(collection=collection_name, namespace=namespace, **kwargs)
        if not self._itoa_storage.wait_for_storage_init(self._session_key):
            raise ItoaGenericCrudException(_("KV store is unavailable."))

    def create(self, data):
        """
        @param data: object to write to the statestore
        @type: dict
        """
        return self._itoa_storage.create(self._session_key, self._owner, self._object_type, data)

    def get(self, identifier=None, filter_data=None, **kwargs):
        """
        Proxies state store object retrieval; ensures the result is always a
        list of dictionaries. All arguments are optional; empty arg list results in
        fetching the full collection.

        @param identifier: _key (if retrieving object by ID)
        @type: string

        @param filter_data: filter data object (if retrieving a set of objects)
        @type: dict

        @rtype: list
        @returns list of matched objects from the state store if using filter_data, or a
                 single-element list if querying by id
        """
        if identifier is not None:
            response = self._itoa_storage.get(self._session_key, self._owner, self._object_type, identifier)
        else:
            response = self._itoa_storage.get_all(self._session_key, self._owner, self._object_type, filter_data=filter_data, **kwargs)
        if is_valid_dict(response):
            return [response] if len(response) > 0 else []
        elif response is None:
            return []
        elif is_valid_list(response):
            return response
        else:
            raise ItoaGenericCrudException(_("Invalid response received from the backend."))

    def edit(self, identifier, data):
        """
        @param identifier: _key of the object to edit
        @type: string

        @param data: edit data
        @type: dict
        """
        return self._itoa_storage.edit(self._session_key, self._owner, self._object_type, identifier, data)

    def delete(self, identifier):
        """
        @param identifier: _key of the object to delete
        @type: string
        """
        return self._itoa_storage.delete(self._session_key, self._owner, self._object_type, identifier)

class ItoaGenericPersistableBase(object):
    """
    Abstract base class for an ITOA persistable object.
    """
    backing_collection = None
    object_type = "itoa_generic_object"

    def __init__(self, logger=None, interface=None, session_key=None, owner="nobody", namespace=None, **kwargs):
        """
        @param logger [optional]: class logger; defaults to a dummy logger
        @type: logging.logger

        @param interface: interface reference
        @type: ItoaStorageInterfaceAdapter

        @param session_key: splunkd session key
        @type: string

        @param owner [optional]: owner; defaults to `nobody`
        @type: string

        @param namespace [optional]: app namespace; default defined in itoa_storage interface
        @type: string

        @param **kwargs [optional]: optional kwargs passed down to storage interface
        """
        if self.backing_collection is None:
            raise ItoaGenericCrudException(_("KV store collection name must be supplied as a class variable."))
        if logger is not None:
            self.logger = logger
        elif not hasattr(self, 'logger'): # in case a subclass initializer already gave us a logger
            self.logger = logging.getLogger('__DUMMY')
        # Initialize the storage interface
        if interface is not None:
            self._interface = interface
        elif session_key is not None and owner is not None:
            self._interface = ItoaStorageInterfaceAdapter(session_key, self.backing_collection,
                                                          owner=owner, object_type=self.object_type, namespace=namespace,
                                                          **kwargs)
        else:
            raise ItoaGenericCrudException(_("Either interface or session key/owner must be provided."))

    @property
    def interface(self):
        return self._interface

    @classmethod
    def initialize_interface(cls, session_key, owner="nobody", namespace=None, **kwargs):
        """
        Class-level method to instantiate `ItoaStorageInterfaceAdapter` class for a given KV store collection.
        The returned object can be used when initializing `ItoaGenericModel` and `ItoaGenericCollection` objects.
        This is more efficient than initializing those objects from a sesion key, which always creates a new instance
        of `ItoaStorageInterfaceAdapter`.

        @param session_key: splunkd session key
        @type: string

        @param owner [optional]: owner; defaults to `nobody`
        @type: string

        @returns an instance of `ItoaStorageInterfaceAdapter`
        @rvalue: `ItoaStorageInterfaceAdapter`
        """
        return ItoaStorageInterfaceAdapter(session_key, cls.backing_collection, owner, namespace, cls.object_type, **kwargs)

    def set_logger(self, logger):
        """
        @param logger: logger to use for this class
        @type: logging.logger
        """
        self.logger = logger

    def fetch(self):
        raise NotImplementedError(_("Attempting to call an abstract method"))

    def save(self):
        raise NotImplementedError(_("Attempting to call an abstract method"))



class ItoaGenericModel(ItoaGenericPersistableBase):
    """
    Itoa generic persistable model class. Can be instantiated from data, or from an object
    _key (in which case it is auto-fetched from the server). Supports basic CRUD
    operations.
    """

    def __init__(self, data, key=None, collection=None, _fetch=False, **kwargs):
        """
        Either `ItoaStorageInterfaceAdapter` reference or session_key/owner
        params must be supplied on instantiation.

        @param data: dict of parameters for this model
        @type: dict

        @param key [optional]: custom key if one must be specified on object creation.
                               DO NOT use`data._key` for this!
        @type: string

        @param logger [optional]: class logger
        @type: logging.logger

        @param interface: interface reference
        @type: ItoaStorageInterfaceAdapter

        @param session_key: splunkd session key
        @type: string

        @param owner [optional]: owner; defaults to `nobody`
        @type: string

        @param collection: collection to associate with this model. If this
          parameter is specified, deletions result in removal of this model reference
          from the collection.
        @type: ItoaGenericCollection

        @param _fetch: auto-fetch flag; used internally by alternative constructors
        @type: bool
        """
        super(ItoaGenericModel, self).__init__(**kwargs)
        self.data = copy.copy(data)
        self._user_supplied_key = key
        self._collection = collection
        if _fetch:
            self.fetch()

    @classmethod
    def fetch_from_key(cls, key, collection=None, **kwargs):
        """
        Constructor that allows to construct a model object from _key alone;
        fetches the object from the backend automatically.

        @param key: object id
        @type: string

        @param interface: interface reference
        @type: ItoaStorageInterfaceAdapter

        @param session_key: splunkd session key
        @type: string

        @param owner: owner (optional; defaults to `nobody`)
        @type: string

        @param collection: collection to associate with this model. If this
          parameter is specified, deletions result in removal of this model reference
          from the collection.
        @type: ItoaGenericCollection
        """
        return cls({}, key=key, collection=collection, _fetch=True, **kwargs)

    def validate_data(self):
        """
        User-supplied validation method. Default one always returns `True`
        Validation runs on both fetch and create (possibly before the model is persisted
        to the server, thus there should be no assumptions about the presence of server-
        generated fields).
        """
        return True

    @property
    def is_new(self):
        """
        The object is defined to be new if it contains the `_key` field. If the key is specified
        but the model with this key does not actually exist on the server, CRUD operations will fail.

        @returns is_new status
        @rtype: bool
        """
        return '_key' not in self.data or not is_valid_str(self.data['_key'])

    def _create(self):
        if not self.validate_data():
            raise ItoaGenericCrudException(_("Failed to create model: data validation failed."))
        # explicitly set the _key field if the user chooses to do so
        if self._user_supplied_key:
            self.data["_key"] = self._user_supplied_key
        response = self._interface.create(self.data)
        if response and response.has_key("_key"):
            self.data.update(response)
            return self.data
        else:
            raise ItoaGenericCrudException(_("Failed to create model."))

    def _update(self):
        response = self._interface.edit(self.data["_key"], self.data)
        if not (is_valid_dict(response) and response.has_key("_key")):
            raise ItoaGenericCrudException(_("Failed to update model."))
        self.data.update(response)
        return self.data

    def update(self, data):
        """
        Updates the model object and saves it.

        @param data: dict of KV pairs to update the model with
        @type: dict

        @returns an updated model object
        @rtype: dict
        """
        self.data.update(data)
        return self.save()

    def save(self):
        """
        Persists the model object to the server.

        @returns the model object as a dict (including the _key returned by the server)
        @rtype: dict
        """
        try:
            if self.is_new:
                return self._create()
            else:
                return self._update()
        except Exception:
            self.logger.exception("Error saving model")
            raise ItoaGenericCrudException(_("Failed to save model."))

    def _ensure_key(self):
        """
        If this method returns True, a valid self.data["_key"] is now present.
        This method may be called from within CRUD operations in order to fall back on
        user-supplied key in case data["_key"] is msising.
        """
        if self.is_new and is_valid_str(self._user_supplied_key):
            self.data["_key"] = self._user_supplied_key
        return is_valid_str(self.data.get("_key", None))

    def fetch(self):
        """
        Fetches the model object from the server; updates internal state.

        @returns the model object as a dict
        @rtype: dict
        """
        try:
            if not self._ensure_key():
                raise ItoaGenericCrudException(_("Cannot fetch an unsaved model."))

            response = self._interface.get(self.data["_key"])
            assert len(response) > 0, "Empty response received"
            assert response[0].has_key("_key"), "Response missing _key field"
            self.data.update(response[0])
            assert self.validate_data(), "Failed to validate fetched response"
            return self.data
        except Exception as e:
            self.logger.exception("Error fetching model")
            raise ItoaGenericCrudException(_("Failed to fetch model: %s.") % e)

    def delete(self):
        """
        Removes the model from the server; if this model is associated
        with a collection, this object's reference is located in the collection and
        deleted.
        """
        try:
            if not self._ensure_key():
                self.logger.debug("Ignoring the delete() call for unsaved model with no user-provided keys")
                return

            res = self._interface.delete(self.data["_key"])
            if self._collection: # remove this model's reference
                idx = next((i for i, x in enumerate(self._collection) if x.data.get("_key", None) == self.data["_key"]), None)
                if idx is not None:
                    del self._collection[idx]
            return res
        except Exception:
            self.logger.exception("Error deleting model")
            raise ItoaGenericCrudException(_("Failed to delete model."))


class ItoaGenericCollection(ItoaGenericPersistableBase):
    """
    Generic collection class. Supports bulk fetch, save, and delete
    operations.  Implements an iterable interface over `ItoaGenericModel` objects.
    """

    model_class = ItoaGenericModel

    def __init__(self, *args, **kwargs):
        """
        Either `ItoaStorageInterfaceAdapter` reference or session_key/owner
        params must be supplied on instantiation.

        @param logger: class logger
        @type: logging.logger

        @param interface: interface reference
        @type: ItoaStorageInterfaceAdapter

        @param session_key: splunkd session key
        @type: string

        @param owner [optional]: owner; defaults to `nobody`
        @type: string
        """
        super(ItoaGenericCollection, self).__init__(*args, **kwargs)
        self._data = []

    def fetch(self, filters=None):
        """
        Fetches a set of model objects from the backend and stores them
        internally.

        @param filters: optional filterspec; if empty returns all objects
        @type: dict

        @returns: list of `ItoaGenericModel` objects (that is also stored internally)
        @rtype: list
        """
        try:
            response = self._interface.get(filter_data=filters)
            self._data = [self.model_class(
                data, interface=self._interface, collection=self
            ) for data in response]
            assert all(x.validate_data() for x in self._data), "Failed to validate data for some models"
            return self._data
        except Exception as exc:
            self.logger.exception("Error fetching collection")
            raise ItoaGenericCrudException(_("Failed to fetch collection: %s.") % exc)

    def save(self):
        """
        Iterates over the `ItoaGenericModel` objects saving them individually.
        """
        for req in self._data:
            req.save()

    def delete(self):
        """
        Iterates over the `ItoaGenericModel` objects deleting them.
        """
        # delete() on a model also deletes its reference from the
        # internal _data array, so it's only safe to iterate in reverse
        for i in xrange(len(self._data) - 1, -1, -1):
            self._data[i].delete()

    @property
    def models(self):
        "Public accessor to the internal array of `ItoaGenericModel`s"
        return self._data

    def __len__(self):
        return len(self._data)

    def __getitem__(self, i):
        return self._data[i]

    def __delitem__(self, i):
        "Removes model reference from the collection WITHOUT removing it from the server"
        return self._data.__delitem__(i)
