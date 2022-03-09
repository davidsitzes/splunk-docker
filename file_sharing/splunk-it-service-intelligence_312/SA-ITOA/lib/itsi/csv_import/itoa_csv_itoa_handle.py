from itsi.objects.itsi_entity import ItsiEntity
from itsi.objects.itsi_service import ItsiService


def _makeItsiObjectWithOwner(name, parent):
    '''
    A simple metaclass for single-session transactions with the ITOA 
    object protocol in which the owner never changes.
    '''
    def __init__(self, session_key, current_user_name, owner=None):
        super(objecttype, self).__init__(session_key, current_user_name)
        self._owner = owner

    def save_batch(self, *args, **kwargs):
        super(objecttype, self).save_batch(*([self._owner] + args), **kwargs)

    def get_bulk(self, *args, **kwargs):
        super(objecttype, self).get_bulk(*([self._owner] + args), **kwargs)

    def get(self, *args, **kwargs):
        super(objecttype, self).get(*([self._owner] + args), **kwargs)

    return type(name, (parent,), {
        '__init__': __init__,
        'save_batch': save_batch,
        'get_bulk': get_bulk,
        'get': get
    });

ItsiServiceOnce = _makeItsiObjectWithOwner('ItsiServiceOnce', ItsiService)
ItsiEntityOnce = _makeItsiObjectWithOwner('ItsiEntityOnce', ItsiEntity)


class ItoaHandle(object):
    def __init__(self, owner, session_key, current_user):
        self.owner = owner
        self.session_key = session_key
        self.current_user = current_user

    def __call__(self, objecttype):
        return {
            SERVICE: ItsiServiceOnce(self.session_key, self.current_user, owner=self.owner),
            ENTITY:  ItsiEntityOnce(self.session_key, self.current_user, owner=self.owner)
        }
