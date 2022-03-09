import json
import logging

from mad_util import MADRESTException
from mad_splunk_util import setup_logging

logger = setup_logging('mad_rest.log', 'mad_rest', level=logging.DEBUG)


class MADSavedSearchManager(object):

    def __init__(self, service):
        self.saved_searches = service.saved_searches
        self.indexes = service.indexes

    def check_index(self, output_dest):
        try:
            self.indexes.get(output_dest)
        except Exception:
            logger.exception("Exception looking up output index '%s'" % output_dest)
            logger.warn("Output index '%s' not found, MAD output may not get indexed" % output_dest)

    def get_spl(self, context):
        return " | ".join([context.search, "mad context=%s" % context.name, "collect index=%s" % context.output_dest, "where 1=2"])

    def create(self, context):

        self.check_index(context.output_dest)

        kwargs = {
            "cron_schedule": "* * * * *",
            "is_scheduled": True,
            "dispatch.earliest_time": "rt",
            "dispatch.latest_time": "rt",
            "dispatch.indexedRealtime": True,
            "disabled": True,
        }

        # Create a saved search
        try:
            self.saved_searches.create(context.name, self.get_spl(context), **kwargs)
        except Exception:
            err_msg = "Could not create saved search '%s' with \n %s" % (context.name, json.dumps(kwargs))
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=500)

    def update(self, new_context):

        self.check_index(new_context.output_dest)

        kwargs = {
            "search" :  self.get_spl(new_context),
            "disabled": new_context.disabled
        }

        try:
            saved_search = self.saved_searches[new_context.name]
            saved_search.update(**kwargs).refresh()
        except Exception:
            err_msg = "Could not update saved search '%s'" % new_context.name
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.ERROR, status_code=500)

    def delete(self, name):
        try:
            self.saved_searches.delete(name)
        except KeyError:
            logger.warn("Could not find saved search '%s'" % name)
        except Exception:
            err_msg = "Could not delete saved search '%s'" % name
            logger.exception(err_msg)
            raise MADRESTException(err_msg, logging.WARN, status_code=500)
