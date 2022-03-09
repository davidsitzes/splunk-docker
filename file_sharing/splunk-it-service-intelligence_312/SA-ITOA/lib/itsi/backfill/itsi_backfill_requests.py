# Copyright (C) 2005-2018 Splunk Inc. All Rights Reserved.
'''
This module handles backfill requests
'''
import copy
import json
from splunk.appserver.mrsparkle.lib import i18n
import splunk.rest as rest

from ITOA.storage.itoa_generic_persistables import ItoaGenericCrudException, ItoaGenericModel, ItoaGenericCollection
from ITOA.setup_logging import setup_logging

LOGGER = setup_logging("itsi_backfill_services.log","itsi.backfill")

class BackfillRequestModel(ItoaGenericModel):
    """
    Backfill request model class. Can be instantiated from data, or from an object
    _key (in which case it is auto-fetched from the server). Supports basic CRUD
    operations.

    The following fields are defined:

     - status: one of ['new', 'pending', 'running', 'done', 'failed', 'cancelled']
     - search
     - earliest
     - latest
     - kpi_id
     - kpi_title
     - job_progress: array of <nchunk> job_metadata objects.
                     This field created when job is added to the queue.
                     job_metadata objects are dicts with keys:
                     ('et', 'lt', 'num', 'tot', 'sid', 'job_status', 'retries_left')
     - t_start [not present in new/pending state]
     - t_finish [not present before completion]

    'status', 'search', 'earliest', 'latest', and 'kpi_id' fields are required on request creation.
    """

    backing_collection = "itsi_backfill"

    def __init__(self, *args, **kwargs):
        self.set_logger(LOGGER)
        super(BackfillRequestModel, self).__init__(*args, **kwargs)

    def __getitem__(self, key):
        return self.data.get(key, None)

    def __setitem__(self, key, item):
        self.data[key] = item

    def get(self, key, default=None):
        '''
        Get the attribute from the data dict
        Inherited from ItoaGenericModel
        @param key: String key for the attribute
        @param default: Default value if the value is not in the dict
        '''
        return self.data.get(key, default)

    @property
    def id_(self):
        '''
        Get the identifying attribute
        or None if not present.
        '''
        return self.data.get("_key", None)

    @property
    def earliest(self):
        '''
        Return the value of the earliest attribute
        case as an int
        Throws an exception if none
        '''
        return int(self.get("earliest"))

    @property
    def latest(self):
        '''
        Return the value of the earliest attribute
        case as an int
        Throws an exception if none
        '''
        return int(self.get("latest"))

    @property
    def job_progress(self):
        """
        Get job progress array. We need to ensure that index fields (such as `num` or `tot)
        and epoch fields (`et`, `lt`) get cast to integers. Note that we return a copy of the
        job_progress array so that non-JSON serializable objects can be added to this
        data structure by the clients without affecting this model.
        """
        jobs = self.get("job_progress", [])
        for j in jobs:
            j['et'] = int(j['et'])
            j['lt'] = int(j['lt'])
            j['num'] = int(j['num'])
            j['tot'] = int(j['tot'])
            j['retries_left'] = int(j['retries_left'])
        return [copy.copy(j) for j in jobs]

    def get_job_chunk(self, num):
        """
        Get job chunk from job process array; this method helps avoid 0/1 indexing confusion
        """
        return self.job_progress[num - 1]

    def update_job_progress(self, job_num, data):
        """
        Update progress for a job chunk

        @param job_num: job chunk number [1..total_jobs]
        @type: int

        @param data: fields to update
        @type: dict
        """
        if job_num > len(self.job_progress):
            raise ItoaGenericCrudException("Cannot update job progress")
        self.get('job_progress')[job_num - 1].update(data)
        self.save()

    def validate_data(self):
        """
        Model validation method. Checks that the model has the minimal set of required keys.
        """
        data = self.data
        required_keys = set(['status', 'search', 'earliest', 'latest', 'kpi_id'])
        valid = required_keys.issubset(set(data.keys()))
        if not valid:
            message = _("Required keys %s are missing from model data") % (required_keys - set(data.keys()))
            message += _("Got the following for data: %s") % data
            self.logger.error(message)
            raise ItoaGenericCrudException(message)
        return valid

    def is_backfillable(self):
        """
        Runs a search to determine whether this model should be backfilled or not.

        @returns: True if the model can be backfilled, False otherwise
        @rtype bool
        """
        kpi_id = self.get('kpi_id')
        url_path = '/servicesNS/nobody/SA-ITOA/search/jobs/export'
        params = {
            'output_mode': 'json',
            'exec_mode': 'oneshot',
            'search': 'search `get_full_itsi_summary_kpi(%s)` | tail 1 | eval earliestTime=_time' % kpi_id
        }

        try:
            server_response, server_content = rest.simpleRequest(url_path,
                                               sessionKey=self.interface._session_key,
                                               method='GET',
                                               getargs=params)

            # use the latest result from the streaming results and remove empty strings
            content_data = filter(None, server_content.split('\n'))
            latest_content = content_data[-1]
            content = json.loads(latest_content)
        except Exception, e:
            self.logger.error('Error while backfilling kpi %s: %s', kpi_id, e)
            return False

        result = content.get('result', None)

        if result is None:
            return True

        earliest_kpi_time = int(result.get('earliestTime'))
        earliest_epoch_time = self.get('earliest')
        if earliest_kpi_time < earliest_epoch_time:
            # no need to backfill
            return False

        try:
            alert_period = int(self.get('alert_period'))
        except (TypeError, ValueError) as e:
            # assume that the latest time has alert_period already accounted for
            return True

        # set latest time for backfill to earliest time in summary index
        latest_epoch_time = earliest_kpi_time - (alert_period * 60) - 1
        self.update({
            'latest': latest_epoch_time
        })

        return True


# pylint: disable=too-few-public-methods
class BackfillRequestCollection(ItoaGenericCollection):
    """
    Backfill request collection class. Supports bulk fetch, save, and delete
    operations on request objects.  Implements an iterable interface over
    `Request` objects.
    """

    backing_collection = "itsi_backfill"
    model_class = BackfillRequestModel

    def __init__(self, *args, **kwargs):
        self.set_logger(LOGGER)
        super(BackfillRequestCollection, self).__init__(*args, **kwargs)

