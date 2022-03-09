import re
from ITOA import itoa_common as utils
from ITOA.saved_search_utility import SavedSearch

class ItsiAtAdSearchBase(object):
    """
    Implements common functionality for operating on saved searches related
    to ITSI anomaly detection and adaptive thresholding features.

    Mostly contains CRUD operations and utility functions.
    """

    log_prefix = '[ITSI AD Search] '

    def __init__(self, session_key, logger=None):
        self.session_key = session_key
        if logger is None:
            self.logger = utils.get_itoa_logger('itsi.object.at_ad_search')
        else:
            self.logger = logger

    def _make_search_name_suffix(self, training_window_id):
        """
        Generate name for AD search stanza
        @param training_window_id: training window string
        @returns: name for AD search stanza
        """
        return 'search_kpi_{0}'.format(training_window_id.replace("-", "minus").replace(" ", ""))

    def _get_all_searches(self, filter_func):
        """
        @param filter_func: boolean-valued function; if returns True when applied to saved search stanza name,
          include it in the output
        @returns: dict of saved searches keyed by stanza name
        """
        saved_searches = {}
        results = utils.get_conf(self.session_key, 'savedsearches')
        if (utils.is_valid_dict(results)
            and utils.is_valid_dict(results.get('response'))
            and utils.is_valid_str(results['response'].get('status'))
            and (results['response']['status'] == '200')):
            content = utils.validate_json('', results.get('content', []))
            # Filter down to KPI saved searches and hash by ID
            for saved_search in content.get('entry', []):
                if not filter_func(saved_search['name']):
                    continue
                saved_searches[saved_search['name']] = saved_search
        return saved_searches

    def to_minutes(self, timespec):
        """
        Convert a limited set of time specifiers to minutes
        @param timespec: relative time specifier string of the form '-<num><unit>' where unit is one of 'm', 'd', 'h', 'w'
        """
        to_minutes = {'m': 1, 'h': 60, 'd': 1440, 'w': 10080}
        m = re.match(r"-(\d+)([dhmw])", timespec)
        units = m.group(2)
        return int(m.group(1)) * to_minutes[units]

    def to_days(self, timespec):
        """
        Convert a limited set of time specifiers to days, rounded down to an integer number
        @param timespec: relative time specifier string of the form '-<num><unit>' where unit is one of 'm', 'd', 'h', 'w'
        """
        return self.to_minutes(timespec) / 1440

    def make_saved_search_params(self, name, search, et, kpi_list):
        """
        Helper method to create KV pairs for the saved search stanza. Must be implemented by subclasses.

        @param name: search stanza name
        @param search: search string
        @param et: earliest time (relative timespec)
        @param kpi_list: list of KPI IDs
        @returns: dict of key/value pairs for the saved search stanza
        """
        raise NotImplementedError()

    def _parse_response(self, response, success_msg, err_msg):
        if not (int(response.get('status')) == 200 or int(response.get('status')) == 201):
            self.logger.debug(err_msg)
            return False
        else:
            self.logger.debug(success_msg)
            return True

    def create_saved_search(self, search_name, search_string, et, kpi_list):
        """
        Create AD or AT search stanza
        @param search_name: search stanza name
        @param search_string: saved search to write
        @param et: dispatch earliest time
        @param kpi_list: list of KPI IDs
        @returns: boolean indicating operation success
        """
        stanza = self.make_saved_search_params(name=search_name,
                                               search=search_string,
                                               et=et, kpi_list=kpi_list)
        result = SavedSearch.update_search(self.session_key, search_name, 'itsi', 'nobody', **stanza)
        if result:
            self.logger.info("Successfully created saved search=%s", search_name)
        else:
            self.logger.error("Failed to create search=%s", search_name)
        return result

    def update_saved_search(self, search_name, search_string, et, kpi_list):
        """
        Update AD or AT search stanza
        @param search_name: search stanza name
        @param search_string: saved search to write
        @param et: dispatch earliest time
        @param kpi_list: list of KPI IDs
        @returns: boolean indicating operation success
        """
        stanza = self.make_saved_search_params(name=search_name,
                                               search=search_string,
                                               et=et, kpi_list=kpi_list)
        result = SavedSearch.update_search(self.session_key, search_name, 'itsi', 'nobody', **stanza)
        if result:
            self.logger.info("Successfully updated saved search=%s", search_name)
        else:
            self.logger.error("Failed to update saved search=%s", search_name)
        return result

    def delete_saved_search(self, search_name):
        """
        Delete AD or AT search stanza
        @param search_name: search stanza name
        @returns: boolean indicating operation success
        """
        result = SavedSearch.delete_search(self.session_key, search_name)
        if result:
            self.logger.info("Successfully deleted saved search=%s", search_name)
        else:
            self.logger.error("Failed to delete saved search=%s", search_name)
        return result
