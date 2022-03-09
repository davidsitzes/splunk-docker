from . import itoa_change_handler

class ExampleChangeHandler(itoa_change_handler.ItoaChangeHandler):
    """
    Do nothing change handler that exists for testing purposes
    """

    def assess_impacted_objects(self, change, transaction_id=None):
        #make up some random objects...
        return {"test_object": ["1","2"]}

    def update_impacted_objects(self, change, impacted_objects, transaction_id=None):
        #oh yeah those objects are totally good now no worries.
        return True
