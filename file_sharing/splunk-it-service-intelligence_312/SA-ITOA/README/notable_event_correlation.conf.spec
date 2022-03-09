[<stanza name>]
* stanza name should be custom alert name which user wants to include

black_list_fields = <string>
* List of field names in notable event whose value are discarded
* from consideration for event correlation by ACE framework

text_field_names = <string>
* List of field names in notable events that usually represent textual content
* of event data

ignore_fields_that_contain = <string>
* List of field names that needs to be implicitly ignored as they are not useful for event correlation

threshold_distinct_value_perc = <int>
* Threshold value for considering a NE fields as categorical field

min_distinct_value_perc = <int>
max_count_perc = <int>
* Threshold value for considering a NE fields as categorical field
* If the cumulative event sum of first min_distinct_value_perc of distinct
* count is contained in max_count_perc of count, the field is considered as categorical field

threshold_event_coverage_perc = <int>
* Threshold value to consider the field as text field

field_analyze_event_limit = <int>
* Limit on number of events that can be processed during field analysis

seed_group_event_limit = <int>
* Limit on number of events that can be processed during seed group generation