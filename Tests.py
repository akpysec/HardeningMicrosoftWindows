# Version 1.00
# To get .csv hardening guides go to "https://www.stigviewer.com/stigs"

import collections
import pandas as pd
import itertools


# Re-usable function to locate indexes in a list
def find_index(in_list: list, key: str):
    value_names_positions = [i for i in range(len(in_list)) if in_list[i] == key]
    return value_names_positions


# Re-usable function to locate duplicate objects in a list
def check_duplicates(list_of: list):
    """ Check if given list contains any duplicates """
    for elem in list_of:
        if list_of.count(elem) > 1:
            return True
    return False


def csv_parser(file_name: str):
    """Function takes a FileName in .csv format as a parameter & parses it to a DataFrame for further use"""

    # Re-usable variables
    STR_REG_HIVE = 'Registry Hive'
    STR_REG_PATH = 'Registry Path'
    STR_REG_PATHS = 'Registry Paths'
    STR_VALUE_NAME = 'Value Name'
    STR_VALUE = 'Value'
    MISSING_ATTRIBUTE = 'Attribute has no value'

    # Reading STIG.csv file
    main_frame = pd.read_csv(file_name)

    # Setting id Column as index
    main_frame.index = main_frame['id']

    # Dropping the id Column
    main_frame.drop('id', axis=1, inplace=True)

    # Setting sort by value order
    main_frame['severity'] = pd.Categorical(main_frame['severity'], ['high', 'medium', 'low'])

    # Changing data_frames order from high to low
    main_frame = main_frame.sort_values('severity')

    # Filtering out only the hardening values that have registry keys & values
    main_frame = main_frame[main_frame['checktext'].str.contains(STR_REG_HIVE)
                            & main_frame['checktext'].str.contains(STR_REG_PATH)
                            & main_frame['checktext'].str.contains(STR_VALUE_NAME)]

    secondary_frame = main_frame['checktext'].str.contains(STR_REG_PATHS)

    merged_Frames = pd.concat([main_frame, secondary_frame])

    # Dropping un-necessary columns
    main_frame.drop(['iacontrols', 'ruleID', 'checkid', 'fixid'], axis=1, inplace=True)

    # Setting view to view all rows
    pd.set_option('display.max_rows', None)
    # Setting view to view all columns
    pd.set_option('max_columns', None)

    # CHECK IF STRINGS ARE IN - frame_1['checktext']
    # The Strings:
    key_names = [STR_REG_HIVE, STR_REG_PATH, STR_VALUE_NAME, STR_VALUE]

    # The Check in main frame:  CHECK FOR SECONDARY FRAME IS NOT DONE YET (there's a series with 4 registry paths)
    filteredData = list(filter(lambda x: any(True for c in key_names if c in x), main_frame['checktext']))

    # Filtering key names values ONLY to a list
    VALUES = list()
    COUNT = 0
    VAL_DICT = collections.defaultdict(list)

    for each in filteredData:
        each = each.split('\n')
        COUNT = COUNT + 1
        for e in each:
            e = e.strip('\r')
            if len(e.split(':')) >= 2:
                filteredNone = list(filter(None, e.split(':')))
                if len(filteredNone) == 2:
                    filteredNone = [filteredNone[0], filteredNone[1].lstrip(' ')]
                    if filteredNone[0] in key_names:
                        VALUES.append(filteredNone)
                        VAL_DICT[COUNT].append(filteredNone)

    # 4 lists for each type of Data that extracted from 'values' list
    REG_HIVE = list()
    REG_PATH = list()
    REG_NAME = list()
    REG_VALUE = list()

    for k, v in VAL_DICT.items():
        # CHECK FOR MISSING DATA & MULTIPLE OCCURRENCES

        # Un-packing lists inside 'v' list
        v = list(itertools.chain(*v))

        # Listing elements from a list 'v'
        FIRST_ELEMENT_SUB_LIST = [item for item in v]

        # Checking first elements from a 'v' list against 'key_names' list
        check = all(item in FIRST_ELEMENT_SUB_LIST for item in key_names)

        # Finding missing value & replacing it with a massage
        if check is False:
            for element in key_names:
                if element not in FIRST_ELEMENT_SUB_LIST:
                    if element == key_names[0]:
                        v.insert(0, element), v.insert(1, MISSING_ATTRIBUTE)
                    elif element == key_names[1]:
                        v.insert(2, element), v.insert(3, MISSING_ATTRIBUTE)
                    elif element == key_names[2]:
                        v.insert(5, element), v.insert(6, MISSING_ATTRIBUTE)
                    elif element == key_names[3]:
                        v.insert(7, element), v.insert(8, MISSING_ATTRIBUTE)

            # Join multiple occurrences to one object in from 'Value Name' object in list until 'Value' object in a list
            v.insert(-2, ', '.join(
                v[find_index(in_list=v, key=key_names[2])[0] + 1: find_index(in_list=v, key=key_names[3])[0]]))
            del v[find_index(in_list=v, key=key_names[2])[0] + 1: -3]

            # Appending to corresponding lists
            if v[0] == key_names[0]:
                REG_HIVE.append(v[1])
            if v[2] == key_names[1]:
                REG_PATH.append(v[3])
            if v[4] == key_names[2]:
                REG_NAME.append(v[5])
            if v[-2] == key_names[3]:
                REG_VALUE.append(v[-1])

        # Dealing with multiple occurrences of key-values
        # Moving multiple occurrences to dictionary for ease of handling
        if check is True:
            if check_duplicates(v) is True:
                print(check)
                # Creating dictionary without duplicates
                TEST = collections.defaultdict(set)
                for key in key_names:
                    if v.count(key) > 1 or v.count(key) > 1 or v.count(key) > 1:
                        indices = [i for i, x in enumerate(v) if x == key]
                        for i in indices:
                            TEST[key].add(v[i + 1])
                # Create a list from dictionary (without duplicates) + turn sets to lists
                s = [[k, list(v)] for k, v in TEST.items()]
                # Dropping outside list brackets
                if s:
                    v = list(itertools.chain(*s))
                    if v[0] != key_names[0]:
                        v.insert(0, MISSING_ATTRIBUTE), v.insert(1, MISSING_ATTRIBUTE)
                    if v[2] != key_names[1]:
                        v.insert(2, MISSING_ATTRIBUTE), v.insert(3, MISSING_ATTRIBUTE)
                    if v[4] != key_names[2]:
                        v.insert(4, MISSING_ATTRIBUTE), v.insert(5, MISSING_ATTRIBUTE)
                    if v[-2] != key_names[3]:
                        v.insert(-2, MISSING_ATTRIBUTE), v.insert(-1, MISSING_ATTRIBUTE)

                # Appending to corresponding lists
                if v[0] == key_names[0]:
                    REG_HIVE.append(v[1][0])
                if v[2] == key_names[1]:
                    REG_PATH.append(v[3][0])
                if v[4] == key_names[2]:
                    REG_NAME.append(v[5][0])
                if v[-2] == key_names[3]:
                    REG_VALUE.append(v[-1][0])

            if check_duplicates(v) is False:
                print(check)
                # Appending to corresponding lists
                if v[0] == key_names[0]:
                    REG_HIVE.append(v[1])
                if v[2] == key_names[1]:
                    REG_PATH.append(v[3])
                if v[4] == key_names[2]:
                    REG_NAME.append(v[5])
                if v[-2] == key_names[3]:
                    REG_VALUE.append(v[-1])

    # FOR TESTING PURPOSES
    print(len(REG_HIVE), len(REG_PATH), len(REG_NAME), len(REG_VALUE))
    print(len(main_frame.index))

    # Creating 4 columns and adding corresponding data to each column
    # main_frame = main_frame.assign(**{STR_REG_HIVE: REG_HIVE[0:],
    #                                   STR_REG_PATH: REG_PATH[0:],
    #                                   STR_VALUE: REG_VALUE[0:],
    #                                   STR_VALUE_NAME: REG_NAME[0:]})

    # print(frame_1)
    # frame_1.to_csv('file_name')
    return main_frame


# Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" | fl EnableScriptBlockLogging
def create_ps_script(data_frame: pd.DataFrame):
    """Function takes DataFrame as a parameter & creates a PowerShell script for auditing"""
    return


def ps_script_output_check(data_frame: pd.DataFrame):
    """Function takes DataFrame as a parameter & runs auditing check over PS script output file against taken
    parameter"""
    return


def local_host_check(data_frame: pd.DataFrame):
    """Function takes DataFrame as a parameter & runs auditing check locally against taken parameter"""
    return


csv_parser(file_name='hardening_guides\\Windows 10 Security Technical Implementation Guide-MAC-3_Sensitive.csv')
