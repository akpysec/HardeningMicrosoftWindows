# Version 1.00
# To get .csv hardening guides go to "https://www.stigviewer.com/stigs"

import collections
import pandas as pd
import itertools

# Re-usable strings
from ordered_set import OrderedSet

KEY_NAMES = [
    'Registry Hive',
    'Registry Path',
    'Value Name',
    'Value',
    'Registry Paths',
    'Attribute has no value'
]


# Re-usable function to locate indexes in a list
def find_index(in_list: list, key: str):
    value_names_positions = [i for i in range(len(in_list)) if in_list[i] == key]
    return value_names_positions


def find_duplicates(in_list: list):
    for elem in in_list:
        if in_list.count(elem) > 1:
            return True
    return False


def get_indexes(in_list, element):
    indexPosList = []
    indexPos = 0
    while True:
        try:
            # Search for item in list from indexPos to the end of list
            indexPos = in_list.index(element, indexPos)
            # Add the index position in list
            indexPosList.append(indexPos)
            indexPos += 1
        except ValueError as e:
            break

    return indexPosList


def csv_parser(file_name: str):
    """Function takes a FileName in .csv format as a parameter & parses it to a DataFrame for further use"""

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
    main_frame = main_frame[main_frame['checktext'].str.contains(KEY_NAMES[0])
                            & main_frame['checktext'].str.contains(KEY_NAMES[1])
                            & main_frame['checktext'].str.contains(KEY_NAMES[2])]

    # secondary_frame = main_frame['checktext'].str.contains(STR_REG_PATHS)
    # merged_Frames = pd.concat([main_frame, secondary_frame])

    # Dropping un-necessary columns
    main_frame.drop(['iacontrols', 'ruleID', 'checkid', 'fixid'], axis=1, inplace=True)

    # Setting view to view all rows
    pd.set_option('display.max_rows', None)
    # Setting view to view all columns
    pd.set_option('max_columns', None)

    # CHECK IF STRINGS ARE IN - main_frame['checktext']

    # The Check in main frame:  CHECK FOR SECONDARY FRAME IS NOT DONE YET (there's a series with 4 registry paths)
    filteredData = list(filter(lambda x: any(True for c in KEY_NAMES if c in x), main_frame['checktext']))

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
                    if filteredNone[0] in KEY_NAMES:
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

        # Dealing with missing data of key-values
        counting = [v.count(KEY_NAMES[0]), v.count(KEY_NAMES[1]), v.count(KEY_NAMES[2]), v.count(KEY_NAMES[3])]
        RIGHT_AMOUNT = list([1, 1, 1, 1])

        if len(v) < 8:
            missing = [mis for mis in KEY_NAMES[0:4] if mis not in v]
            v.append(missing[0]), v.append(KEY_NAMES[-1])

        if len(v) > 8:
            TEST = collections.defaultdict(set)
            # print('*' * 50)
            # print(v)

            counting = [c for c in KEY_NAMES if v.count(c) > 1]
            for item in KEY_NAMES:
                keys_index = get_indexes(v, item)
                for r in keys_index:
                    TEST[item].add(v[r + 1])

            TEST_LIST = list()
            for key, value in TEST.items():
                TEST_LIST.append([key, ', '.join(value)])
            TEST_LIST = list(itertools.chain(*TEST_LIST))

            v = TEST_LIST

        if counting == RIGHT_AMOUNT:
            REG_HIVE.append(v[1])
            REG_PATH.append(v[3])
            REG_NAME.append(v[5])
            REG_VALUE.append(v[7])
            # print(v)

        if counting != RIGHT_AMOUNT:
            if len(v) < 8:
                REG_HIVE.append(v[1])
                REG_PATH.append(v[3])
                REG_NAME.append(v[5])
                REG_VALUE.append(v[7])
                # print(v)
            if len(v) == 8:
                REG_HIVE.append(v[1])
                REG_PATH.append(v[3])
                REG_NAME.append(v[5])
                REG_VALUE.append(v[7])
                print(v)

    # FOR TESTING PURPOSES
    print(len(REG_HIVE), len(REG_PATH), len(REG_NAME), len(REG_VALUE))
    # print(REG_HIVE, REG_PATH, REG_NAME, REG_VALUE)
    print(len(main_frame.index))

    # Creating 4 columns and adding corresponding data to each column
    main_frame = main_frame.assign(**{KEY_NAMES[0]: REG_HIVE[0:],
                                      KEY_NAMES[1]: REG_PATH[0:],
                                      KEY_NAMES[2]: REG_NAME[0:],
                                      KEY_NAMES[3]: REG_VALUE[0:]
                                      })

    print(main_frame)
    # frame_1.to_csv('file_name')

    return main_frame


csv_parser(file_name='hardening_guides\\Windows 10 Security Technical Implementation Guide-MAC-3_Sensitive.csv')

# Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" | fl EnableScriptBlockLogging
# def create_ps_script(data_frame: pd.DataFrame):
#     """Function takes DataFrame as a parameter & creates a PowerShell script for auditing"""
#     return
#
#
# def ps_script_output_check(data_frame: pd.DataFrame):
#     """Function takes DataFrame as a parameter & runs auditing check over PS script output file against taken
#     parameter"""
#     return
#
#
# def local_host_check(data_frame: pd.DataFrame):
#     """Function takes DataFrame as a parameter & runs auditing check locally against taken parameter"""
#     return
