# Version 1.00
# To get .csv hardening guides go to "https://www.stigviewer.com/stigs"

import collections
import re

import pandas as pd
import itertools

# Re-usable strings
KEY_NAMES = [
    'Registry Hive',
    'Registry Path',
    'Value Name',
    'Value',
    'Registry Paths',
    'Attribute has no value'
]


# Re-usable function to locate indexes of an object in a list
def find_index(in_list: list, key: str):
    value_names_positions = [i for i in range(len(in_list)) if in_list[i] == key]
    return value_names_positions


# Re-usable function to locate all indexes of an object in a list
def get_indexes(in_list, element):
    index_pos_list = []
    index_pos = 0
    while True:
        try:
            # Search for item in list from indexPos to the end of list
            index_pos = in_list.index(element, index_pos)
            # Add the index position in list
            index_pos_list.append(index_pos)
            index_pos += 1
        except ValueError as e:
            break

    return index_pos_list


def csv_parser(STIG_file_name: str):
    """Function takes a FileName in .csv format as a parameter & parses it to a DataFrame for further use"""

    # Reading STIG.csv file
    main_frame = pd.read_csv(STIG_file_name)

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

        # Appending to lists that have a frame less than 8 objects (Avoiding trouble with PANDAS)
        if len(v) < 8:
            missing = [mis for mis in KEY_NAMES[0:4] if mis not in v]
            v.append(missing[0]), v.append(KEY_NAMES[-1])

        # Frames(lists) that have multiple values... was a brain-f*** for me
        if len(v) > 8:
            combining_values = collections.defaultdict(set)

            counting = [c for c in KEY_NAMES if v.count(c) > 1]
            for item in KEY_NAMES:
                keys_index = get_indexes(v, item)
                for r in keys_index:
                    combining_values[item].add(v[r + 1])

            combined_values_list = list()
            for key, value in combining_values.items():
                combined_values_list.append([key, list(value)])
            combined_values_list = list(itertools.chain(*combined_values_list))

            v = combined_values_list

        # Appending to DataFrame
        if counting == RIGHT_AMOUNT:
            REG_HIVE.append(v[1])
            REG_PATH.append(v[3])
            REG_NAME.append(v[5])
            REG_VALUE.append(v[7])
            # print(v)

        # Appending to DataFrame
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
                # print(v)

    # FOR TESTING PURPOSES
    # print(len(REG_HIVE), len(REG_PATH), len(REG_NAME), len(REG_VALUE))
    # print(REG_HIVE, REG_PATH, REG_NAME, REG_VALUE)
    # print(len(main_frame.index))

    # Creating 4 columns and adding corresponding data to each column
    main_frame = main_frame.assign(**{KEY_NAMES[0]: REG_HIVE[0:],
                                      KEY_NAMES[1]: REG_PATH[0:],
                                      KEY_NAMES[2]: REG_NAME[0:],
                                      KEY_NAMES[3]: REG_VALUE[0:]
                                      })

    # print(main_frame)
    # main_frame.to_csv('file_name')

    return main_frame


def create_ps_script(data_frame: pd.DataFrame, file_name: str, path: str):
    """Function takes DataFrame as a parameter & creates a PowerShell script for auditing"""
    with open(f'{file_name}.ps1', 'a') as transcript:
        transcript.writelines('$hostname=hostname\n$ErrorActionPreference="silentlycontinue"\nStart-Transcript -Path '
                              f'"{path}output_{file_name}.txt" -NoClobber\n\n')
        for path, name_value, title in zip(data_frame[KEY_NAMES[1]], data_frame[KEY_NAMES[2]], data_frame['title']):

            # UN-PACKING lists
            if type(path) == list or type(name_value) == list:
                if len(path) > 1:
                    for each_path in path:
                        # print(each_path, name_value[0])
                        transcript.writelines(
                            '# ' + title + '\n'
                            f'Get-ItemProperty -Path "HKLM:\\{each_path}" | Format-List "{name_value[0]}"' + '\n\n')
                if len(name_value) > 1:
                    for each_value in name_value:
                        # print(path[0], each_value)
                        transcript.writelines(
                            '# ' + title + '\n'
                            f'Get-ItemProperty -Path "HKLM:\\{path[0]}" | Format-List "{each_value}"' + '\n\n')

            # MISSING VALUES - FROM DataFrame - 'Registry Paths' - Needs to be handled in 'csv_parser' function
            if path == '':
                # print('path')
                pass

            # NO TROUBLES HERE
            if type(path) != list or type(name_value) != list:
                if path != '':
                    transcript.writelines(
                        '# ' + title + '\n'
                        f'Get-ItemProperty -Path "HKLM:\\{path}" | Format-List "{name_value}"' + '\n\n')
                    # print(f'Get-ItemProperty -Path "HKLM:\\{path}" | Format-List "{name_value}"' + '\n')
                    pass

        transcript.writelines('\nStop-Transcript\n')


def create_parsed_csv(data_frame: pd.DataFrame, file_name: str):
    """Writes to a .csv file with all exported values; Registry Hive, Registry Path, Value Name, Value"""
    data_frame.to_csv(f"{file_name}.csv")
    return


def ps_script_output_check(data_frame: pd.DataFrame, powershell_output: str):
    """Function takes DataFrame as a parameter & runs auditing check over PS script output file against taken
    parameter"""

    ids = list()
    output_values = list()
    output_value_names = list()

    with open(powershell_output, 'r', encoding='utf-8') as output:
        value = [v for v in data_frame['Value Name'] if len(v) > 1]
        value = [x.casefold() for x in value if type(x) != list]

        for line in output:
            line = line.strip('\n').split(':')
            if len(line) > 1:
                line[0] = line[0].strip(' ')
                line[1] = line[1].strip(' ')
                newD = data_frame.loc[data_frame[KEY_NAMES[2]].str.lower() == line[0].lower()]
                ids.append(list(newD.index))
                if line[0].casefold() in value:
                    output_values.append(line[1])
                    output_value_names.append(line[0])

    ids = list(itertools.chain(*ids))

    for idd, val, val_nam in zip(ids, output_values, output_value_names):
        print(data_frame.loc[idd, 'Value Name'], val_nam)
        # print(data_frame.loc[idd, 'Value'], '*****', val)     # STIG values retrieving

    # for i in value:
    #     print(i)
    #     if type(i) == list:
    #         pass
    #     elif type(i) != list:
    #         i = i.split()
    #         if i[0].startswith('0x'):
    #             print(int(i[0], 16))
    #         elif not i[0].startswith('0x'):
    #             print(i)
    #         print(i.split())
    # print(value)
    # return


# ps_script_output_check(data_frame=csv_parser(
#     STIG_file_name='hardening_guides\\Windows 10 Security Technical Implementation Guide-MAC-3_Sensitive.csv'),
#     powershell_output='output_transcript.txt')

create_ps_script(
    data_frame=csv_parser(
        STIG_file_name='hardening_guides\\'
                       'Windows 10 Security Technical Implementation Guide-MAC-3_Sensitive.csv'),
    file_name='transcript',
    path='K:\\Hardening_for_Microsoft_Windows\\')

# create_parsed_csv(data_frame=csv_parser('hardening_guides\\'
#                   'Windows 10 Security Technical Implementation Guide-MAC-3_Sensitive.csv'), file_name='TEST')
