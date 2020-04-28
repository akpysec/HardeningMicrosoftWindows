import collections
import pandas as pd
import itertools

# Re-usable variables
STR_REG_HIVE = 'Registry Hive'
STR_REG_PATH = 'Registry Path'
STR_VALUE_NAME = 'Value Name'
STR_VALUE = 'Value'

# Reading STIG.csv file
df = pd.read_csv('win2012r2.csv')

# Setting id Column as index
df.index = df['id']

# Dropping the id Column
df.drop('id', axis=1, inplace=True)

# Setting sort by value order
df['severity'] = pd.Categorical(df['severity'], ['high', 'medium', 'low'])

# Changing data_frames order from high to low
df = df.sort_values('severity')

# Filtering out only the hardening values that have registry keys & values
df = df[df['checktext'].str.contains(STR_REG_HIVE)
        & df['checktext'].str.contains(STR_REG_PATH)
        & df['checktext'].str.contains(STR_VALUE_NAME)]

# Dropping un-necessary columns
df.drop(['iacontrols', 'ruleID', 'checkid', 'fixid'], axis=1, inplace=True)

# Setting view to view all rows
pd.set_option('display.max_rows', None)
# Setting view to view all columns
pd.set_option('max_columns', None)

# CHECK IF STRINGS ARE IN - df['checktext']
# The Strings:
key_names = [STR_REG_HIVE, STR_REG_PATH, STR_VALUE_NAME, STR_VALUE]

# The Check:
filteredData = list(filter(lambda x: any(True for c in key_names if c in x), df['checktext']))

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

test_list = list()


# Re-usable function to locate indexes in a list
def find_index(in_list: list, key: str):
    value_names_positions = [i for i in range(len(in_list)) if in_list[i] == key]
    return value_names_positions


for k, v in VAL_DICT.items():
    # CHECK FOR MISSING DATA & MULTIPLE OCCURRENCES
    # Listing first elements from a sub-lists
    FIRST_ELEMENT_SUB_LIST = [item[0] for item in v]
    # Checking first elements from a sub-list against 'key_names' list
    check = all(item in FIRST_ELEMENT_SUB_LIST for item in key_names)
    # Finding missing value & replacing it with a massage
    if check is False:
        # print(v)
        for element in key_names:
            if element not in FIRST_ELEMENT_SUB_LIST:
                element = [element, 'Attribute has no value']
                v.append(element)
    # Dealing with multiple occurrences of key-values
    if check is True:
        # Un-packing lists inside 'v' list
        v = list(itertools.chain(*v))

        # Checking if number of occurrences of 'Registry Hive' is greater than 1
        if v.count(key_names[0]) > 1:
            # Recovering indexes of 'Registry Hive' occurrences + Removing all that follows
            # This removes when you have 2 options for 2 different WIN versions
            del v[find_index(in_list=v, key=key_names[0])[1]:]

        # Checking if number of occurrences of 'Value Name' is greater than 1
        if v.count(key_names[2]) > 1:
            # Recovering indexes of 'Value Name' occurrences + Inserting values to -2 last objects
            for index in find_index(in_list=v, key=key_names[2]):
                v.insert(-2, v[index + 1])

        # Removing duplicates (this is for ---> Value Name, but removes all doubles, may cause trouble later)
        v = list(dict.fromkeys(v))

        # Locating & joining values that follow 'Value'
        if v[-2] != key_names[3]:
            values_join = v[find_index(in_list=v, key=key_names[3])[0] + 1:]
            values_join = ' '.join(values_join)
            del v[find_index(in_list=v, key=key_names[3])[0] + 1:]
            v.insert(find_index(in_list=v, key=key_names[3])[0] + 1, values_join)

        print(v)

        # Joining the multiple occurrences to become one object in a list
        # print(_v[5:-1])
        # print(_v)
        # print(_v.count(key_names[0]), _v.count(key_names[1]), _v.count(key_names[2]), _v.count(key_names[3]))

        # Appending to corresponding lists
        if v[0] == key_names[0]:
            REG_HIVE.append(v[1])
        if v[2] == key_names[1]:
            REG_PATH.append(v[3])
        if v[4] == key_names[2]:
            REG_NAME.append(v[5])
        if v[-2] == key_names[3]:
            REG_VALUE.append(v[-1])


# FOR TESTING
print(len(REG_HIVE), len(REG_PATH), len(REG_NAME), len(REG_VALUE))

# Creating 4 columns and adding corresponding data to each column
# df = df.assign(**{STR_REG_HIVE: REG_HIVE[0:193],
#                   STR_REG_PATH: REG_PATH[0:193],
#                   STR_VALUE: REG_VALUE[0:193],
#                   STR_VALUE_NAME: REG_NAME[0:193]})
#
# print(df)


# Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" | fl EnableScriptBlockLogging
