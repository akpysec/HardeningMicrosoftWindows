import pandas as pd

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

# Checks if Strings are in df['checktext']
# The Strings:
key_names = [STR_REG_HIVE, STR_REG_PATH, STR_VALUE_NAME, STR_VALUE]
# The Check:
filteredData = list(filter(lambda x: any(True for c in key_names if c in x), df['checktext']))

# Filtering key names values ONLY to a list
VALUES = list()
for each in filteredData:
    each = each.split('\n')
    for e in each:
        e = e.strip('\r')
        if len(e.split(':')) >= 2:
            filteredNone = list(filter(None, e.split(':')))
            if len(filteredNone) == 2:
                filteredNone = [filteredNone[0], filteredNone[1].lstrip(' ')]
                if filteredNone[0] in key_names:
                    VALUES.append(filteredNone)

# 4 lists for each type of Data that extracted from 'values' list
REG_HIVE = list()
REG_PATH = list()
REG_NAME = list()
REG_VALUE = list()

for v in VALUES:
    if v[0] == key_names[0]:
        REG_HIVE.append(v[1])
    elif v[0] == key_names[1]:
        REG_PATH.append(v[1])
    elif v[0] == key_names[2]:
        REG_NAME.append(v[1])
    elif v[0] == key_names[3]:
        REG_VALUE.append(v[1])

# Creating 4 columns and adding corresponding data to each column
df = df.assign(**{STR_REG_HIVE: REG_HIVE[0:193],
                  STR_REG_PATH: REG_PATH[0:193],
                  STR_VALUE: REG_VALUE[0:193],
                  STR_VALUE_NAME: REG_NAME[0:193]})

print(len(REG_HIVE), len(REG_PATH), len(REG_VALUE), len(REG_NAME))



# Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" | fl EnableScriptBlockLogging
