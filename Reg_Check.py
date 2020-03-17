from termcolor import colored
import stig
from Map_Regs import reg_keys_to_human

insides = [
    "checkid"
    "checktext"
    "description"
    "fixid"
    "fixtext"
    "iacontrols"
    "id"
    "ruleID"
    "severity"
    "title"
    "version"
]

cats = stig.win_server_2012_r2.get('stig')['findings']


def user_interaction():
    while True:
        try:
            server_version = int(input('1) Server 2008 R2\n2) Server 2012 R2:\n>'))
            if server_version == 1:
                cat = stig.win_server_2008_r2.get('stig')['findings']
                return cat
            elif server_version == 2:
                cat = stig.win_server_2012_r2.get('stig')['findings']
                return cat
        except (TypeError, ValueError) as type_value_error:
            print(f'Error: {type_value_error}')


def get_item_property():
    new_listing = list()
    for k, v in cats.items():

        if v.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
            # print(colored("*" * 100, 'yellow'))
            raw_list.append(v.get('checktext').strip('\n'))

            for item in raw_list:
                for i in item.split('\n'):
                    if i.__contains__('Registry Path'):
                        keys = 'Get-ItemProperty -Path "HKLM:' + i.split(': ')[1].lstrip(' ') + '"'
                        new_listing.append(keys)
                    elif i.__contains__('Value Name'):
                        values = i.split(': ')[1]
                        values = ' | fl ' + values + '\n'
                        new_listing.append(values)

    new_list = (list(filter(None, new_listing)))

    # print(''.join(new_list).strip('\n'))
    return ''.join(new_list).strip('\n')


def read_pulled_txt(file_name: str):
    only_configs = list()
    pulled_configs_dict = dict()
    with open(file_name, 'r') as pulled:
        for line in pulled.readlines():
            only_configs.append(line.strip('\n').split(' : '))
    for item in only_configs:
        if item != ['']:
            if len(item) > 1:
                key = item[0].lower()
                value = item[1]
                config_dict = {key: value}
                pulled_configs_dict.update(config_dict)

    return pulled_configs_dict


def combine_checks():
    new_listing = list()
    total_dict = dict()
    for k, v in cats.items():

        if v.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
            raw_list.append(v.get('checktext').strip('\n'))

            for item in raw_list:
                for i in item.split('\n'):
                    if i.__contains__('Value Name'):
                        values = i.split(': ')[1]
                        values = values.lstrip(' ').lower()
                        new_listing.append(values)
                        combo = {values: v.get('title').strip('.')}
                        total_dict.update(combo)

    return total_dict


def if_er_engine():
    pulled_from_server = read_pulled_txt(file_name='pulled.txt')

    vals = {'0': 'Disabled', '1': 'Enabled'}

    for ks in combine_checks().keys():
        if ks in pulled_from_server.keys():
            length = len(combine_checks().get(ks))
            if vals.get(pulled_from_server.get(ks)) is None:
                print(combine_checks().get(ks), colored(pulled_from_server.get(ks), 'cyan'))
                print(colored("*" * length, 'yellow'))
            else:
                print(combine_checks().get(ks), '-', colored(vals.get(pulled_from_server.get(ks)), 'magenta'))
                print(colored("*" * len(combine_checks().get(ks)), 'yellow'))


# if_er_engine()
# print(get_item_property())

f_in_list = list()
for key, value in read_pulled_txt(file_name='pulled_massive.txt').items():
    # print(k, v)
    if reg_keys_to_human.get(key) is None:
        print(colored(f'Missing mapping for - {key}:', 'red'), colored(value, 'cyan'))
        new = key + '~ ' + value
        f_in_list.append(new)
    else:
        print(reg_keys_to_human.get(key), colored(value, 'cyan'))
        old = reg_keys_to_human.get(key) + '~ ' + value
        f_in_list.append(old)

for f in sorted(f_in_list):
    print(f)
