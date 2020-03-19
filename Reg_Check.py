from termcolor import colored
from STIG import win_server_2012_r2

cats = win_server_2012_r2.get('stig')['findings']


# Re-writes STIG title: value_name for human readable format
def get_stig_dictionary():
    computer_settings = dict()
    for ks, vs in cats.items():

        if vs.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
            titles = list()
            titles.append(vs.get('title'))
            # print(v.get('title'))

            raw_list.append(vs.get('checktext').strip('\n'))

            for item in raw_list:
                for i in item.split('\n'):
                    if i.__contains__('Value Name'):
                        values = i.split(': ')[1].strip(' ').lower()
                        in_dict = {vs.get('title'): values}
                        computer_settings.update(in_dict)
                        # print({v.get('title'): values})

    # print(computer_settings)
    return computer_settings


# Function to create a Get-ItemProperty command list for all the registry values
def get_item_property():
    new_listing = list()
    for kp, vp in cats.items():

        if vp.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
            raw_list.append(vp.get('checktext').strip('\n'))

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


# Function that reads the output from .txt exported file from .ps1 script with transcript
def read_pulled_txt(file_name: str):
    only_configs = list()
    pulled_configs_dict = dict()
    with open(file_name, 'r') as pulled:
        for line in pulled.readlines():
            only_configs.append(line.strip('\n').split(' : '))
    for item in only_configs:
        if item != ['']:
            if len(item) > 1:
                kee = item[0].lower()
                wal = item[1]
                config_dict = {kee: wal}
                pulled_configs_dict.update(config_dict)
    
    # print(pulled_configs_dict)
    return pulled_configs_dict


for key, value in read_pulled_txt(file_name='transcript.txt').items():
    for k, v in get_stig_dictionary().items():
        if key == v:
            print(k, value)
