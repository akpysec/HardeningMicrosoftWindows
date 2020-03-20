from termcolor import colored
from STIG import win_server_2012_r2

cats = win_server_2012_r2.get('stig')['findings']


def get_value(gett: str):

    """A function that returns best practice configs"""

    all_values = list()
    all_titles = list()

    for ks, vs in cats.items():
        if vs.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
            raw_list.append(vs.get('checktext').strip('\n'))

            for item in raw_list:
                for i in item.split('\n'):
                    if i.__contains__('Value:'):
                        all_values.append(i.strip('Value: ').lower())
                        all_titles.append(vs.get('title'))

    keys_values_harden = dict(zip(all_titles, all_values))
    # print(keys_values_harden)

    return keys_values_harden.get(gett)


def get_stig_dictionary():

    """Re-writes STIG title: value_name for human readable format"""

    computer_settings = dict()
    for ks, vs in cats.items():

        if vs.get('checktext').strip('\n').__contains__(':'):
            raw_list = list()
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


def get_item_property():

    """Function to create a Get-ItemProperty command list for all the registry values"""

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


def read_pulled_txt(file_name: str):

    """Function that reads the output from .txt exported file from .ps1 script with transcript"""

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


def dry_check():

    """Dumb Check to see what configs are not compliant with best practice"""

    not_compliant = dict()

    for key, value in sorted(read_pulled_txt(file_name='laptop.txt').items()):
        for k, v in get_stig_dictionary().items():
            # Default values check
            if key == v:
                if str(value) == get_value(gett=k):
                    # print(k, colored(value, 'blue'), colored(get_value(gett=k), 'green'))
                    pass
                elif str(value) != get_value(gett=k):
                    # print(k, colored(value, 'red'), colored(get_value(gett=k), 'green'))
                    temp_dict = {k: [value, get_value(k)]}
                    not_compliant.update(temp_dict)

    # print(not_compliant)
    return not_compliant


def wet_check():

    """A function to deal with findings from dry_check function"""

    shle = dict()

    for wet_key, wet_value in dry_check().items():

        best_practice = wet_value[1]
        setting_in_place = wet_value[0]

        # Stripping the "()" in an interesting way
        table = str.maketrans(dict.fromkeys("()"))
        parentheses_less = best_practice.translate(table)

        temp_list = parentheses_less.split(' ')
        if setting_in_place in temp_list:
            # print(wet_key, colored(setting_in_place, 'blue'), colored(temp_list[temp_list.index(setting_in_place)],
            # 'green'))
            pass
        # Shows only not matched
        elif setting_in_place not in temp_list:
            setting_in_place = setting_in_place.strip('{}')

            # Runs another check after one more stripping
            if setting_in_place not in temp_list:
                print(wet_key, colored(setting_in_place, 'red'), colored(temp_list, 'green'))

    print(shle)
    return shle


def super_wet_check():

    """Another function to clear the compliant settings and leave behind only non-compliant.
        this one has human (mine) logic in it"""

    wet_check()

    return


super_wet_check()
