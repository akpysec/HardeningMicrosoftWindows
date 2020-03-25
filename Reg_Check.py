from termcolor2 import colored
from STIG import win_server_2012_r2
from Misc import miscellaneous
import colorama
colorama.init()

cats = win_server_2012_r2.get('stig')['findings']

transcript = 'file_name.txt'
utf = 'utf-16'


# transcript = str(input('Put the output file from PowerShell script in the same folder as this script,\n'
#                        'Enter file name (with extension) to run the Best Practice Check:\n>'))


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


def get_severity(gett: str):
    """Function to get Severity level for the Settings"""

    main_dict = dict()

    for sev_key, sev_value in cats.items():
        all_severities = sev_value.get('severity')
        all_titles = sev_value.get('title')
        temp_dict = {all_titles: all_severities.upper()}
        main_dict.update(temp_dict)

    # print(main_dict)

    return main_dict.get(gett)


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


def read_pulled_txt():
    """Function that reads the output from .txt exported file from .ps1 script with transcript"""

    only_configs = list()
    pulled_configs_dict = dict()

    try:
        with open(transcript, 'r', encoding=utf) as pulled:
            for line in pulled.readlines():
                only_configs.append(line.strip('\n').split(' : '))
        for item in only_configs:
            if item != ['']:
                if len(item) > 1:
                    kee = item[0].lower()
                    wal = item[1]
                    config_dict = {kee: wal}
                    pulled_configs_dict.update(config_dict)

        print(colored('FINDINGS:', 'cyan'))

    except UnicodeError as unicode_error:
        print(colored(f'Error: {unicode_error}', 'red'),
              colored('\nTry changing encoding in "read_pulled_txt" function.', 'cyan'))

    # print(pulled_configs_dict)
    return pulled_configs_dict


def dry_check():
    """Dumb Check to see what configs are not compliant with best practice"""

    not_compliant = dict()

    for key, value in sorted(read_pulled_txt().items()):
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

    findings_still_raw = dict()

    for wet_key, wet_value in dry_check().items():

        best_practice = wet_value[1]
        setting_in_place = wet_value[0]

        # Stripping the "()" in an interesting way
        table = str.maketrans(dict.fromkeys("()"))
        parentheses_less = best_practice.translate(table)

        temp_list = parentheses_less.split(' ')
        if setting_in_place in temp_list:
            # print(wet_key, colored(setting_in_place, 'blue'), colored(temp_list[temp_list.index(setting_in_place)],
            #                                                           'green'))
            pass

        # Shows only not matched
        elif setting_in_place not in temp_list:
            setting_in_place = setting_in_place.strip('{}')

            # Runs another check after one more stripping
            if setting_in_place not in temp_list:
                severities = get_severity(gett=wet_key)

                for_shle = {wet_key: [setting_in_place, temp_list, severities]}
                findings_still_raw.update(for_shle)

    # Special Values dictionary switch to human readable format

    parsed_findings = dict()

    for s_wet_keys, s_wet_values in sorted(findings_still_raw.items()):
        if s_wet_keys not in miscellaneous.keys():

            parsed_1 = {s_wet_keys: [miscellaneous.get("Enabled_Disabled")[s_wet_values[0]],
                                     miscellaneous.get("Enabled_Disabled")[s_wet_values[1][0]], s_wet_values[2]]}
            parsed_findings.update(parsed_1)

        elif s_wet_keys in miscellaneous.keys():
            # print(s_wet_keys, miscellaneous.get(s_wet_keys).get(s_wet_values[0]),
            #       miscellaneous.get(s_wet_keys).get(s_wet_values[1][0]), s_wet_values[2])
            if miscellaneous.get(s_wet_keys).get(s_wet_values[0]) and miscellaneous.get(s_wet_keys).get(
                    s_wet_values[1][0]):
                # print(s_wet_keys, miscellaneous.get(s_wet_keys).get(s_wet_values[0]),
                #       miscellaneous.get(s_wet_keys).get(s_wet_values[1][0]), s_wet_values[2])
                parsed_2 = {s_wet_keys: [miscellaneous.get(s_wet_keys).get(s_wet_values[0]),
                                         miscellaneous.get(s_wet_keys).get(s_wet_values[1][0]), s_wet_values[2]]}
                parsed_findings.update(parsed_2)
            elif not miscellaneous.get(s_wet_keys).get(s_wet_values[0]) or miscellaneous.get(s_wet_keys).get(
                    s_wet_values[1][0]):
                if len(s_wet_values[1][0:]) > 1 and len(s_wet_values[1][0:]) == 3:  # Parsing elements of 3
                    # print(s_wet_keys, s_wet_values[0], ' '.join(s_wet_values[1][0:]), s_wet_values[2])
                    parsed_3 = {s_wet_keys: [s_wet_values[0], ' '.join(s_wet_values[1][0:]), s_wet_values[2]]}
                    parsed_findings.update(parsed_3)
                elif len(s_wet_values[1][0:]) > 1:
                    # if int(s_wet_values[1][0], 16):
                    #     print(s_wet_values[1][0])
                    if s_wet_values[1][0] == 'see':
                        # print(s_wet_keys, s_wet_values[0], miscellaneous.get(s_wet_keys).get(s_wet_values[1][0]),
                        #       s_wet_values[2])
                        parsed_4 = {s_wet_keys: [s_wet_values[0], miscellaneous.get(s_wet_keys).get(s_wet_values[1][0]),
                                                 s_wet_values[2]]}
                        parsed_findings.update(parsed_4)
                    elif len(s_wet_values[1][0:]) > 5:      # SMB Client Parse
                        # print(s_wet_keys, s_wet_values[0], miscellaneous.get(s_wet_keys).get(' '.join(s_wet_values[1][0:])), s_wet_values[2])
                        parsed_5 = {s_wet_keys: [s_wet_values[0], miscellaneous.get(s_wet_keys).get(' '.join(s_wet_values[1][0:])), s_wet_values[2]]}
                        parsed_findings.update(parsed_5)
                    elif s_wet_values[1][0]:      # Last parse, for now
                        # print(s_wet_keys, s_wet_values[0], s_wet_values[1][1:], s_wet_values[2])
                        parsed_6 = {s_wet_keys: [s_wet_values[0], ' '.join(s_wet_values[1][1:]), s_wet_values[2]]}
                        parsed_findings.update(parsed_6)

    # print(parsed_findings)
    return parsed_findings


def final():
    """Another function to clear the compliant settings and leave behind only non-compliant.
        this one has human (mine) logic in it"""
    for juice, cups in wet_check().items():
        if cups[2] == 'LOW':
            print(juice, colored(cups[0], 'red'), colored(cups[1], 'green'), colored(cups[2], 'blue'))
        elif cups[2] == 'MEDIUM':
            print(juice, colored(cups[0], 'red'), colored(cups[1], 'green'), colored(cups[2], 'yellow'))
        elif cups[2] == 'HIGH':
            print(juice, colored(cups[0], 'red'), colored(cups[1], 'green'), colored(cups[2], 'red'))

    return


# wet_check()
final()

# stop = input('\nPress "Enter" to quit...')
# stop
