from stig_win_10 import windows_10_pc as hardening


def main_parser():
    """Function to parse STIG dictionary Value Names, Values, Registry Paths & Setting Titles"""

    full_list = list()
    full_dict = dict()
    titles_length = list()
    star = '|'

    for i in hardening:
        if hardening.get(i)['checktext'].__contains__('Value Name') and hardening.get(i)['checktext'].__contains__(
                'Value:') and hardening.get(i)['checktext'].__contains__('Registry Path:'):

            values = hardening.get(i)["checktext"].split('\n')
            titles = hardening.get(i)["title"]
            titles_length.append(str(len(titles)))
            titles = titles.replace('.', ' ')  # Solves problem '.' in the middle of the title

            if not titles.endswith('.'):
                titles = titles + '.'  # Solves the Title problem, if it's not endswith '.' the script will break
            full_list.append(titles)
            full_list.append(hardening.get(i)["severity"].upper())

            for v in values:
                if v.startswith('Registry Path:') or v.startswith('Value Name') or v.startswith('Value:'):
                    full_list.append(v)

            full_list.append(star)
    new_list = ' '.join(full_list).split(star)

    for item in sorted(new_list):
        item = item.lstrip(' ').replace('Value Name:', '').replace('Registry Path:', '').replace('Value:',
                                                                                                 '', ).replace(
            '  ', ' ').replace('\n', '').replace('  ', ' ')
        item = item.split('.')

        if item == ['']:
            pass
        elif item != ['']:
            values = item[1].lstrip(' ').rstrip(' ').split(' ')
            keys = item[0]
            # print(values)
            if values[1].startswith('\\') and values[2].endswith('\\'):
                values[1] = values[1] + ' ' + values[2]
                # print(values)
                if type(values[3:]) == list:
                    super_each = list()
                    for each in values[3:]:
                        super_each.append(each)
                        temp_dict = {keys: [values[0], values[1], super_each[0], ' '.join(super_each[1:])]}
                        full_dict.update(temp_dict)
            elif '\\' in values[1] and '\\' in values[2]:
                values[1] = values[1] + ' ' + values[2]
                if type(values[3:]) == list:
                    super_each = list()
                    for each in values[3:]:
                        super_each.append(each)
                        temp_dict = {keys: [values[0], values[1], super_each[0], ' '.join(super_each[1:])]}
                        full_dict.update(temp_dict)
            elif '\\' in values[1] and '\\' in values[2] and '\\' in values[3]:
                values[1] = values[1] + ' ' + values[2] + ' ' + values[3]
                if type(values[4:]) == list:
                    super_each = list()
                    for each in values[4:]:
                        super_each.append(each)
                        temp_dict = {keys: [values[0], values[1], super_each[0], ' '.join(super_each[2:])]}
                        full_dict.update(temp_dict)
            else:
                temp_dict = {keys: values}
                full_dict.update(temp_dict)

    final_dict = dict()
    power_shell_commands = list()
    for k, v in sorted(full_dict.items()):
        if v[2].endswith('\\'):
            temp = str(v[3]).split(' ')
            commands = 'Get-ItemProperty -Path HKLM:' + v[1].lstrip('HKLM') + ' ' + v[2], ' | fl ', str(temp[0]) + '\n'
            power_shell_commands.append(commands)
            k = k.rstrip(' ')
            new_temp_dict = {k: [v[0], v[1] + v[2], ' '.join(v[3:])]}
            final_dict.update(new_temp_dict)

            # print(k, v[0], v[1] + v[2], v[3])
        else:
            k = k.rstrip(' ')
            commands = 'Get-ItemProperty -Path HKLM:' + v[1].lstrip('HKLM'), ' | fl ', v[2] + '\n'
            power_shell_commands.append(commands)
            new_temp_dict = {k: [v[0], v[1], v[2], ' '.join(v[3:])]}
            final_dict.update(new_temp_dict)

    # for a, s in final_dict.items():
    #     print(s)

    return final_dict


def re_write_stig(stig_file_name: str):
    with open(f'{stig_file_name}.py', 'a') as stig_py:
        # print('win_10 = {')
        stig_py.writelines(f'{stig_file_name} = {{')
        for b, j in main_parser().items():
            if not j[3:]:
                new_stig = f"\t'{b}':\n\t\t{{\n" + f"\t\t\t'severity': '{j[0]}', \n" + f"\t\t\t'reg_path': {[(j[1])]}," \
                           f"\n" + f"\t\t\t'setting': '{j[2]}',\n" + f"\t\t\t'more': {None}\n\t\t}},\n"
                new_stig = new_stig.replace('[', '').replace(']', '')
                stig_py.writelines(new_stig)
                # print(new_stig)
            elif j[3:] == ['']:
                new_stig = f"\t'{b}':\n\t\t{{\n" + f"\t\t\t'severity': '{j[0]}', \n" + f"\t\t\t'reg_path': {[(j[1])]}," \
                           f"\n" + f"\t\t\t'setting': '{j[2]}',\n" + f"\t\t\t'more': {None}\n\t\t}},\n"
                new_stig = new_stig.replace('[', '').replace(']', '')
                stig_py.writelines(new_stig)
                # print(new_stig)
            else:
                new_stig = f"\t'{b}':\n\t\t{{\n" + f"\t\t\t'severity': '{j[0]}', \n" + f"\t\t\t'reg_path': {[(j[1])]}," \
                           f"\n" + f"\t\t\t'setting': '{j[2]}',\n" + f"\t\t\t'more': {j[3:]}\n\t\t}},\n"
                new_stig = new_stig.replace('[', '').replace(']', '')
                stig_py.writelines(new_stig)
                # print(new_stig)
        stig_py.writelines('}')
        # print('}')


re_write_stig(stig_file_name='parsed_win10_stig')
