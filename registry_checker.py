from termcolor import colored
# Choose Version, Comment-out rest
# from stig_server_2008_r2 import windows_server_2008_r2 as hardening
# from stig_server_2012_r2 import windows_server_2012_r2 as hardening
# from stig_server_2016 import windows_server_2016 as hardening
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
            new_temp_dict = {k: [v[0], v[1] + v[2], v[3:]]}
            final_dict.update(new_temp_dict)

            # print(k, v[0], v[1] + v[2], v[3])
        else:
            k = k.rstrip(' ')
            commands = 'Get-ItemProperty -Path HKLM:' + v[1].lstrip('HKLM'), ' | fl ', v[2] + '\n'
            power_shell_commands.append(commands)
            new_temp_dict = {k: [v[0], v[1], v[2], v[3:]]}
            final_dict.update(new_temp_dict)

    # for a, s in final_dict.items():
    #     print(s)

    return final_dict, power_shell_commands


def create_transcript(transcript_name: str):
    """Function for creating PowerShell Transcript with registry keys"""

    print(f'\nRun {transcript_name} with', colored('ADMINISTRATOR\n', 'red'))
    with open(f'{transcript_name}.ps1', 'a') as transcript:
        transcript_start = f'$hostname = hostname\n$ErrorActionPreference = "silentlycontinue"\n' \
                           f'$Pazh = "C:\\temp\\$hostname.txt"\nStart-Transcript -Path $Pazh -NoClobber\n\n'
        transcript.writelines(transcript_start)

        for command in main_parser()[1]:
            transcript.writelines(command)

        transcript_end = '\nStop-Transcript\n'
        transcript.writelines(transcript_end)


def read_pulled_txt(transcript: list, utf: str):
    """Function that reads the output from .txt exported file from .ps1 script with transcript"""

    only_configs = list()
    pulled_configs_dict = dict()

    try:
        for file in transcript:
            with open(file, 'r', encoding=utf) as pulled:
                for line in pulled.readlines():
                    only_configs.append(line.strip('\n').split(' : '))
            for item in only_configs:
                if item != ['']:
                    if len(item) > 1:
                        kee = item[0].lower()
                        wal = item[1]
                        config_dict = {kee: wal}
                        pulled_configs_dict.update(config_dict)

            print(colored(f'FINDINGS on {file.upper().strip(".TXT")}:', 'cyan'))

    except UnicodeError as unicode_error:
        print(colored(f'Error: {unicode_error}', 'red'),
              colored('\nTry changing encoding in "read_pulled_txt" function.', 'cyan'))

    # print(pulled_configs_dict)
    return pulled_configs_dict


def checker():
    """Check Transcript output file against STIG hardening"""

    for b, j in read_pulled_txt(transcript=['andreyk-laptop.txt'], utf='utf-8').items():
        if b.startswith('\\\\'):
            if main_parser()[0].values():
                print(main_parser()[0].values())
            # print(b.strip('\\\\'), j)
        else:
            # print(main_parser()[1][0])
            # print(b, j)
            pass
    return


# print(main_parser())

# main_parser()
create_transcript(transcript_name='win_10_pc')
# checker()
# print(main_parser()[0])
