from termcolor import colored
# Choose Version, Comment-out rest
from stig_server_2008_r2 import windows_server_2008_r2 as hardening
from stig_server_2012_r2 import windows_server_2012_r2 as hardening
from stig_server_2016 import windows_server_2016 as hardening


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
            if '\\' in values[1] and '\\' in values[2]:
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
                        temp_dict = {keys: [values[0], values[1], super_each[0], ' '.join(super_each[1:])]}
                        full_dict.update(temp_dict)
            else:
                temp_dict = {keys: values}
                full_dict.update(temp_dict)

    # for k, v in sorted(full_dict.items()):
    #     # print(k, v)
    #     print('Get-ItemProperty -Path HKLM:' + v[1].lstrip('HKLM'), ' | fl', v[2] + '\n')

    return full_dict


def create_transcript(transcript_name: str):
    """Function for creating PowerShell Transcript with registry keys"""
    
    print(f'\nRun {transcript_name} with', colored('ADMINISTRATOR', 'red'))
    with open(f'{transcript_name}.txt', 'a') as transcript:
        transcript_start = f'$hostname = hostname\n$ErrorActionPreference = "silentlycontinue"\n' \
                           f'$Pazh = "C:\\temp\\$hostname.txt"\nStart-Transcript -Path $Pazh -NoClobber\n\n '
        transcript.writelines(transcript_start)
        for k, v in sorted(main_parser().items()):
            command = 'Get-ItemProperty -Path HKLM:' + v[1].lstrip('HKLM'), ' | fl', v[2] + '\n'
            transcript.writelines(command)
        transcript_end = '\nStop-Transcript\n'
        transcript.writelines(transcript_end)


def checker():
    return


main_parser()
# create_transcript(transcript_name='test')
