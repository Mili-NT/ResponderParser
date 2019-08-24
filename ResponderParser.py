import re
import matplotlib.pyplot as plotter
from os import getcwd, mkdir
from os.path import isdir
import datetime
#
# Made by: Mili
# Python Version: 3.6.0
# Credit to Laurent Gaffie for making and maintaining Responder
def session_file_proc(filename, folder):
    netbios_dict = {}
    service_dict = {}
    OS_dict = {}
    UA_dict = {}
    hash_dict = {}
    timestamp = len('08/23/2019 05:20:13 PM - ')
    lineinfo = '[*] [NBT-NS] '
    pattern = r'(?:\d{1,3}\.)+(?:\d{1,3})'
    with open(f'{folder}ResponderSession_Boxes_{datetime.datetime.now().date()}.txt', 'w') as savefile:
        with open(filename, 'r') as logfile:
            for line in logfile.readlines():
                cleaned = line.rstrip()[timestamp:]
                if cleaned[1] == '*' and '[NBT-NS]' in cleaned:
                    workstring = cleaned.replace(' ', '').strip(lineinfo)[20:]
                    service_name = workstring.split('(service:')[1].replace(')', '')
                    if service_name not in service_dict.keys():
                        service_dict[service_name] = 1
                    else:
                        service_dict[service_name] += 1
                    stringip = re.findall(pattern, workstring)
                    unproc_name = cleaned[cleaned.find('name '):].split('(')[0]
                    true_name = unproc_name.replace('name ', '').rstrip()
                    if true_name not in netbios_dict.keys():
                        savefile.write(f'Box Name: [{true_name}], Service Type: [{service_name}], Address: [{stringip[0]}]\n')
                        netbios_dict[true_name] = stringip
                    else:
                        pass
                    pass
                elif cleaned[:8] == '[FINGER]':
                    if 'OS Version' in cleaned:
                        version = cleaned.split(':')[1]
                        if version not in OS_dict.keys():
                            OS_dict[version] = 1
                        else:
                            OS_dict[version] += 1
                elif cleaned[:6] == '[HTTP]':
                    if cleaned[7:17] == 'User-Agent':
                        user_agent = cleaned.split(':')[1]
                        user_agent = user_agent[1:len(user_agent)]
                        if user_agent in UA_dict.keys():
                            UA_dict[user_agent] += 1
                        else:
                            UA_dict[user_agent] = 1
                    elif cleaned[7:18] == 'NTLMv2 Hash':
                        ntlm = cleaned.split(': ')[1]
                        username = ntlm.split('::')
                        if username[0] not in hash_dict.keys():
                            hash_dict[username[0]] = username[1]
    with open(f'{folder}ResponderSession_OS_{datetime.datetime.now().date()}.txt', 'w') as osfile:
        for k,v in OS_dict.items():
            osfile.write(f'OS Version: {k}, Instances: {v}\n')
    with open(f'{folder}ResponderSession_UA_{datetime.datetime.now().date()}.txt', 'w') as uafile:
        for k,v in UA_dict.items():
            uafile.write(f'User-Agent: {k}, Instances: {v}\n')
    masterdict = {'osd':OS_dict, 'uad':UA_dict, 'nbsd':service_dict}
    return masterdict
def session_data_visualization(identifier, resources, folderpath):
    if identifier == 'osd':
        savename = 'OperatingSystemsGraph'
        title = "Operating System Prevalence"
    elif identifier == 'uad':
        savename = 'UserAgentGraph'
        title = "User-Agent Prevalence"
    elif identifier == 'nbsd':
        savename = 'NBTServicesGraph'
        title = 'Net BIOS Services Prevalence'
    empty = []
    labels = []
    data = []
    for k in resources.keys():
        labels.append(k)
        empty.append('')
        data.append(resources[k])
    figureObject, axesObject = plotter.subplots()
    axesObject.pie(data, labels=empty, autopct='%1.2f', startangle=90)
    if identifier == 'osd':
        plotter.legend(title=title, loc="best", labels=labels)
    elif identifier == 'uad':
        plotter.legend(title=title, loc="lower center", labels=labels)
    elif identifier == 'nbsd':
        plotter.legend(title=title, loc="best", labels=labels)
    axesObject.axis('equal')
    plotter.show()
    plotter.savefig(f"{folderpath}{savename}")
def sessions_main():
    folder = getcwd() + '\\' + 'RP_Session_Output\\'
    if isdir(folder) is True:
        pass
    else:
        mkdir(folder)
    while True:
        try:
            fileinput = input("Enter the filepath of the Responder-Session log file: ")
            break
        except FileNotFoundError:
            print("No such file found.")
            continue
    masterdict = session_file_proc(fileinput, folder)
    for k in masterdict.keys():
        session_data_visualization(k, masterdict[k], folder)

if __name__ == '__main__':
    sessions_main()