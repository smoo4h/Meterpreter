# **Final Project**

## **Introduction**
This project consists of three major components as defined below:
* Client - It consists of the main code that is responsible for creating and registering a process as an agent. It is also responsible for recieving tasks from the server and performing them.
* Server - It is responsible for accepting new agent registration and storing their data. It is also responsible for assigning tasks to the agents.
* CLI - It is a command line interface tool to interact with the server. With the help of this CLI tool, we can send tasks to the agents that they will perform.
* sRDI Modules - It stores modules for our two new functionalities (listprivs and setpriv) along with Loader.

Hence, the purpose of this project is to create and register a process as an agent on the server. Next, recieve a task from the server that can be assigned with the help of CLI tool, and perform those tasks and give back any output resultant of those tasks.

## **Client**
Client.exe is located in Client/x64/Debug/ directory. On running it, it will execute the main.cpp code. Following are its main responsibilities:
* Create a new agent whenever it is executed.
* Register this newly created agent to the server and recieve an agent ID.
* Ask for any task assigned to it from the server at regular intervals.
* If a task is assigned, perform the task and output the result, else go to sleep.
* Following are the tasks that can be performed by agent:
  * pwd - print the current working directory
  * cd <directory_path> - change directory to the given directory path
  * getuid - get the username of the user who is running the agent.
  * ps - list all running processes
  * scinject [path/sc.bin] [pid] - remote injection where pid is the processid you want to inject in and sc.bin is the shellcode.
  * Any custom task through Postman
  * shell <cmd with args> - send a command with arguments to the agent for execution.
  * upload <local_file_path> <destination_file_path> - upload a file from your machine to download on a destination file path on the agent's machine.
  * download <file_path> - downloads a target file, provided in teh file path, from the client machine to our machine.
  * listprivs - lists the values of privileges and  shows whether they are enabled (denoted by the value TRUE) or disabled (denoted by the value FALSE).
  * setpriv <privilege_name> <enabled | disabled> - enable or disable a particular privilege provided you have enough permissions to do the modification.
  * bypassuac [method1=fodhelper] <cmd with args> - elevate user to high integrity level and execute the command, provided the user is present in Local Admin Group.
  * getsystem [method1=pipe] <cmd with args> - elevate user to SYSTEM integrity level and execute the commad, provided the implant is already running in high integrity level.
  * screenshot - take a screenshot of the current screen of the target machine and save it to our Server/data/screenshots directory.
  * sleep <base_sleep_time> <jitter_percentage> - set a custom sleep time along with jitter percentage. The default jitter percentage is 25%.
  * logonpasswords - use mimikatz functionality of capturing stored passwords in the target machine.
  * mimikatz <mimikatz_command> - run a particular mimikatz command.
  * help [command] - displays information regarding a particular command (if provided). Alternatively, prints help menu.

## **Server**
The Server/ directory consists of the code for Python server and also a CLI tool which will be discussed later. The main responsibility of the server are:
* Take in new agent registration request and register them. Also, provide them an agent ID.
* Store the data of all the registered agents.
* Send task to the agents (assign the tasks based on the agent IDs)

## **CLI**
CLI tool is another important thing present in Server/ directory. The main responsibilities of the CLI tool is to interact with the server and provide following capabilities:
* List down all the agents that are stored in the server.
* Use any agent and interact with the agent.
* Assign tasks to the agent.
* Retrieve data about the agent, like system information on which the agent is running, current active tasks and history of all the tasks assigned to the agent.

## **Testing**
We have created a Testing/ directory where we have shared the result of our tests on the project. In the tests, we have tested all the possible commands that can be performed with the help of CLI, and also tested a custom task to test the behaviour of the agent.
