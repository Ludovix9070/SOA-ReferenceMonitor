# SoaProject
## Project Specification ##
The examination requires fulfilling the development of a project in the Linux kernel, which must comply with the following specification. Each student should develop the project individually.
**Kernel Level Reference Monitor for File Protection**
This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:

   - OFF, meaning that its operations are currently disabled;
   - ON, meaning that its operations are currently enabled;
   - REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode). 

The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

   - the process TGID
   - the thread ID
   - the user-id
   - the effective user-id
   - the program path-name that is currently attempting the open
   - a cryptographic hash of the program file content 

The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work. 

## Getting Started ##
1. Clone the following repository
    ```bash
   git clone https://github.com/Ludovix9070/SOA-ReferenceMonitor.git
   ```
2. Move to the direcotory **./reference-monitor** and run the following script to install the modules
    ```bash
   sudo sh launch.sh
   ```
## Main Features ##
Once the module is installed, the reference monitor status is set to ON and there are some default blacklisted paths in order to test the application. The main features offered by the reference monitor are:
 - Set the reference monitor status to ON;
 - Set the reference monitor status to OFF;
 - Set the reference monitor status to REC-ON;
 - Set the reference monitor status to REC-OFF;
 - Add a new path to the blacklist;
 - Remove an existing path from the blacklist;
 - Change the password;

To execute these operations move to the **./reference-monitor/user** directory and run the following commands:
   ```bash
   make all
   ```
   ```bash
   sudo make run
   ```
At the beginning, all these operations require a default user **password** as input. 

## Testing ##
To test the reference monitor, move to the directory **./reference-monitor/user/test** and execute the following commands:
   ```bash
   make all
   ```
   ```bash
   make run
   ```
Once the testing is running, there are different operations that can be performed:
 - Open a file (try to open a file, if the file is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Delete a file (try to delete a file, if the file is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Create a directory (try to create a directory, if the directory to create is into a blacklisted directory and the reference monitor is ON/			REC-ON -> the operation will be rejected);
 - Delete a directory (try to delete a directory, if the directory to delete is into a blacklisted directory and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Move a file/directory (try to move a file/directory to a new path, if the file/directory to move or the destination path is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Copy a file (try to copy a file to a new path, if the file to copy or the destination path is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Copy a directory (try to copy a directory to a new path, if the directory to copy or the destination path is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);
 - Link a file (try to create an hard link to a file, if the file to link is blacklisted and the reference monitor is ON/REC-ON -> the operation will be rejected);

 

