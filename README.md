
# <！-- by 黄朝淼 -->🇬🇧 English Version README.md
# Set Up a Custom Supernode
## Overview
This guide will provide a detailed introduction on how to set up a custom supernode, and it will also cover relevant code explanations. By setting up a custom supernode, you can create your own n2n network infrastructure, enhancing network security and privacy.

## I. Operation Steps for Setting a Custom Supernode
### Installing the n2n Software Package
Install the n2n software package on a public server (such as a VPS). The installation methods vary depending on the operating system as follows:

1.For Ubuntu/Debian systems: Open the terminal and execute the command sudo apt-get update && sudo apt-get install n2n to update the software source and install n2n.
2.For CentOS systems: First, ensure that the EPEL source is installed. Then, execute sudo yum install n2n in the terminal to install the n2n software package.
### Editing the Configuration File
Use a text editor (such as nano or vim) to open the /etc/n2n/supernode.conf file and add the content -p=1234. Here, 1234 is the specified port, which can be modified according to the actual situation. This operation is to set the port that the supernode listens on.
### Starting the supernode Service
Enter the command sudo systemctl start supernode in the terminal to start the supernode service, allowing the supernode to run on the set port.
### Setting Auto-start on Boot (Optional)
If you want the supernode service to start automatically after the server restarts, execute the command sudo systemctl enable supernode in the terminal.
## Parameter Processing Logic and Initialization Logic
The setOption function is the core logic for handling command-line parameters in the n2n supernode. It is responsible for parsing various configuration options and setting the corresponding structure members. The following is a detailed textual explanation of this function:
## Parameter Parsing Process
### 1.Receiving parameters:
 The function receives three parameters: optkey (parameter identifier), _optarg (parameter value), and sss (supernode structure pointer).
### 2.Branch processing:
 Use a switch statement to handle different parameter options according to optkey.
### 3.Port parameter (-p):
Format judgment: First, check whether the parameter value contains a colon : to distinguish different input formats.
IP: port format: If it contains a colon, split the string into an IP address part and a port part. Use inet_addr to convert the IP string into an integer in network byte order, and then convert it into host byte order through ntohl. Use atoi to convert the port string into an integer.
#### Error handling:
If the IP address is invalid (returns INADDR_NONE), it will default to bind to all available interfaces (INADDR_ANY).
If the port number is invalid (parsed as 0), the default port (usually 7777) will be used.
#### Only IP or only port:
If the parameter value contains a dot ., it will be regarded as only specifying the IP address, and the default value will be used for the port.
Otherwise, it will be regarded as only specifying the port number, and the IP address will be bound to all interfaces.
## Security Features
#### 1.Input verification:
 Check the validity of the IP address and port number to prevent the program from crashing due to illegal input.
Default value handling: When the input is invalid, it will automatically fall back to a secure default configuration to ensure that the service can start normally.
#### 2.Log recording:
 Use traceEvent to record the warning information during the parameter parsing process, which is convenient for debugging and maintenance.
## Explanation of Supernode Initialization Logic
The initialization of the supernode is divided into two main functions: sn_init_defaults and sn_init, which complete the initialization work at different stages respectively:
### Basic Initialization (sn_init_defaults)
#### 1.Initializing structure members: 
Set each field of the supernode structure to its default value.
#### 2.Network configuration:
###### 1.bind_address:
 Default to bind to all available interfaces (INADDR_ANY).
###### 2.lport:
 The default listening port (usually 7777).
mport: The management port (used to receive management commands).
###### 3.Memory allocation: 
Allocate initial memory space for dynamic data structures such as the edge node table and the community list.
Setting default parameters: Set other runtime parameters, such as the number of threads and the timeout time.
## Advanced Initialization (sn_init)
###### 1.Thread creation:
Create a resolution thread (resolve_create_thread) to handle domain name resolution and node discovery. This thread is responsible for maintaining the reachability information of edge nodes to ensure smooth communication between nodes.
###### 2.Resource initialization:
Initialize the encryption context and configure the default encryption algorithm.
Start the management interface and listen for management commands.
###### 3.Service preparation:
Create a socket and bind it to the specified address and port.
Start listening for client connection requests.
###### 4.Status notification:
Record the initialization completion information through logs, including key configurations such as the bound address and port.
### Characteristics of the Initialization Process
###### 1.Staged initialization: 
Split the complex initialization process into two stages, basic setting and advanced setting, to improve code maintainability.
###### 2.Modular design:
 Each initialization task is independently encapsulated, making it easy to expand and modify functions.
Resource management: Reasonably allocate and initialize system resources to ensure the normal operation of the service.
###### 3.Error handling:
 When the initialization fails, perform appropriate cleaning and error reporting to ensure the robustness of the program.
### Combined Workflow of the Two
###### 1.Parameter parsing:
 Parse the command-line parameters through the setOption function and modify the default configuration.
###### 2.Basic initialization:
 Call sn_init_defaults to set the default values and build the basic operating environment.
###### 3.Parameter application: 
Apply the parsed parameter values to the initialized structure and overwrite the default values.
###### 4.Advanced initialization:
 Call sn_init to complete the remaining initialization work and start the core service components.
###### 5.Service operation: 
The supernode starts listening for client connections and processes communication requests between nodes.
This design makes the configuration of the supernode flexible and easy to expand, while ensuring the stability and security of the initialization process.

# Edge Node Configuration
## Connect to the Custom Supernode
On your edge node, you can specify the custom supernode using the -l parameter. For example, use the following command on the edge node to connect to the custom supernode:

sudo edge -d tun0 -l your_supernode_ip:1234 -c mycommunity -k mysecretkey -a 192.168.100.2 -f

### Parameter Explanation:
-d tun0: Use the tun0 virtual interface
-l: Specify the supernode address and port
-c: Community name
-k: Encryption key
-a: Assigned virtual IP address
-f: Run in the foreground (for debugging purposes)
=======

<!-- by 文荣平  -->
### Quick Setup
- **Installation Method**: In some Linux distributions, `n2n` is provided as a software package, and you can install it using `sudo apt install n2n`. Additionally, the latest software packages for most distributions can be obtained from [ntop repositories](http://packages.ntop.org/).
- **Example Configuration**: Here are examples of configuring edge nodes on different hosts:

```sh
# Run the edge command with sudo privileges to configure an n2n edge node
# -c specifies the community name as mynetwork
# -k specifies the encryption key as mysecretpass
# -a specifies the local IP address as 192.168.100.1
# -f runs the process in foreground mode
# -l specifies the supernode to connect to as supernode.ntop.org:7777
```
    - Host 1:
```sh
sudo edge -c mynetwork -k mysecretpass -a 192.168.100.1 -f -l supernode.ntop.org:7777
```
    - Host 2:
```sh
sudo edge -c mynetwork -k mysecretpass -a 192.168.100.2 -f -l supernode.ntop.org:7777
```

After the configuration is completed, the two hosts can ping each other. It is highly recommended to choose a custom community name (`-c`) and a secret encryption key (`-k`) to prevent other users from connecting to your computer. To protect data privacy and reduce the server load of `supernode.ntop.org`, it is also recommended to set a custom supernode. 

I. Community and Encryption Key Settings
1. Custom Community and Key
To prevent other users from connecting to your computer, it is strongly recommended to select a custom community name (using the -c parameter) and a secure encryption key (using the -k parameter) for each virtual network. Avoid using default or easily guessable community names and keys to ensure the privacy and security of the network.
2. Key Strength
The length and complexity of the encryption key will affect the security of the encryption. When setting the encryption key, try to use a key that is long and contains multiple character types (letters, numbers, special characters). A longer key can increase the difficulty of cracking and improve the security of data transmission.
II. Security of Supernode Usage
1. Custom Supernode
To protect data privacy and reduce the server load of public supernodes (such as supernode.ntop.org), it is recommended to set a custom supernode. Follow these steps to set it up:
Install the n2n package.
Edit the /etc/n2n/supernode.conf file and add a listening port, for example, -p = 1234.
Start the supernode service using sudo systemctl start supernode.
Optionally, use sudo systemctl enable supernode to make the supernode start automatically when the system boots.
2. Port Security
When setting up a custom supernode, you need to open the specified port (such as port 1234 in the above example) on the firewall (usually iptables). Ensure that only the necessary ports are opened and appropriate access control is carried out on the ports to prevent unauthorized access.
III. Data Encryption
1. Payload Encryption
When payload encryption is enabled (by providing a key using the -k parameter), the supernode will not be able to decrypt the traffic exchanged between the two edge nodes, but it will still know which edge nodes are communicating. This means that although the data content is protected, the communication topology information is still visible.
2. Encryption Scheme Selection
The n2n edge nodes use AES encryption by default. You can select other encryption schemes according to your needs and specify them using the -A_ option. Different encryption schemes may vary in terms of security, performance, etc. It is recommended to refer to the comparison chart in the Crypto description and select a suitable encryption scheme according to the actual situation.
3. Encryption Benchmark Testing
If you compile n2n from the source code, you can use tools/n2n-benchmark to conduct benchmark tests on different encryption methods to understand their performance and find a balance between security and performance.
IV. Header Encryption
Metadata Protection
The header of the edge node contains some metadata, such as the virtual MAC address, IP address, real host name, and community name. To protect the privacy of this metadata, you can use the -H option on the edge node to encrypt the header and prevent the leakage of this information.
V. Authentication and Authorization
1. User/Password Authentication
When using the user/password-based authentication method, the supernode needs to be prepared accordingly. Configure the user and password information in the community.list file. If a user changes their password or you need to prohibit a user from accessing the community, you need to update or delete the corresponding lines in the community.list file and restart the supernode or send the reload_communities command to the management port to make the changes take effect.
2. Management Port Authentication
For command operations on the management port, there is a simple authentication mechanism. Read operations are generally allowed, while write operations may require providing the correct authentication password. The basic authentication logic is implemented in the mgmt_auth function, which determines whether to authorize by comparing the password hash value in the request with the provided authentication password hash value. Ensure that a secure management port password is set to prevent unauthorized management operations.
VI. Version and Update
1. Use of Stable Version
It is generally recommended to use the latest stable version. The current dev branch usually does not guarantee backward compatibility with the latest stable version or the previous dev state. If you want to try new features, you can compile from the dev branch, but you need to pay attention to tracking the changes that may occur quickly and provide feedback in the Issues section.
2. Timely Update
Regularly check for updates of n2n and install the latest version in a timely manner to obtain security patches and functional improvements to ensure the security and stability of the software.
VII. Code Security
1. Open Source Code Review
Since n2n is open source software, you can review the source code to understand its implementation details and potential security risks. In particular, carefully review the code sections related to key functions such as encryption, authentication, and network communication.
2. Security of Dependent Libraries
n2n may depend on some external libraries, such as OpenSSL. Ensure that the versions of these dependent libraries are secure and update the dependent libraries with security vulnerabilities in a timely manner.
By following the above security precautions, you can improve the security of the n2n virtual network and protect the privacy of data transmission and network communication.


