
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

