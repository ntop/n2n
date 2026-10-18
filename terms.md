
<！-- by 黄朝淼 -->
 超级节点（Supernode）：在网络中具有特殊功能和地位的节点，通常承担着数据转发、网络管理等重要任务，可用于构建特定的网络架构。英文解释：A node in a network that has special functions and status, usually undertaking important tasks such as data forwarding and network management, and can be used to build a specific network architecture.
n2n：一种虚拟专用网络（VPN）技术，允许用户创建自己的私有网络，实现不同设备之间的安全通信。英文解释：A virtual private network (VPN) technology that allows users to create their own private network to achieve secure communication between different devices.
配置文件（Configuration File）：包含软件或系统配置信息的文件，用于指定各种参数和设置，以控制软件或系统的行为。英文解释：A file that contains the configuration information of software or a system, used to specify various parameters and settings to control the behavior of the software or system.
端口（Port）：计算机与外部设备或其他计算机进行通信的接口，每个端口都有一个唯一的编号，用于区分不同的通信通道。英文解释：An interface through which a computer communicates with external devices or other computers. Each port has a unique number used to distinguish different communication channels.
源码编译（Source Code Compilation）：将人类可读的源代码转换为计算机可执行的机器代码的过程，需要使用编译器等工具。英文解释：The process of converting human - readable source code into machine - code that can be executed by a computer, which requires the use of tools such as compilers.
边缘节点（Edge Node）：位于网络边缘的节点，通常与终端设备或用户直接连接，用于接收和发送数据。英文解释：A node located at the edge of a network, usually directly connected to terminal devices or users, used to receive and send data.
虚拟接口（Virtual Interface）：在计算机系统中模拟出来的网络接口，并非实际的物理接口，用于实现特定的网络功能或连接到虚拟网络。英文解释：A network interface simulated in a computer system, not an actual physical interface, used to implement specific network functions or connect to a virtual network.
社区名称（Community Name）：在特定的网络环境中，用于标识一组相关设备或用户的名称，通常用于区分不同的网络区域或用户群体。英文解释：In a specific network environment, a name used to identify a group of related devices or users, usually used to distinguish different network areas or user groups.
加密密钥（Encryption Key）：用于对数据进行加密和解密的字符串或数字，确保数据在传输和存储过程中的安全性。英文解释：A string or number used to encrypt and decrypt data, ensuring the security of data during transmission and storage.
自启（Auto - start）：指计算机程序或服务在操作系统启动时自动运行的功能，无需用户手动启动。英文解释：Refers to the function that a computer program or service automatically runs when the operating system starts, without the need for manual user startup.
=======

<!-- by 文荣平 -->

|------------------|-----------------------|--------------------------------------------------------------------------|
| 边缘节点         | Edge Node             | 运行n2n edge客户端的设备，加入虚拟网络并通过超级节点与其他边缘节点通信 |
| 超级节点         | Supernode             | 协助边缘节点建立连接的中继服务器，负责转发发现和连接信息               |
| 社区名称         | Community Name        | `-c`参数值，用于隔离不同用户组的虚拟网络，类似"网络名称"                |
| 加密密钥         | Encryption Key        | `-k`参数值，用于加密节点间通信数据的密钥，需所有成员保持一致            |
| 虚拟网络IP       | Virtual Network IP    | `-a`参数值，边缘节点在虚拟网络中的私有IP地址，用于内部通信              |
| 软件包仓库       | Software Repository   | 如ntop repositories，提供n2n软件包的在线存储和分发服务                  |
| 前台模式         | Foreground Mode       | `-f`参数效果，使进程在终端前台运行，便于查看实时输出                     |
| 中继服务器负载   | Relay Server Load     | 超级节点处理连接请求的工作量，建议自建节点减轻公共服务器压力            |
=======
负载加密（payload encryption）：对传输的数据（有效负载）进行加密，防止传输中数据内容被非法获取，提升通信安全性。

超级节点（supernode）：在网络架构里具有特殊功能或权限的节点，可承担管理、协调等任务，与边缘节点相对。

边缘节点（edge node）：位于网络边缘，是用户设备或与之直接相连的设备，在点对点 VPN 中负责数据接入和传输。

加密方案（encryption scheme）：实现加密的具体算法、策略及流程组合，不同方案在安全性、性能等方面有差别。

AES 加密（AES encryption）：即 Advanced Encryption Standard（高级加密标准），是对称加密算法，在数据加密领域应用广泛，安全性高。

基准测试（benchmark testing）：利用特定测试程序和方法，对系统、软件、算法等的性能指标（如速度、效率）进行评估和比较。

元数据（metadata）：描述其他数据属性的数据，如边缘节点的虚拟 MAC 地址、IP 地址等，用于标识和管理数据。

虚拟 MAC 地址（virtual MAC address）：通过软件等虚拟出的 MAC 地址，非物理网卡真实地址，用于特定网络标识等场景。

实际 MAC 地址（actual MAC address）：网络设备物理网卡的唯一硬件地址，用于局域网中设备身份标识。
hostname：主机名，是网络中计算机或设备的名称，用于在网络中识别区分不同设备。


