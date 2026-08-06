<-- by 唐崟 -->
N2N	N2N:一款轻量级 VPN 软件，可创建虚拟网络，绕过防火墙限制
VPN（Virtual Private Network）	虚拟专用网络:可在公共网络上建立加密通道，实现安全通信
supernode	超级节点:作为网络枢纽，负责边缘节点的注册与发现，支持多社区并发中继
edge node	边缘节点:虚拟网络的终端节点，支持多平台部署，具备数据加密功能
virtual network	虚拟网络:通过软件技术构建的网络，可实现设备间的互联
firewall	防火墙:用于网络安全防护，限制网络访问的设备或软件
community	社区:N2N 中以虚拟网络划分的单位，每个社区有独立网络空间和加密密钥
NAT（Network Address Translation）	网络地址转换:用于在不同网络间转换地址，N2N 中直连时会用到 NAT 穿透技术
UDP（User Datagram Protocol）	用户数据报协议:一种无连接的传输层协议，N2N 中用于节点间数据传输
AES - 256（Advanced Encryption Standard - 256）	高级加密标准 - 256:一种数据加密算法，N2N 中用于社区级数据加密
identity authentication	身份认证:用于确认用户或设备身份的过程，保障网络安全
data packet verification	数据包校验:检查数据包的完整性，防止数据传输过程中被篡改
key rotation	密钥轮换:定期更换加密密钥，增强数据安全性
<-- by 唐崟 -->

---

<-- by 谢思源 -->
手动编译
中文术语：手动编译
英文术语：Manual Compilation
解释：指通过手动执行一系列命令从源代码构建软件的过程
源代码
中文术语：源代码
英文术语：Source Code
解释：以人类可读的高级语言编写的程序代码，可被编译或解释执行
Linux 系统
中文术语：Linux 系统
英文术语：Linux System
解释：一种开源的操作系统，广泛应用于服务器和各种设备中
编译
中文术语：编译
英文术语：Compile
解释：将源代码转换为可执行文件或其他目标产物的过程
配置
中文术语：配置
英文术语：Configure
解释：根据系统实际情况设置编译参数，检查依赖项，生成 Makefile 等操作
###./autogen.sh 脚本
中文术语：./autogen.sh 脚本
英文术语：./autogen.sh Script
解释：用于自动生成配置所需文件，检测系统环境的脚本
###./configure 命令
中文术语：./configure 命令
英文术语：./configure Command
解释：进一步检查依赖项，设置编译参数，生成 Makefile 的命令
make 命令
中文术语：make 命令
英文术语：make Command
解释：根据 Makefile 规则编译源代码的命令
make install 命令
中文术语：make install 命令
英文术语：make install Command
解释：可选的安装命令，将编译好的文件安装到系统指定目录
依赖项
中文术语：依赖项
英文术语：Dependencies
解释：软件运行或编译所依赖的其他软件包、库或工具等
可执行文件
中文术语：可执行文件
英文术语：Executable File
解释：可以在操作系统上直接运行的文件，由源代码编译生成
库文件
中文术语：库文件
英文术语：Library File
解释：包含可被其他程序调用的函数和数据的文件，用于代码复用
Makefile
中文术语：Makefile
英文术语：Makefile
解释：包含编译规则和相关配置信息的文件，make 命令依据此文件进行编译操作
Windows 系统
中文术语：Windows 系统
英文术语：Windows System
解释：由微软公司开发的操作系统，在个人计算机中广泛使用
MacOS 系统
中文术语：MacOS 系统
英文术语：MacOS System
解释：苹果公司开发的操作系统，用于苹果的 Mac 系列计算机
优化
中文术语：优化
英文术语：Optimization
解释：对编译过程或软件性能进行改进，以提高效率或减少资源消耗
通用构建选项
中文术语：通用构建选项
英文术语：General Build Options
解释：适用于不同系统和场景的常见编译配置选项
稳定版本
中文术语：稳定版本
英文术语：Stable Version
解释：经过充分测试和验证，稳定性和兼容性有保障的软件版本
开发分支（dev 分支）
中文术语：开发分支（dev 分支）
英文术语：Development Branch (dev Branch)
解释：用于开发新功能、测试未稳定特性的代码分支
向后兼容
中文术语：向后兼容
英文术语：Backward Compatibility
解释：新的版本或代码能够在基于之前版本构建的环境中正常运行的特
<-- by 谢思源 -->



---



<-- by 黄朝淼 -->
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

<-- by 黄朝淼 -->


---


<-- by 文荣平 -->



|------------------|-----------------------|--------------------------------------------------------------------------|
---

| 边缘节点         | Edge Node             | 运行n2n edge客户端的设备，加入虚拟网络并通过超级节点与其他边缘节点通信 |

---

| 超级节点         | Supernode             | 协助边缘节点建立连接的中继服务器，负责转发发现和连接信息               |

---

| 社区名称         | Community Name        | `-c`参数值，用于隔离不同用户组的虚拟网络，类似"网络名称"                |

---

| 加密密钥         | Encryption Key        | `-k`参数值，用于加密节点间通信数据的密钥，需所有成员保持一致            |

---

| 虚拟网络IP       | Virtual Network IP    | `-a`参数值，边缘节点在虚拟网络中的私有IP地址，用于内部通信              |

---

| 软件包仓库       | Software Repository   | 如ntop repositories，提供n2n软件包的在线存储和分发服务                  |

---

| 前台模式         | Foreground Mode       | `-f`参数效果，使进程在终端前台运行，便于查看实时输出                     |

---

| 中继服务器负载   | Relay Server Load     | 超级节点处理连接请求的工作量，建议自建节点减轻公共服务器压力            |



<-- by 文荣平 -->



---


<-- by 陈思良 -->

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

<-- by 陈思良 -->


---


<---by 刘琳锋--->
# 术语词汇表

以下是一些常用术语及其定义，以帮助您更好地理解相关文档和讨论。

## FAQ
**Frequently Asked Questions** 的缩写，指常见问题解答。

## CLI
**Command Line Interface** 的缩写，指命令行界面，是一种通过文本命令与计算机程序交互的用户界面。

## GUI
**Graphical User Interface** 的缩写，指图形用户界面，是一种通过图形图标和菜单与计算机程序交互的用户界面。

## Docker
一种开源的应用容器引擎，让开发者可以打包他们的应用以及依赖包到一个可移植的容器中，然后发布到任何流行的 Linux 机器上，也可以实现虚拟化。

## Kubernetes
一个开源的容器编排系统，用于自动化部署、扩展和管理容器化应用程序。

## Helm
Kubernetes 的包管理工具，它帮助您定义、安装和升级 Kubernetes 应用程序。

## n2n
一种点对点（P2P）虚拟专用网络（VPN）解决方案，允许用户创建一个安全的网络，使远程计算机可以相互通信，就像它们在同一局域网中一样。

## Pull Request
在版本控制系统中，特别是在使用 Git 的系统中，一个用户向另一个用户或团队的代码库提交更改的请求。

## Supernode
在网络中，超级节点是一种特殊的节点，它充当其他节点之间的中介，帮助它们相互通信。

## Edge
在网络术语中，边缘节点是指网络的外围部分，通常是指连接到网络的最终用户设备。

## Lucktu
一个为 Windows 提供的 n2n 预编译二进制文件集合。

## Hin2n
为 Android 设备提供的 n2n 客户端。

## HappyNet
一个为 Windows 提供的 GUI，支持 n2n 网络的配置和管理。
<---by 刘琳锋--->


