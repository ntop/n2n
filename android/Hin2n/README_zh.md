# n2n_vLTS

[README](README.md) | [中文文档](README_zh.md)

n2n是一个支持内网穿透p2p的VPN项目，最初由ntop.org大神`Luca Deri` <deri@ntop.org>, `Richard Andrews` <andrews@ntop.org>开发并开源的项目，后由`meyerd`大神 <https://github.com/meyerd>继续做优化工作。我们的目的是在几位大神的基础上做持续优化并提供`手机版本`的支持。

## Hin2n
原版的n2n支持很多平台，包括windows，linux，osx，bsd，openwrt，raspberry pie等，唯独缺少对手机(非root)的支持。因此，我们开发了Hin2n项目。

### Hin2n是什么
- Hin2n是支持n2n协议的手机VPN软件
- 该APP不需要root手机
- 该APP暂时只支持安卓手机，后续会发开IPhone版本
- 该项目现处于持续开发阶段，仅支持基本的配置连接功能，后续会提供更完善的功能
- 该项目现只支持[n2n_v2s](#关于v2s版本)协议，其他版本的n2n协议正在开发中

### Hin2n最新版本 [CHANGELOG](Hin2n_android/CHANGELOG_zh)
Hin2n最新版本可在[release地址](https://github.com/switch-iot/n2n_vLTS/releases)查看下载。

### Hin2n开发计划
详细开发计划请见[`Projects`](https://github.com/switch-iot/n2n_vLTS/projects)。
大家如果有新需求和想法，任何意见建议均可提交在[`issues`](https://github.com/switch-iot/n2n_vLTS/issues)中，我们将会酌情安排开发计划。您的关注就是我们的动力。

### 技术原理
- VPNService
> Hin2n基于安卓原生提供的VPNService，通过VPNService建立tun虚拟网卡，与supernode和edge通讯。
- tun2tap
> 安卓上层仅支持建立tun虚拟网卡，仅是TCP/IP网络层，而n2n协议依赖tap虚拟网卡，需要对数据链路层的支持，因此我们模拟了数据链路层，并实现了ARP协议。
- n2n protocol
> Hin2n对n2n协议的支持是采用jni的方式，native方法可以尽量复用原n2n项目的代码。

## n2n协议版本
n2n项目现有三个主流版本
- ntop.org大神们维护的v1版本，项目地址：https://github.com/meyerd/n2n.git(n2n_v1)
- ntop.org大神们维护的v2版本，项目地址：https://github.com/ntop/n2n.git
- meyerd大神维护的[v2s版本](#关于v2s版本)，项目地址：https://github.com/meyerd/n2n.git(n2n_v2)

### 关于v2s版本
v2s版本是N2N交流QQ群(256572040)中对meyerd大神维护的v2版本(又称v2.1)的命名，即v2升级版，该版本与ntop.org大神们维护的v2版本并不互通，为避免混淆，群友们对该项目另行命名。

## 项目开发/编译说明
### Hin2n
- git clone https://github.com/switch-iot/n2n_vLTS.git `--recurse-submodules`
- windows环境下需要在项目文件夹下执行`link.bat`，用于替换linux下的符号链接
- Hin2n_android目录即是Hin2n项目安卓源码目录
- Hin2n_android目录下执行`gradlew assemble`编译
- Hin2n_android项目的gradle是2.14.1版本，如需4.4版本的gradle，请将分支`dev_android_gradle4.4`下的文件拷贝至分支`marster`/`dev_android`下，覆盖相应的文件

### 关于开源协议
该项目以[`GPLv3`](LICENSE)协议进行开源，与n2n原有开源协议保持一致，也希望大家支持并遵守本项目的开源协议。

## 为Hin2n做贡献
Hin2n是一个免费且开源的n2n项目，我们欢迎任何人为其开发和进步贡献力量。
- 在使用过程中出现任何问题，可以通过[`issues`](https://github.com/switch-iot/n2n_vLTS/issues) 来反馈
- Bug的修复可以直接提交`Pull Request`到`android_dev`分支
- 如果是增加新的功能特性，请先创建一个[`issues`](https://github.com/switch-iot/n2n_vLTS/issues)并做简单描述以及大致的实现方法，提议被采纳后，就可以创建一个实现新特性的 Pull Request
- 欢迎对说明文档做出改善，帮助更多的人使用`Hin2n`，特别是英文文档
- 如果您觉得Hin2n对您有帮助，欢迎您关注该项目，并给项目点个`Star`

### 贡献者
- [`lucktu`](https://github.com/lucktu)是Hin2n项目的发起人，对该项目起到至关重要的作用，感谢[`lucktu`](https://github.com/lucktu)对该项目的组织、推广、测试等工作
- [`zhangbz`](https://github.com/zhangbz)主要负责Android层面的开发，在项目最困难的时候，给予了强有力的支持，[`zhangbz`](https://github.com/zhangbz)的参与，使得该项目得以继续
- 同时也感谢广大群友对我们的支持

## 交流群
- Hin2n交流群： 769731491(QQ群号)
- N2N交流群： 256572040(QQ群号)
