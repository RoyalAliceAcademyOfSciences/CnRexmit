# CnRexmit

CnRexmit 是一款用于应对 GFW 随机丢包的小工具，同时支持在墙外或在墙内使用。

使用本工具可以把过墙数据的丢包率从 50% 左右降低到 22% 左右，通过增加冗余牺牲带宽的方式来换取连接的稳定性。

## 编译说明

### Windows 环境

需要 WinPcap 4.1.2 Developer's Pack 下载地址： http://www.winpcap.org/devel.htm

CMakeLists.txt 编写并不规范，TARGET_LINK_LIBRARIES 中包含 WinPcap 库的位置是本机的硬编码，请根据需要自行修改路径。

### Linux 环境

需要 libpcap 与 libGeoIP 库支持

`gcc -lpcap -lGeoIP main.c -o CnRexmit`

## 使用方法

CnRexmit [-h] [-i inteface] [-c Country Code] [-o]

## 参数说明

  - `-h` 查看使用方法

  - `-i` 网卡 ID，不使用此参数时所有网卡的 ID 会在列表中显示，需手动输入

  - `-c` 国家代码，默认为 CN，通常不需要做更改

  - `-o` 在墙外的同学请增加此参数，用于反转工作模式，将发往墙内的数据包加倍

## 授权

本软件在 GNU General Public License version 2 (GPLv2) 下发布
