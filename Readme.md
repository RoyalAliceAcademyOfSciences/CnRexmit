CnRexmit是一款用于应对GFW随机丢包的小工具，同时支持在墙外或在墙内使用，可以把过墙数据的丢包率从50%左右降低到22%左右，通过增加冗余牺牲带宽的方式来换取连接的稳定性。

#编译说明
##Windows环境
需要 WinPcap 4.1.2 Developer's Pack 下载地址：http://www.winpcap.org/devel.htm
CMakeLists.txt编写并不规范，TARGET_LINK_LIBRARIES中包含 WinPcap 库的位置是本机的硬编码，请根据需要自行修改路径。
##Linux环境
需要 libpcap 与 libgeoip 库支持

#使用方法
CnRexmit [-i inteface] [-c Country Code] [-o]

#参数说明
-i 网卡ID，不使用此参数时所有网卡的ID会在列表中显示，需手动输入
-c 国家代码，默认为CN，通常不需要做更改
-o 在墙外的同学请增加此参数，用于反转工作模式，将发往墙内的数据包加倍
