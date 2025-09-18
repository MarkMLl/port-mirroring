Significant changes were made during 2018, these were stored offline and are now being committed.

* On Debian the package libpcap0.8-dev or later is required as a prerequisite, with libnetfilter-log-dev optional.

* If the packet is explicitly marked as already being TZSP-encapsulated then drop it immediately. If it is Ethernet then look at the Ethertype, setting pIPHead so that we can check the destination etc. in an attempt to avoid loops, this should handle both straight Ethernet and VLAN traffic; also handle _RAW and _SLL as trivial. For the moment let anything else through.

* Accept encapsulating protocols (MPLS, PPoE and QinQ) and all IP6 without inspection of their content on the assumption that it will be destined for a non-local network so loops are unlikely.

* The TZSP protocol field needs to track the datalink layer to reflect what's actually been captured rather than assuming it's Ethernet.

* The DLC packet types now exceed 255 so more than 8 bits of the 16-bit protocol field are needed. It's probably safest to be absolutely blatant in breaking the TZSP encapsulation so that Wireshark comes up with a completely unambiguous warning that something unexpected has been seen. MarkMLl.

* If there is more than one interface being monitored then yield in an attempt to improve interleave. The -y option inverts the default behaviour.

* Added this to get the capturing device's MAC address for a TZSP tag.

* Added reopen loop, specifically to handle vanishing PPP interfaces.

Also see examples in port-mirroring.conf

This has been used fairly heavily in the context of a distributed routing system. Broadly speaking it stood up well, but there are a few residual problems when using multiple layers of encapsulation (from memory, VLAN in conjunction with PPPoE and L2TP). MarkMLl.


port-mirroring
================

## 原repo
<https://code.google.com/p/port-mirroring/>
原来的repo里面的git里没有代码, 不过还好代码量很小, 直接把源码导入了.

## 编译
openwrt下编译的Makefile在 openwrt/Makefile

1. 在openwrt源码目录, 创建目录 package/port-mirroring
2. 下载Makefile到这个目录
3. make menuconfig
4. make

## 预编译好的程序

<https://code.google.com/p/port-mirroring/downloads/list>

<https://github.com/Akagi201/port-mirroring>

## What is this "port mirroring"?

"Port mirroring"(SPAN) is required for a network sniffer to analysis a network. In case your switch/router does not have port mirroring feature, you can use this software solution to monitor network traffic.

This "port-mirroring" program can mirror traffic of adapter(s) to another adapter or to a remote computer. It is designed for openwrt and ddwrt, it also works in other linux systems.

Different to the "TEE" target of iptables, "port-mirroring" encapsulates a whole packet including ethernet headers using TSZP protocol <http://en.wikipedia.org/wiki/TZSP>.

"TEE" format mirroring is added in version 1.3. Since version 1.3, you can choose "TEE" or "TZSP" as the mirroring protocol.

## "TEE" or "TZSP"

"TEE" is an iptables routing target. It allows you to forward packets to another host. Iptables simply modifies the ethernet header of the original packets to the target host's MAC address. Therefore, you can not get the original source and destination mac addresses. Also, the target host must be in the same subnet as the mirroring source.

"TZSP" encapsulates a whole packet and forwards packets in udp protocol. Therefore the target host does not need to be in a same subnet. However, since a "TZSP" header is appended in each packet, your sniffer shall be able to strip "TZSP" headers to get the original packets. As I know, wireshark can do this.

## Usages
* install port-mirroring

* Edit /etc/config/port-mirroring
```
config 'port-mirroring'
       option "target" '192.168.1.20'      #Target remote ip address or another interface
       option 'source_ports' 'wlan0'       #Source mirrored interfaces
       option 'filter' ''                    #libpcap filter
       option 'protocol' 'TEE'             #TEE(default) or TZSP
```

* Start port-mirroring with debug
```
root@OpenWrt:~# port-mirroring --debug
```

* Start port-mirroring as a daemon
```
root@OpenWrt:~# /etc/init.d/port_mirroring start
```

* Stop port-mirroring
```
root@OpenWrt:~# /etc/init.d/port_mirroring stop
```

* Remove port-mirroring
```
root@OpenWrt:~# opkg remove port-mirroring
```

## Typical Usage

Suppose you have a linksys WRT54G router running openwrt backfire, now you want to monitor and filter client computers internet traffic. The steps:

* Install from prebuilt packages
* Edit mirroring settings
* Start port-mirroring
* Install an internet filtering program(eg: WFilter) in the remote computer to monitor and filter client computers.

## developer's blogs
* <http://blog.imfirewall.us/>
* <http://www.imfirewall.us/>



