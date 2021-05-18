# Overview 

This project is a port of the l4lb project[[1]] from Netronome/bpf-samples using cilium/ebpf[[2]].

# :warning: Warning

cilium/ebpf does not support attach/detach the ebpf program to network interfaces.
In this project, `netlink.LinkSetXdpFd`[[2]] is used to attach xdp to the interface.
Also, `defer Close()` for BPF map does not work properly for reasons that I have not figured out.

# Description 

- `main.go`

  Golang source file. It is designed to create BPF map, attach `xdp.elf` to a specific interface, and output statistics.  

- `ebpf_prog/xdp.c`

  XDP source code to be built with `xdp.elf`. This includes the implementation for the linux jenkins hash[[4]] loadbalancer.

# Demo 

To create a virtual network using the alias `t` of `testenv.sh` (refer [[5]]), 
```
t setup --name l4lb --legacy
t exec --name l4lb -- ip addr show veth0
```

In my case, IP address of `veth0` in namespace `l4lb` is '10.11.1.2'. 
```
2: veth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 12:55:3e:d7:8e:ef brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.11.1.2/24 scope global veth0
       valid_lft forever preferred_lft forever
    inet6 fc00:dead:cafe:1::2/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::1055:3eff:fed7:8eef/64 scope link
       valid_lft forever preferred_lft forever
```

The default auguments for user program `main` is `-iface veth0`. 
So the followings are the same. 

```
t exec --name l4lb -- ./main 
# t exec --name l4lb -- ./main -iface veth0
```

To generate massive traffic, 
```
hping3 10.11.1.2 --rand-source -i l4lb --flood
```

Result: 
```
10.0.89.127        74151 pkts (      11229 pps )        5487 Kbytes (      6 Mbits/s )
10.0.214.65        74022 pkts (      11042 pps )        5477 Kbytes (      6 Mbits/s )
10.0.178.75        74038 pkts (      10871 pps )        5478 Kbytes (      6 Mbits/s )
10.0.24.77         74365 pkts (      11086 pps )        5503 Kbytes (      6 Mbits/s )
10.0.199.54        74077 pkts (      10829 pps )        5481 Kbytes (      6 Mbits/s )
10.0.234.48        74344 pkts (      11145 pps )        5501 Kbytes (      6 Mbits/s )
10.0.175.130       73848 pkts (      10953 pps )        5464 Kbytes (      6 Mbits/s )
10.0.244.158       74496 pkts (      11253 pps )        5512 Kbytes (      6 Mbits/s )
10.0.185.52        74161 pkts (      11016 pps )        5487 Kbytes (      6 Mbits/s )
10.0.159.176       73982 pkts (      11135 pps )        5474 Kbytes (      6 Mbits/s )
10.0.125.19        74326 pkts (      10943 pps )        5500 Kbytes (      6 Mbits/s )
10.0.56.49         74399 pkts (      11180 pps )        5505 Kbytes (      6 Mbits/s )
10.0.75.197        73988 pkts (      11098 pps )        5475 Kbytes (      6 Mbits/s )
10.0.75.209        74814 pkts (      11082 pps )        5536 Kbytes (      6 Mbits/s )
10.0.92.11         74176 pkts (      11217 pps )        5489 Kbytes (      6 Mbits/s )
10.0.31.144        74022 pkts (      11015 pps )        5477 Kbytes (      6 Mbits/s )
10.0.32.134        73652 pkts (      11284 pps )        5450 Kbytes (      6 Mbits/s )
10.0.50.179        74238 pkts (      11002 pps )        5493 Kbytes (      6 Mbits/s )
10.0.0.57          74174 pkts (      10920 pps )        5488 Kbytes (      6 Mbits/s )
10.0.16.109        73522 pkts (      11032 pps )        5440 Kbytes (      6 Mbits/s )
10.0.192.32        73717 pkts (      10856 pps )        5455 Kbytes (      6 Mbits/s )
10.0.90.135        74192 pkts (      11111 pps )        5490 Kbytes (      6 Mbits/s )
10.0.75.126        74008 pkts (      11039 pps )        5476 Kbytes (      6 Mbits/s )
10.0.63.10         73825 pkts (      10959 pps )        5463 Kbytes (      6 Mbits/s )
10.0.161.129       74380 pkts (      11247 pps )        5504 Kbytes (      6 Mbits/s )
10.0.129.60        74158 pkts (      10923 pps )        5487 Kbytes (      6 Mbits/s )
10.0.143.99        73967 pkts (      11037 pps )        5473 Kbytes (      6 Mbits/s )
10.0.32.35         73347 pkts (      10970 pps )        5427 Kbytes (      6 Mbits/s )
10.0.14.88         73978 pkts (      11158 pps )        5474 Kbytes (      6 Mbits/s )
10.0.23.41         74312 pkts (      10997 pps )        5499 Kbytes (      6 Mbits/s )
10.0.90.214        74186 pkts (      11080 pps )        5489 Kbytes (      6 Mbits/s )
10.0.181.34        73981 pkts (      11038 pps )        5474 Kbytes (      6 Mbits/s )
```

[1]: https://github.com/Netronome/bpf-samples/tree/master/l4lb
[2]: https://github.com/cilium/ebpf
[3]: https://github.com/vishvananda/netlink
[4]: https://github.com/torvalds/linux/blob/master/tools/include/linux/jhash.h
[5]: https://github.com/xdp-project/xdp-tutorial
