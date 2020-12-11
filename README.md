# XDP-tutorial

  - examples to run eBPF at various hook points


There are 2 ways to compile and run eBPF programs:

  - Using bcc[https://github.com/iovisor/bcc] and python bindings.
    This is the easier way of running stand alone bpf programs.
  - Using llvm + clang directly and libbpf.
    This allows better integration of bpf into larger C/C++ projects.

## Background readings

    TBD

## Useful Information and Tools


***Kernel Versions***
Newer kernel is always preferred as new features are added with almost every kernel minor version.[https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md]

***bpftool***
This is the tool to interact with bpf programs in shell 
 - Installation:
    1. Using the kernel source code
        ```
        $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
        $ cd linux
        $ cd tools/bpf/bpftool
        $ make
        (# make install)
        (# make doc doc-install)
        ```
    2. Using libbpf repo [https://github.com/libbpf/libbpf/]
        Should be quicker, but haven't tried.
 - Usage:
    `bpftool` can be used to interact with bpf objects from shell, a very convinent debugging tool.
    ```
    Usage: bpftool [OPTIONS] OBJECT { COMMAND | help }
       bpftool batch file FILE
       bpftool version

       OBJECT := { prog | map | link | cgroup | perf | net | feature | btf | gen | struct_ops | iter }
       OPTIONS := { {-j|--json} [{-p|--pretty}] | {-f|--bpffs} |
                    {-m|--mapcompat} | {-n|--nomount} }

    ```


***ip link***
`ip link show` can be used to check the hook point of xdp programs
```
12: enp4s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:15:4d:13:3d:12 brd ff:ff:ff:ff:ff:ff
    prog/xdp id 151
```
Possible hookpoint tags are
`xdp`           native XDP mode, using XDP hookpoint with driver support
`xdpgeneric`   generic XDP mode, using TC hookpoint without driver support
`xdpoffload`   offloaded XDP mode, using supported nics, e.g. Netronome


` sudo ip link set dev enp4s0 xdp off` can also be used to purge all ebpf/xdp programs hooked to a specific nic.


## Running ebpf/XDP with python and bcc
 - Installation
    [https://github.com/iovisor/bcc/blob/master/INSTALL.md]

NOTE: different bcc tool may have slightly different API, so the example program may need some tweek to work with latest bcc relase.
***example1***

 This example will cover:
 - load and run XDP program at various hookpoint
 - different types of bpf maps
 - interact with eBPF objects in both python and shell

 There are 2 files in this example: 
 - `example1.c` contains the eBPF program.
 - `example1_loader.py` is the bcc binding that does compile, load, interact with ebpf all-in-one.

 
 


## Running ebpf/XDP using libbpf and LLVM + Clang

Pending...
