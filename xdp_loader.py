#!/usr/bin/python
#
# xdp_redirect_map.py Redirect the incoming packet to another interface
#                     with the helper: bpf_redirect_map()
#
# Copyright (c) 2018 Gary Lin
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode(XDP generic)")
    print("       -X: use XDP Native mode")
    print("       -H: use hardware offload mode")
    print("e.g.: {0} -X eth0\n".format(sys.argv[0]))
    exit(1)


offload_device = None

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()
if len(sys.argv) == 2:
    device = sys.argv[1]
elif len(sys.argv) == 3:
    device = sys.argv[2]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= (1 << 1)
    if "-X" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= (1 << 0)
    if "-H" in sys.argv:
        # XDP_FLAGS_HW_MODE
        # maptype = "array"
        offload_device = device
        flags |= (1 << 3)

mode = BPF.XDP
ip = pyroute2.IPRoute()

# load BPF program
b = BPF(src_file = "topk_xdp.c", cflags=["-w"], device=offload_device)
in_fn = b.load_func("topk", mode, offload_device)

if mode == BPF.XDP:
	b.attach_xdp(device, in_fn, flags)

rxcnt = b.get_table("rxcnt")
globalhash = b.get_table("globalhash")
print("Printing redirected packets, hit CTRL+C to stop")
while 1:
    try:
        val = rxcnt.sum(0).value
        if val:
            print("{} pkt/s".format(val))
        keys = globalhash.items()
        for k in range(len(keys)):
            print(hex(keys[k][0].value), "=", keys[k][1].value)
        print("ebpf running. hit CTRL+C to stop")
        time.sleep(4)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break;

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
#else:
