//go:build ignore
#pragma once

struct ebpf_ns {
    __u32 ns_id;
    __u32 veths[1];
};

struct ebpf_veth {
    __u32 veth_id;
    __u32 pair_veth_id;
    __u32 bridge_id;
    __u32 ip_addr;
    __u32 host_interface;
};

struct ebpf_bridge {
    __u32 bridge_id;
    __u32 veths[2];
};

struct ip_port_pair {
    __u32 ns_id;
    __u32 ip;
    __u16 port;
};
