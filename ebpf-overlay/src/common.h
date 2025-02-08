//go:build ignore
#pragma once

struct ip_port_pair {
    __u32 ip;
    __u16 port;
};

struct ebpf_ns {
    // The IP address that this namespace has been assigned
    __u32 ip;
};