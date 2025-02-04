#pragma once

struct __attribute__((aligned(8))) ip_port_pair {
    __u32 ip;
    __u16 port;
};
