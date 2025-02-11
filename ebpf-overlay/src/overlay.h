//go:build ignore
#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u32);
} pid_enid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ebpf_ns);
} ebpf_ns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ebpf_veth);
} ebpf_veth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct ebpf_bridge);
} ebpf_bridge_map SEC(".maps");

//////////////////////////////


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ip_port_pair);
} ns_to_host_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ip_port_pair);
} host_to_ns_map SEC(".maps");

//////////////////////////////


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct sockaddr_data);
} fd_sock_map SEC(".maps");

struct sockaddr_data {
    long uaddr_ptr;
    long addrlen;
};

struct sys_enter_bind_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long fd;
    void *uaddr_ptr;
    long addrlen;
};

struct sys_enter_connect_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long fd;
    void *uaddr_ptr;
    long addrlen;
};

struct sys_enter_getsockname_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long fd;
    void *uaddr_ptr;
    long addrlen;
};

struct sys_exit_getsockname_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long ret;
};

struct trace_entry {
    unsigned short type;     // Event type identifier
    unsigned char flags;     // Trace flags
    unsigned char preempt_count; // Preemption counter
    int pid;                 // Process ID associated with the event
};

struct trace_event_raw_inet_sock_set_state {
    struct trace_entry ent;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    char __data[0];
};