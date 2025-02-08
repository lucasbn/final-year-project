//go:build ignore
#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bpf/bpf_helpers.h>
#include "common.h"


// Map from PID to eNID (eBPF Namespace ID)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u32);
} enids_map SEC(".maps");

// Map from eNID to [struct ebpf_ns] which stores important metadata about the
// namespace (e.g available ip addresses and TCP port mappings)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ebpf_ns);
} ebpf_ns_map SEC(".maps");

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


// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1024);
//     __type(key, __u64);
//     __type(value, struct sockaddr_data);
// } fd_sock_map SEC(".maps");

// struct sockaddr_data {
//     void *uaddr_ptr;
//     long addrlen;
// };

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

// struct sys_exit_getsockname_ctx {
//     unsigned short common_type;
//     unsigned char common_flags;
//     unsigned char common_preempt_count;
//     int common_pid;

//     long syscall_nr;
//     long ret;
// };

struct trace_entry {
    unsigned short type;     // Event type identifier
    unsigned char flags;     // Trace flags
    unsigned char preempt_count; // Preemption counter
    int pid;                 // Process ID associated with the event
};


struct trace_event_raw_sched_process_exec {
    struct trace_entry ent;
    pid_t pid;               // Process ID
    int old_pid;             // Previous PID (if exec happened within a thread group)
    unsigned long filename;  // Pointer to the executed filename (char *)
    unsigned long argv;      // Pointer to the argv array
    unsigned long envp;      // Pointer to the envp array
};

struct trace_event_raw_sched_process_exit {
    struct trace_entry ent;
    pid_t pid;      // Process ID of the exiting process
    int prio;       // Process priority
};
