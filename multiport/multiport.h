#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>

// #include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// This map contains the original port numbers that a particular port was
// requested to be bound to.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} sock_port_map SEC(".maps");

struct sockaddr_data {
    void *uaddr_ptr;
    long addrlen;
};

// This map is used to pass the sockaddr_data struct from the getsockname entry
// point to the exit point. The key is the PID of the process making the syscall.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct sockaddr_data);
} fd_sock_map SEC(".maps");

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
