#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

////////////////////////////////////////////////////////////////
//// bind (enter)
////////////////////////////////////////////////////////////////
struct sys_enter_bind_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long fd;

    /* Pointer to userspace memory containing the sockaddr_in structure */
    void *uaddr_ptr;

    long addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} sock_port_map SEC(".maps");

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct sys_enter_bind_ctx *ctx) {
    struct sockaddr_in addr;

    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        bpf_printk("Failed to read sockaddr from user memory\n");
        return 0;
    }

    /* Only run our program if the user is trying to bind to port 3000 */
    if (ntohs(addr.sin_port) != 3000) {
        return 0;
    }

    /* Update the mapping from new port -> old port */
    __u32 old_port = ntohs(addr.sin_port);
    __u32 new_port = bpf_get_prandom_u32() % 64512 + 1024;
    bpf_map_update_elem(&sock_port_map, &new_port, &old_port, BPF_ANY);

    /* Overwrite bind args with new port */
    addr.sin_port = htons(new_port);
    bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr));

    return 0;
}


////////////////////////////////////////////////////////////////
//// getsockname (enter)
////////////////////////////////////////////////////////////////
struct sys_enter_getsockname_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;


    long syscall_nr;
    long fd;

    /* Pointer to userspace memory containing the sockaddr_in structure */
    void *uaddr_ptr;

    long addrlen;
};

struct sockaddr_data {
    void *uaddr_ptr;
    long addrlen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);      // PID/TID
    __type(value, struct sockaddr_data);
} fd_sock_map SEC(".maps");

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct sys_enter_getsockname_ctx *ctx) {
    bpf_printk("Called getsockname\n");

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sockaddr_data data = {
        .uaddr_ptr = ctx->uaddr_ptr,
        .addrlen = ctx->addrlen,
    };

    bpf_map_update_elem(&fd_sock_map, &pid_tgid, &data, BPF_ANY);
    return 0;
}

////////////////////////////////////////////////////////////////
//// getsockname (exit)
////////////////////////////////////////////////////////////////
struct sys_exit_getsockname_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long syscall_nr;
    long ret;
};

// Figure out a way to pass the uaddr_ptr from the bind to this program,
// probably via a map.
//
// Actually need to do this in the sys_enter_getsockname so that we can
// associate a particular PID
SEC("tp/syscalls/sys_exit_getsockname")
int tp_sys_exit_getsockname(struct sys_exit_getsockname_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr_data *data;

    // Retrieve stored data
    data = bpf_map_lookup_elem(&fd_sock_map, &pid_tgid);
    if (!data || ctx->ret < 0) {
        bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
        return 0;
    }
    
    struct sockaddr_in addr;

    if (bpf_probe_read_user(&addr, sizeof(addr), data->uaddr_ptr) < 0) {
        bpf_printk("Failed to read sockaddr from user memory\n");
        return 0;
    }

    __u32 port = ntohs(addr.sin_port);

    // Look up in map to see if we've masked this
    __u32 *mapping = bpf_map_lookup_elem(&sock_port_map, &port);
    if (mapping == NULL) {
        bpf_printk("No mapping for %d\n", port);
        bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
        return 0;
    }

    bpf_printk("Overwriting port\n");


    addr.sin_port = htons(*mapping);
    bpf_probe_write_user(data->uaddr_ptr, &addr, sizeof(addr));

    // Cleanup the map entry
    bpf_map_delete_elem(&fd_sock_map, &pid_tgid);

    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
