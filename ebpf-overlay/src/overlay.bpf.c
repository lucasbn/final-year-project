//go:build ignore
#include <linux/bpf.h>
#include "overlay.h"
#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 enid = 1;
    bpf_map_update_elem(&enids_map, &pid_tgid, &enid, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&enids_map, &pid_tgid);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct sys_enter_bind_ctx *ctx) {
    // Check if the current process is in a namespace.
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *enid = bpf_map_lookup_elem(&enids_map, &pid_tgid);
    if (enid == NULL) {
        // Allow the system call to execute normally
        bpf_printk("Process is not in an eBPF namespace");
        return 0;
    }

    // Fetch the eBPF namespace
    struct ebpf_ns *ns = bpf_map_lookup_elem(&ebpf_ns_map, enid);
    if (ns == NULL) {
        bpf_printk("eBPF namespace does not exist");
        return 0;
    }

    // Read the sockaddr_in from userspace
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        bpf_printk("Failed to read socket");
        return 0;
    }
    // TODO: Add logic to check for TCP/IP

    // TEMPORARY PROTECTION: don't interfere with other processes, limit this to
    // attempts to bind to port 8000
    if (ntohs(addr.sin_port) != 8000) {
        bpf_printk("Port is not 8000");
        return 0;
    }

    __u32 requested_ip = ntohl(addr.sin_addr.s_addr);
    __u16 requested_port = ntohs(addr.sin_port);

    // First check that the requested IP address is either IN_ADDR_ANY (0.0.0.0)
    // or the IP address assigned to the eBPF namespace
    if (requested_ip != 0 && requested_ip != ns->ip) {
        bpf_printk("IP address does not match the namespace");
        return -1;
    }

    // Now check that the requested port is available within the eBPF namespace
    __u32 ns_to_host_key = (requested_ip * 100000) + requested_port;
    struct ip_port_pair *mapping = bpf_map_lookup_elem(&ns_to_host_map, &ns_to_host_key);
    if (mapping != NULL) {
        bpf_printk("Port already in use");
        return -1;
    }

    // Assign a random host port number
    __u32 host_port = bpf_get_prandom_u32() % 64512 + 1024;
    
    // Update ns_to_host_map and host_to_ns_map so that we can reuse these
    // mappings in the future
    struct ip_port_pair ns_to_host_value = {.ip = 0, .port = host_port};
    if (bpf_map_update_elem(&ns_to_host_map, &ns_to_host_key, &ns_to_host_value, BPF_ANY) < 0) {
        return 0;
    }

    __u32 host_to_key = host_port;
    struct ip_port_pair host_to_ns_value = {.ip = requested_ip, .port = requested_port};
    if (bpf_map_update_elem(&ns_to_host_map, &host_to_key, &host_to_ns_value, BPF_ANY) < 0) {
        return 0;
    }

    // Update the bind syscall arguments to actually bind to IN_ADDR_ANY and the
    // assigned host port number
    addr.sin_addr.s_addr = htonl(0);
    addr.sin_port = htons(host_port);
    if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };

    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct sys_enter_connect_ctx *ctx) {
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        return 0;
    }

    __u32 requested_ip = ntohl(addr.sin_addr.s_addr);
    __u16 requested_port = ntohs(addr.sin_port);

    // Check if a mapping exists for the requested ip and port number
    __u32 ns_to_host_key = (requested_ip * 100000) + requested_port;
    struct ip_port_pair *mapping = bpf_map_lookup_elem(&ns_to_host_map, &ns_to_host_key);
    if (mapping == NULL) {
        return 0;
    }

    // Update the connect syscall arguemnts to connect to the correct ip address
    // and port number
    addr.sin_addr.s_addr = htonl(mapping->ip);
    addr.sin_port = htons(mapping->port);
    if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };
    return 0;
}

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct sys_enter_getsockname_ctx *ctx) {
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0);
    addr.sin_port = htons(60);
    if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };

    return 0;
}


SEC("kprobe/sys_getsockname")
int handle_getsockname_entry(struct pt_regs *ctx)
{
    bpf_override_return(ctx, 0);
    return 0;
}q

// SEC("tp/syscalls/sys_exit_getsockname")
// int tp_sys_exit_getsockname(struct sys_exit_getsockname_ctx *ctx) {
//     /* At the syscall entry point, we stored some fields of sockaddr_in struct
//      * in a map so that we could access them here.*/
//     __u64 pid_tgid = bpf_get_current_pid_tgid();
//     struct sockaddr_data *data;
//     data = bpf_map_lookup_elem(&fd_sock_map, &pid_tgid);
//     if (ctx->ret < 0 || data == NULL) {
//         bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
//         return 0;
//     }
    
//     /* Read the sockaddr_in from userspace */
//     struct sockaddr_in addr;
//     if (bpf_probe_read_user(&addr, sizeof(addr), data->uaddr_ptr) < 0) {
//         return 0;
//     }

//     __u32 old_ip_addr = ntohl(addr.sin_addr.s_addr);
//     __u16 old_port = ntohs(addr.sin_port);

//     __u32 key = (old_ip_addr * 100000) + old_port;

//     struct ip_port_pair *mapping = bpf_map_lookup_elem(&ip_port_map, &key);
//     if (mapping == NULL) {
//         bpf_printk("no mapping found! %d\n", key);
//         return 0;
//     }

//     addr.sin_addr.s_addr = htonl(mapping->ip);
//     addr.sin_port = htons(mapping->port);
//     if (bpf_probe_write_user(data->uaddr_ptr, &addr, sizeof(addr))) {
//         return 0;
//     };

//     bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
//     return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";