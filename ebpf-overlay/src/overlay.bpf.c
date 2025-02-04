#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "overlay.h"
#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct sys_enter_bind_ctx *ctx) {
    /* Read the sockaddr_in from userspace */
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        return 0;
    }

    __u32 old_ip_addr = ntohl(addr.sin_addr.s_addr);
    __u16 old_port = ntohs(addr.sin_port);

    /* Temporary, don't want to have mappings for all bind syscalls, just
     * keeping to port 8000 */
    if (ntohs(addr.sin_port) != 8000) {
        return 0;
    }

    __u32 key = (old_ip_addr * 100000) + old_port;

    struct ip_port_pair value = {
        .ip = 0,
        .port = 3000,
    };

    if (bpf_map_update_elem(&ip_port_map, &key, &value, BPF_ANY) < 0) {
        return 0;
    }

    ///

    __u32 reverse_key = 3000;

    struct ip_port_pair reverse_value = {
        .ip = old_ip_addr,
        .port = old_port,
    };

    if (bpf_map_update_elem(&ip_port_map, &reverse_key, &reverse_value, BPF_ANY) < 0) {
        return 0;
    }

    ///

    addr.sin_addr.s_addr = htonl(value.ip);
    addr.sin_port = htons(value.port);
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

    __u32 old_ip_addr = ntohl(addr.sin_addr.s_addr);
    __u16 old_port = ntohs(addr.sin_port);

    __u32 key = (old_ip_addr * 100000) + old_port;

    if (ntohs(addr.sin_port) != 8000) {
        return 0;
    }

    struct ip_port_pair *mapping = bpf_map_lookup_elem(&ip_port_map, &key);
    if (mapping == NULL) {
        bpf_printk("no mapping found! %d\n", key);
        return 0;
    }

    addr.sin_addr.s_addr = htonl(mapping->ip);
    addr.sin_port = htons(mapping->port);
    if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };
    return 0;
}

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct sys_enter_getsockname_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sockaddr_data data = {
        .uaddr_ptr = ctx->uaddr_ptr,
        .addrlen = ctx->addrlen,
    };

    /* We want to be able to access the uaddr_ptr and addrlen at the exit point
     * of the getsockname syscall, so we store them in a map keyed by the PID. */
    bpf_map_update_elem(&fd_sock_map, &pid_tgid, &data, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getsockname")
int tp_sys_exit_getsockname(struct sys_exit_getsockname_ctx *ctx) {
    /* At the syscall entry point, we stored some fields of sockaddr_in struct
     * in a map so that we could access them here.*/
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sockaddr_data *data;
    data = bpf_map_lookup_elem(&fd_sock_map, &pid_tgid);
    if (ctx->ret < 0 || data == NULL) {
        bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
        return 0;
    }
    
    /* Read the sockaddr_in from userspace */
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), data->uaddr_ptr) < 0) {
        return 0;
    }

    __u32 old_ip_addr = ntohl(addr.sin_addr.s_addr);
    __u16 old_port = ntohs(addr.sin_port);

    __u32 key = (old_ip_addr * 100000) + old_port;

    struct ip_port_pair *mapping = bpf_map_lookup_elem(&ip_port_map, &key);
    if (mapping == NULL) {
        bpf_printk("no mapping found! %d\n", key);
        return 0;
    }

    addr.sin_addr.s_addr = htonl(mapping->ip);
    addr.sin_port = htons(mapping->port);
    if (bpf_probe_write_user(data->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };

    bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";