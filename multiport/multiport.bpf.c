#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "multiport.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct sys_enter_bind_ctx *ctx) {
    /* Read the sockaddr_in from userspace */
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uaddr_ptr) < 0) {
        return 0;
    }

    /* Only run our program if the user is trying to bind to port 3000 - this is
     * just precautionary as I don't want to overwrite for any core services
     * that may be expecting a particular port. This could most likely (?) be
     * relaxed to something like `port >= 1024` (below which have special
     * reservations). */
    if (ntohs(addr.sin_port) != 3000) {
        return 0;
    }

    /* We want to keep track of the remappings that we make so that we can mask
     * it to any observers using `getsockname` to inspect the port number. */
    __u32 old_port = ntohs(addr.sin_port);
    __u32 new_port = bpf_get_prandom_u32() % 64512 + 1024;
    if (bpf_map_update_elem(&sock_port_map, &new_port, &old_port, BPF_ANY) < 0) {
        return 0;
    }

    /* Overwrite the userspace memory that contains the sockaddr_in with our new
     * sockaddr_in struct that contains the remapped port. */
    addr.sin_port = htons(new_port);
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


    /* Check the map created when we bound our socket to a port to see if we've
     * remapped it. */
    __u32 port = ntohs(addr.sin_port);
    __u32 *mapping = bpf_map_lookup_elem(&sock_port_map, &port);
    if (mapping == NULL) {
        bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
        return 0;
    }

    /* If we have remapped the port, we need to update the userspace memory
     * containing the sockaddr_in struct so that it contains the original port
     * that the process requested the socket be bound to. */
    addr.sin_port = htons(*mapping);
    bpf_probe_write_user(data->uaddr_ptr, &addr, sizeof(addr));

    bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";