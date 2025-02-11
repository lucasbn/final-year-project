//go:build ignore
#include <linux/bpf.h>
#include "overlay.h"
#include "common.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) (((void *)PTR) + OFFSET > ((void *)END))

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct sys_enter_bind_ctx *ctx) {
    // Check if the current process is in a namespace.
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *enid = bpf_map_lookup_elem(&pid_enid_map, &pid_tgid);
    if (enid == NULL) {
        // Allow the system call to execute normally
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

    __u32 requested_ip = ntohl(addr.sin_addr.s_addr);
    __u16 requested_port = ntohs(addr.sin_port);

    // Check that the namespace has a veth defined, and then ensure that the
    // requested ip matches the IP assigned to that veth
    __u32 veth_id = ns->veths[0];
    struct ebpf_veth *veth = bpf_map_lookup_elem(&ebpf_veth_map, &veth_id);
    if (veth == NULL) {
        bpf_printk("Namespace does not have an interface");
        return 0;
    }

    if (requested_ip == 0) {
        requested_ip = veth->ip_addr;
    } else if (requested_ip != veth->ip_addr) {
        bpf_printk("IP address does not match the namespace");
        return 0;
    }


    // Now check that the requested port is available within the eBPF namespace
    __u32 ns_to_host_key = (requested_ip * 100000) + requested_port;
    struct ip_port_pair *mapping = bpf_map_lookup_elem(&ns_to_host_map, &ns_to_host_key);
    if (mapping != NULL) {
        bpf_printk("Port already in use");
        return 0;
    }

    // Assign a random host port number
    __u32 host_port = bpf_get_prandom_u32() % 64512 + 1024;
    
    // Update ns_to_host_map and host_to_ns_map so that we can reuse these
    // mappings in the future
    struct ip_port_pair ns_to_host_value = {.ip = 0, .port = host_port, .ns_id = 0};
    if (bpf_map_update_elem(&ns_to_host_map, &ns_to_host_key, &ns_to_host_value, BPF_ANY) < 0) {
        return 0;
    }

    __u32 host_to_ns_key = (0 * 100000) + host_port;
    struct ip_port_pair host_to_ns_value = {.ip = requested_ip, .port = requested_port, .ns_id = ns->ns_id};
    if (bpf_map_update_elem(&host_to_ns_map, &host_to_ns_key, &host_to_ns_value, BPF_ANY) < 0) {
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
        // If we have a mapping in the host_to_ns_map, then the user is trying
        // to connect with an IP/port pair that is owned by an eBPF namespace
        // and we should block it
        mapping = bpf_map_lookup_elem(&host_to_ns_map, &ns_to_host_key);
        if (mapping == NULL) {
            return 0;
        }

        // Block connection by assigning an invalid port number
        // TODO: this should probably be changed to a kprobe which supports
        // overriding syscall return values properly
        addr.sin_port = 0;
        if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
            return 0;
        };
        return 0;
    }

    // Check that there is a valid virtual network path from the calling process
    // to the server
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;
    __u32 *enid = bpf_map_lookup_elem(&pid_enid_map, &pid_tgid);
    if (enid == NULL) {
        // If it isn't in a namespace, there isn't a valid path
        return 0;
    }

    // Fetch the eBPF namespace
    struct ebpf_ns *ns = bpf_map_lookup_elem(&ebpf_ns_map, enid);
    if (ns == NULL) {
        bpf_printk("eBPF namespace does not exist");
        return 0;
    }

    // Fetch the veth interface
    struct ebpf_veth *veth = bpf_map_lookup_elem(&ebpf_veth_map, &ns->veths[0]);
    if (veth == NULL) {
        bpf_printk("veth does not exist");
        return 0;
    }

    // Fetch the other end of the veth
    struct ebpf_veth *veth_pair = bpf_map_lookup_elem(&ebpf_veth_map, &veth->pair_veth_id);
    if (veth_pair == NULL) {
        bpf_printk("veth pair does not exist");
        return 0;
    }

    // Fetch the bridge
    struct ebpf_bridge *bridge = bpf_map_lookup_elem(&ebpf_veth_map, &veth_pair->bridge_id);
    if (bridge == NULL) {
        bpf_printk("bridge does not exist");
        return 0;
    }

    // Loop through the veths in the bridge
    for (int i = 0; i < 2; i++) {
        if (bridge->veths[0] == veth_pair->veth_id) {
            continue;
        }
        
        // Fetch the veth interface
        struct ebpf_veth *br_veth = bpf_map_lookup_elem(&ebpf_veth_map, &bridge->veths[0]);
        if (br_veth == NULL) {
            bpf_printk("br_veth does not exist");
            return 0;
        }

        // Fetch the other end of the veth
        struct ebpf_veth *br_veth_pair = bpf_map_lookup_elem(&ebpf_veth_map, &br_veth->pair_veth_id);
        if (br_veth_pair == NULL) {
            bpf_printk("br_veth_pair pair does not exist");
            return 0;
        }

        if (requested_ip == br_veth_pair->ip_addr) {
            // Update the connect syscall arguemnts to connect to the correct ip address
            // and port number
            addr.sin_addr.s_addr = htonl(mapping->ip);
            addr.sin_port = htons(mapping->port);
            if (bpf_probe_write_user(ctx->uaddr_ptr, &addr, sizeof(addr))) {
                return 0;
            };
            return 0;
        }
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct sys_enter_getsockname_ctx *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;

    struct sockaddr_data data = {
        .uaddr_ptr = (long) ctx->uaddr_ptr,
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
    __u64 pid_tgid = bpf_get_current_pid_tgid() >> 32;

    __u32 *enid = bpf_map_lookup_elem(&pid_enid_map, &pid_tgid);
    if (enid == NULL) {
        // Allow the system call to execute normally
        return 0;
    }

    struct sockaddr_data *data;
    data = bpf_map_lookup_elem(&fd_sock_map, &pid_tgid);
    if (ctx->ret < 0 || data == NULL) {
        bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
        return 0;
    }
    
    /* Read the sockaddr_in from userspace */
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), (void *) data->uaddr_ptr) < 0) {
        return 0;
    }

    __u32 old_ip_addr = ntohl(addr.sin_addr.s_addr);
    __u16 old_port = ntohs(addr.sin_port);

    __u32 key = (old_ip_addr * 100000) + old_port;

    struct ip_port_pair *mapping = bpf_map_lookup_elem(&host_to_ns_map, &key);
    if (mapping == NULL) {
        return 0;
    }

    addr.sin_addr.s_addr = htonl(mapping->ip);
    addr.sin_port = htons(mapping->port);
    if (bpf_probe_write_user((void *) data->uaddr_ptr, &addr, sizeof(addr))) {
        return 0;
    };

    bpf_map_delete_elem(&fd_sock_map, &pid_tgid);
    return 0;
}


SEC("tracepoint/sock/inet_sock_set_state")
int sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Check if new state is a closed state 
    if (ctx->newstate == 5 || ctx->newstate == 6 || ctx->newstate == 7) {
        __u32 ip_addr = ((__u32) ctx->saddr[0] << 24) | 
                ((__u32) ctx->saddr[1] << 16) | 
                ((__u32) ctx->saddr[2] << 8)  | 
                ((__u32) ctx->saddr[3]);

        __u32 host_to_ns_key = (ip_addr * 100000) + ctx->sport;
        struct ip_port_pair *mapping = bpf_map_lookup_elem(&host_to_ns_map, &host_to_ns_key);
        if (mapping == NULL) {
            bpf_printk("nothing to remove %d %d", ip_addr, ctx->sport);
            return 0;
        }

        __u32 ns_to_host_key = (mapping->ip * 100000) + mapping->port;
        bpf_map_delete_elem(&ns_to_host_map, &ns_to_host_key);
        bpf_map_delete_elem(&host_to_ns_map, &host_to_ns_key);
        return 0;
    }

    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";