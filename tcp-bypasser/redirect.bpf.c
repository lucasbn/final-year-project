#include <linux/bpf.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define LOCALHOST_IPV4 16777343

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, int);
    __type(value, int);
} sock_map SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("sk_msg")
int sk_msg_prog(struct sk_msg_md *msg)
{   
    if(msg->remote_ip4 != LOCALHOST_IPV4 || msg->local_ip4!= LOCALHOST_IPV4)
        return SK_PASS;

    int key = (bpf_htonl(msg->local_port) * 1000) + msg->remote_port;

    return bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
}

SEC("sockops")
int sockops_prog(struct bpf_sock_ops *skops){

    __u32 op = skops->op;
    if (op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
    && op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return BPF_OK;
    }

    if(skops->remote_ip4 != LOCALHOST_IPV4 || skops->local_ip4!= LOCALHOST_IPV4) {
        return BPF_OK;
    }

    int key = (skops->remote_port * 1000) + bpf_htonl(skops->local_port);

    bpf_sock_hash_update(skops, &sock_map, &key, BPF_NOEXIST);

    return BPF_OK;
}