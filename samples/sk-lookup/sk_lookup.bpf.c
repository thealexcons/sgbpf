
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SOCKETS_ALLOWED 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_ports SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} map_socket SEC(".maps");


SEC("sk_lookup")
int dispatch_prog(struct bpf_sk_lookup* ctx) {
	const __u32 zero = 0;

    __u16 port = ctx->local_port;   // NOTE: this is in host byte order
    __u8* open = bpf_map_lookup_elem(&map_ports, &port);
    if (!open)
        return SK_DROP;

    struct bpf_sock* sk = bpf_map_lookup_elem(&map_socket, &zero);
    if (!sk)
        return SK_DROP;

    long err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return err ? SK_DROP : SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";