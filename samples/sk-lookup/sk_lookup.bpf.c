
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
    __uint(pinning, LIBBPF_PIN_BY_NAME); // sudo rm /sys/fs/bpf/map_socket
} map_socket SEC(".maps");

struct sk_storage {
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct sk_storage);
    __uint(max_entries, 0);
} map_sk_storage SEC(".maps");

SEC("sk_lookup")
int dispatch_prog(struct bpf_sk_lookup* ctx) {
	const __u32 zero = 0;

    // bpf_printk("Got message here: %d", ctx->local_port);

    __u16 port = ctx->local_port;   // NOTE: this is in host byte order
    __u8* open = bpf_map_lookup_elem(&map_ports, &port);
    if (!open)
        return SK_PASS;

    if (ctx->protocol == 6) {
        bpf_printk("got tcp packe");
    } else if (ctx->protocol == 17) {
        bpf_printk("got udp packet");
    }
    bpf_printk("Got pk with relevant port: %d", port);

    struct bpf_sock* sk = bpf_map_lookup_elem(&map_socket, &zero);
    if (!sk) {
        bpf_printk("could not find sk in map!??");
        return SK_DROP;
    }

    bpf_printk("Got bpf_sock from map: %d", sk->src_port);

    // Unknown func when loading.... maybe include path is not using correct
    // version of BPF??
    // struct sk_storage* stg = bpf_sk_storage_get(&map_sk_storage, sk, 0, 0);
    // if (!stg)
        // return SK_DROP;
    // bpf_printk("Got data storage from map: %d", stg->data);


    long err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    return err ? SK_DROP : SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";