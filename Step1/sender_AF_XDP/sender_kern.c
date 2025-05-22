#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_sender_func(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u64 *counter;
    
    counter = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (counter) {
        (*counter)++;
    }
    
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return bpf_redirect_map(&xsks_map, index, 0);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";