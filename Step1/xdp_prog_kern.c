// SPDX-License-Identifier: GPL-2.0
/* XDP program per AF_XDP socket - Versione semplice
 * Redirigi tutti i pacchetti UDP al socket AF_XDP
 * Compatibile con RXDROP e L2FWD
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Mappa per i socket AF_XDP\
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
   
    // Verifica lunghezza minima per Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
   
    struct ethhdr *eth = data;
   
    // FILTRO ARP: Droppa pacchetti ARP - CONFRONTA IN NETWORK BYTE ORDER
    if (eth->h_proto == bpf_htons(ETH_P_ARP))
        return XDP_DROP;
   
    // Solo pacchetti IP - CONFRONTA IN NETWORK BYTE ORDER  
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
   
    // Verifica lunghezza per IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
   
    struct iphdr *ip = data + sizeof(struct ethhdr);
   
    // Solo pacchetti UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
   
    // Redirigi tutti i pacchetti UDP al socket AF_XDP
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

char _license[] SEC("license") = "GPL";