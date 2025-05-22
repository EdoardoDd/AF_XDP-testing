/**
 * common_packet.c - Funzioni per la gestione dei pacchetti
 */
#include <string.h>  
#include <stdlib.h>  
#include <ctype.h>   
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "common_packet.h"


__sum16 csum16_add(__sum16 csum, __be16 addend)
{
    uint16_t res = (uint16_t)csum;

    res += (__u16)addend;
    return (__sum16)(res + (res < (__u16)addend));
}

__sum16 csum16_sub(__sum16 csum, __be16 addend)
{
    return csum16_add(csum, ~addend);
}

void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
    *sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}


void print_packet_info(void *data, size_t length)
{
    struct ethhdr *eth = data;
    uint16_t eth_type;
    uint8_t proto;
    void *next_hdr;
    
    if (length < sizeof(*eth)) {
        printf("Packet too small for Ethernet header\n");
        return;
    }
    
    eth_type = ntohs(eth->h_proto);
    
    printf("Ethernet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x, Type: 0x%04x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2], 
           eth->h_source[3], eth->h_source[4], eth->h_source[5],
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
           eth_type);
    
    next_hdr = (char *)eth + sizeof(*eth);
    
    switch (eth_type) {
    case ETH_P_IP: {
        struct iphdr *ip = next_hdr;
        
        if (length < sizeof(*eth) + sizeof(*ip)) {
            printf("  IPv4: Packet too small for IPv4 header\n");
            return;
        }
        
        printf("  IPv4: %u.%u.%u.%u -> %u.%u.%u.%u, Protocol: %u, Length: %u\n",
               (ip->saddr >> 0) & 0xff, (ip->saddr >> 8) & 0xff, 
               (ip->saddr >> 16) & 0xff, (ip->saddr >> 24) & 0xff,
               (ip->daddr >> 0) & 0xff, (ip->daddr >> 8) & 0xff, 
               (ip->daddr >> 16) & 0xff, (ip->daddr >> 24) & 0xff,
               ip->protocol, ntohs(ip->tot_len));
        
        proto = ip->protocol;
        next_hdr = (char *)ip + (ip->ihl * 4);
        
        switch (proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = next_hdr;
            
            if (length < sizeof(*eth) + (ip->ihl * 4) + sizeof(*tcp)) {
                printf("    TCP: Packet too small for TCP header\n");
                return;
            }
            
            printf("    TCP: Port %u -> %u, Flags: %c%c%c%c%c%c\n",
                   ntohs(tcp->source), ntohs(tcp->dest),
                   (tcp->fin ? 'F' : '.'), (tcp->syn ? 'S' : '.'),
                   (tcp->rst ? 'R' : '.'), (tcp->psh ? 'P' : '.'),
                   (tcp->ack ? 'A' : '.'), (tcp->urg ? 'U' : '.'));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = next_hdr;
            
            if (length < sizeof(*eth) + (ip->ihl * 4) + sizeof(*udp)) {
                printf("    UDP: Packet too small for UDP header\n");
                return;
            }
            
            printf("    UDP: Port %u -> %u, Length: %u\n",
                   ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr *icmp = next_hdr;
            
            if (length < sizeof(*eth) + (ip->ihl * 4) + sizeof(*icmp)) {
                printf("    ICMP: Packet too small for ICMP header\n");
                return;
            }
            
            printf("    ICMP: Type: %u, Code: %u\n", icmp->type, icmp->code);
            break;
        }
        default:
            printf("    IP Protocol: %u\n", proto);
        }
        break;
    }
    case ETH_P_IPV6: {
        struct ipv6hdr *ip6 = next_hdr;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        
        if (length < sizeof(*eth) + sizeof(*ip6)) {
            printf("  IPv6: Packet too small for IPv6 header\n");
            return;
        }
        
        inet_ntop(AF_INET6, &ip6->saddr, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6->daddr, dst, INET6_ADDRSTRLEN);
        
        printf("  IPv6: %s -> %s, Next Header: %u, Length: %u\n",
               src, dst, ip6->nexthdr, ntohs(ip6->payload_len));
        
        proto = ip6->nexthdr;
        next_hdr = (char *)ip6 + sizeof(*ip6);
        
        switch (proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = next_hdr;
            
            if (length < sizeof(*eth) + sizeof(*ip6) + sizeof(*tcp)) {
                printf("    TCP: Packet too small for TCP header\n");
                return;
            }
            
            printf("    TCP: Port %u -> %u, Flags: %c%c%c%c%c%c\n",
                   ntohs(tcp->source), ntohs(tcp->dest),
                   (tcp->fin ? 'F' : '.'), (tcp->syn ? 'S' : '.'),
                   (tcp->rst ? 'R' : '.'), (tcp->psh ? 'P' : '.'),
                   (tcp->ack ? 'A' : '.'), (tcp->urg ? 'U' : '.'));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = next_hdr;
            
            if (length < sizeof(*eth) + sizeof(*ip6) + sizeof(*udp)) {
                printf("    UDP: Packet too small for UDP header\n");
                return;
            }
            
            printf("    UDP: Port %u -> %u, Length: %u\n",
                   ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
            break;
        }
        case IPPROTO_ICMPV6: {
            struct icmp6hdr *icmp6 = next_hdr;
            
            if (length < sizeof(*eth) + sizeof(*ip6) + sizeof(*icmp6)) {
                printf("    ICMPv6: Packet too small for ICMPv6 header\n");
                return;
            }
            
            printf("    ICMPv6: Type: %u, Code: %u\n", icmp6->icmp6_type, icmp6->icmp6_code);
            break;
        }
        default:
            printf("    IPv6 Next Header: %u\n", proto);
        }
        break;
    }
    case ETH_P_ARP:
        printf("  ARP packet\n");
        break;
    default:
        printf("  Unknown Ethernet Type: 0x%04x\n", eth_type);
    }
    
    printf("  Hex Dump (first 32 bytes):\n  ");
    for (int i = 0; i < length && i < 32; i++) {
        printf("%02x ", ((unsigned char *)data)[i]);
        if ((i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n\n");
}


/**
 * Crea un pacchetto completo Ethernet/IP/UDP
 * 
 * @param buffer Buffer in cui verrà creato il pacchetto
 * @param size Dimensione massima del buffer
 * @param dst_mac Indirizzo MAC di destinazione
 * @param src_mac Indirizzo MAC sorgente
 * @param src_ip Indirizzo IP sorgente (formato stringa)
 * @param dst_ip Indirizzo IP di destinazione (formato stringa)
 * @param src_port Porta UDP sorgente
 * @param dst_port Porta UDP di destinazione
 * @param data Dati del payload
 * @param data_len Lunghezza del payload
 * @return Dimensione totale del pacchetto o -1 in caso di errore
 */
int create_udp_packet(void *buffer, size_t size,
                      const uint8_t *dst_mac, const uint8_t *src_mac,
                      const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      const void *data, size_t data_len)
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    char *payload;
    size_t packet_len;
    
    if (!buffer || !dst_mac || !src_mac || !src_ip || !dst_ip || (!data && data_len > 0))
        return -1;
    
    struct in_addr src_addr, dst_addr;
    if (inet_pton(AF_INET, src_ip, &src_addr) != 1 ||
        inet_pton(AF_INET, dst_ip, &dst_addr) != 1) {
        return -1; 
    }
    
    
    packet_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + data_len;
    if (packet_len > size)  // Check available space
        return -1;
    
    eth = buffer;
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);
    
    ip = (struct iphdr *)(eth + 1);
    ip->version = 4;
    ip->ihl = 5; 
    ip->tos = 0;
    ip->tot_len = htons(sizeof(*ip) + sizeof(*udp) + data_len);
    ip->id = htons(rand() & 0xFFFF); 
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0; 
    ip->saddr = src_addr.s_addr;
    ip->daddr = dst_addr.s_addr;
    
    ip->check = 0;
    uint16_t *ipdata = (uint16_t *)ip;
    uint32_t checksum = 0;
    for (int i = 0; i < ip->ihl * 2; i++)
        checksum += ipdata[i];
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum & 0xffff) + (checksum >> 16);
    ip->check = ~checksum;
    
    udp = (struct udphdr *)(ip + 1);
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(*udp) + data_len);
    udp->check = 0; 
    
    payload = (char *)(udp + 1);
    if (data_len > 0 && data != NULL) {
        memcpy(payload, data, data_len);
    }
    
    return packet_len;
}

/**
 * Crea un pacchetto di risposta basato su un pacchetto ricevuto
 * 
 * @param rx_buffer Buffer del pacchetto ricevuto
 * @param rx_size Dimensione del pacchetto ricevuto
 * @param tx_buffer Buffer per il pacchetto di risposta
 * @param tx_size Dimensione massima del buffer di risposta
 * @param data Payload della risposta
 * @param data_len Lunghezza del payload della risposta
 * @return Dimensione del pacchetto di risposta o -1 in caso di errore
 */
int create_response_packet(const void *rx_buffer, size_t rx_size,
                           void *tx_buffer, size_t tx_size,
                           const void *data, size_t data_len)
{
    struct ethhdr *rx_eth, *tx_eth;
    struct iphdr *rx_ip, *tx_ip;
    struct udphdr *rx_udp, *tx_udp;
    uint8_t src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port, dst_port;
    
    if (!rx_buffer || !tx_buffer || (!data && data_len > 0) || rx_size < sizeof(*rx_eth) + sizeof(*rx_ip) + sizeof(*rx_udp))
        return -1;
    
    rx_eth = (struct ethhdr *)rx_buffer;
    
    if (ntohs(rx_eth->h_proto) != ETH_P_IP)
        return -1;
    
    rx_ip = (struct iphdr *)(rx_eth + 1);
    
    if (rx_ip->ihl < 5 || (size_t)(rx_ip->ihl * 4) + sizeof(*rx_eth) > rx_size)
        return -1;
    
    if (rx_ip->protocol != IPPROTO_UDP)
        return -1;
    
    rx_udp = (struct udphdr *)((char *)rx_ip + (rx_ip->ihl * 4));
    
    if ((size_t)((char *)rx_udp + sizeof(*rx_udp) - (char *)rx_buffer) > rx_size)
        return -1;
    
    memcpy(src_mac, rx_eth->h_dest, ETH_ALEN);
    memcpy(dst_mac, rx_eth->h_source, ETH_ALEN);
    
    struct in_addr addr;
    addr.s_addr = rx_ip->daddr;
    inet_ntop(AF_INET, &addr, src_ip, INET_ADDRSTRLEN);
    
    addr.s_addr = rx_ip->saddr;
    inet_ntop(AF_INET, &addr, dst_ip, INET_ADDRSTRLEN);
    
    src_port = ntohs(rx_udp->dest);
    dst_port = ntohs(rx_udp->source);
    
    return create_udp_packet(tx_buffer, tx_size, 
                            dst_mac, src_mac, 
                            src_ip, dst_ip, 
                            src_port, dst_port, 
                            data, data_len);
}

/**
 * Estrae informazioni da un pacchetto ricevuto
 * 
 * @param buffer Buffer del pacchetto
 * @param size Dimensione del pacchetto
 * @param src_mac Buffer per memorizzare il MAC sorgente (deve essere almeno 6 byte)
 * @param dst_mac Buffer per memorizzare il MAC di destinazione (deve essere almeno 6 byte)
 * @param src_ip Buffer per memorizzare l'IP sorgente (deve essere almeno 16 byte)
 * @param dst_ip Buffer per memorizzare l'IP di destinazione (deve essere almeno 16 byte)
 * @param src_port Puntatore per memorizzare la porta sorgente
 * @param dst_port Puntatore per memorizzare la porta di destinazione
 * @param payload Puntatore per memorizzare il puntatore al payload
 * @param payload_len Puntatore per memorizzare la lunghezza del payload
 * @return 0 in caso di successo, valore negativo in caso di errore
 */
int extract_packet_info(const void *buffer, size_t size,
                        uint8_t *src_mac, uint8_t *dst_mac,
                        char *src_ip, char *dst_ip,
                        uint16_t *src_port, uint16_t *dst_port,
                        const void **payload, size_t *payload_len)
{
    const struct ethhdr *eth;
    const struct iphdr *ip;
    const struct udphdr *udp;
    const char *pkt_payload;
    size_t header_size, pkt_payload_len;
    
    if (!buffer || size < sizeof(*eth) + sizeof(*ip) + sizeof(*udp))
        return -1;
    
    eth = buffer;
    
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return -2;
    
    ip = (const struct iphdr *)(eth + 1);
    
    if (ip->ihl < 5 || (size_t)(ip->ihl * 4) + sizeof(*eth) > size)
        return -3;
    
    if (ip->protocol != IPPROTO_UDP)
        return -4;
    
    udp = (const struct udphdr *)((const char *)ip + (ip->ihl * 4));
    
    header_size = (const char *)udp + sizeof(*udp) - (const char *)buffer;
    if (header_size > size)
        return -5;
    
    pkt_payload = (const char *)udp + sizeof(*udp);
    pkt_payload_len = size - header_size;
    
    if (src_mac)
        memcpy(src_mac, eth->h_source, ETH_ALEN);
    
    if (dst_mac)
        memcpy(dst_mac, eth->h_dest, ETH_ALEN);
    
    if (src_ip) {
        struct in_addr addr;
        addr.s_addr = ip->saddr;
        inet_ntop(AF_INET, &addr, src_ip, INET_ADDRSTRLEN);
    }
    
    if (dst_ip) {
        struct in_addr addr;
        addr.s_addr = ip->daddr;
        inet_ntop(AF_INET, &addr, dst_ip, INET_ADDRSTRLEN);
    }
    
    if (src_port)
        *src_port = ntohs(udp->source);
    
    if (dst_port)
        *dst_port = ntohs(udp->dest);
    
    if (payload)
        *payload = pkt_payload;
    
    if (payload_len)
        *payload_len = pkt_payload_len;
    
    return 0;
}

/**
 * Controlla se il pacchetto contiene un payload specifico
 * 
 * @param buffer Buffer del pacchetto
 * @param size Dimensione del pacchetto
 * @param pattern Modello da cercare
 * @param pattern_len Lunghezza del modello
 * @return 1 se il modello è trovato, 0 se non trovato, valore negativo in caso di errore
 */
int packet_contains(const void *buffer, size_t size,
                    const void *pattern, size_t pattern_len)
{
    const void *payload;
    size_t payload_len;
    int ret;
    
    if (!buffer || !pattern || pattern_len == 0)
        return -1;
    
    ret = extract_packet_info(buffer, size, NULL, NULL, NULL, NULL, 
                            NULL, NULL, &payload, &payload_len);
    if (ret < 0)
        return ret;
    
    if (pattern_len > payload_len)
        return 0;
    
    for (size_t i = 0; i <= payload_len - pattern_len; i++) {
        if (memcmp((const char *)payload + i, pattern, pattern_len) == 0) {
            return 1; 
        }
    }
    
    return 0;
}



/**
 * @param ifname Nome dell'interfaccia
 * @param mac Buffer per memorizzare l'indirizzo MAC (deve essere almeno ETH_ALEN byte)
 * @return 0 in caso di successo, valore negativo in caso di errore
 */
int get_interface_mac(const char *ifname, uint8_t *mac)
{
    char cmd[256];
    FILE *fp;
    int ret = -1;
    
    if (!ifname || !mac)
        return -EINVAL;
    
    snprintf(cmd, sizeof(cmd), "ip link show %s | grep link/ether | awk '{print $2}'", ifname);
    fp = popen(cmd, "r");
    if (fp) {
        char mac_str[18];
        if (fgets(mac_str, sizeof(mac_str), fp) != NULL) {
            ret = str_to_mac_addr(mac_str, mac);
        }
        pclose(fp);
    }
    
    return ret;
}


int discover_mac_address(const char *ip_addr, uint8_t *mac, int timeout_ms)
{
    char cmd[256];
    FILE *fp;
    int ret = -1;
    int ping_timeout = timeout_ms / 1000;
    
    if (!ip_addr || !mac || timeout_ms < 0)
        return -EINVAL;
    
    if (ping_timeout < 1)
        ping_timeout = 1;
    
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s > /dev/null 2>&1", 
             ping_timeout, ip_addr);
    if (system(cmd) != 0) {
    }
    
    snprintf(cmd, sizeof(cmd), "ip neigh show %s | awk '{print $5}'", ip_addr);         // Look up the MAC in the ARP table
    fp = popen(cmd, "r");
    if (fp) {
        char mac_str[18];
        if (fgets(mac_str, sizeof(mac_str), fp) != NULL) {
            ret = str_to_mac_addr(mac_str, mac);
        }
        pclose(fp);
    }
    
    return ret;
}


char *mac_addr_to_str(const uint8_t *mac, char *buf, size_t buf_size)
{
    if (!mac || !buf || buf_size < 18)
        return NULL;
    
    snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return buf;
}


int str_to_mac_addr(const char *str, uint8_t *mac)
{
    unsigned int values[ETH_ALEN];
    int count;
    
    if (!str || !mac)
        return -EINVAL;
    
    count = sscanf(str, "%x:%x:%x:%x:%x:%x",
                  &values[0], &values[1], &values[2],
                  &values[3], &values[4], &values[5]);
    
    if (count == ETH_ALEN) {
        for (int i = 0; i < ETH_ALEN; i++)
            mac[i] = (uint8_t)values[i];
        return 0;
    }
    
    return -1;
}