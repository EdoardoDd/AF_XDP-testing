#ifndef COMMON_PACKET_H
#define COMMON_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

// Function per calcolare checksum
__sum16 csum16_add(__sum16 csum, __be16 addend);
__sum16 csum16_sub(__sum16 csum, __be16 addend);
void csum_replace2(__sum16 *sum, __be16 old, __be16 new);


void print_packet_info(void *data, size_t length);

int create_udp_packet(void *buffer, size_t size,
                      const uint8_t *dst_mac, const uint8_t *src_mac,
                      const char *src_ip, const char *dst_ip,
                      uint16_t src_port, uint16_t dst_port,
                      const void *data, size_t data_len);
int create_response_packet(const void *rx_buffer, size_t rx_size,
                           void *tx_buffer, size_t tx_size,
                           const void *data, size_t data_len);
int extract_packet_info(const void *buffer, size_t size,
                        uint8_t *src_mac, uint8_t *dst_mac,
                        char *src_ip, char *dst_ip,
                        uint16_t *src_port, uint16_t *dst_port,
                        const void **payload, size_t *payload_len);
int packet_contains(const void *buffer, size_t size,
                    const void *pattern, size_t pattern_len);


int get_interface_mac(const char *ifname, uint8_t *mac);
int discover_mac_address(const char *ip_addr, uint8_t *mac, int timeout_ms);
char *mac_addr_to_str(const uint8_t *mac, char *buf, size_t buf_size);
int str_to_mac_addr(const char *str, uint8_t *mac);


#endif 