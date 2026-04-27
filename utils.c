#include <stdio.h>
#include <string.h>
#include "router.h"

uint16_t ip_checksum(const void *data, int len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

bool ip_in_network(ip_addr_t ip, ip_addr_t net, ip_addr_t mask) {
    return (ip & mask) == (net & mask);
}

void ip_to_str(ip_addr_t ip, char *buf) {
    snprintf(buf, 16, IP_FMT, IP_ARGS(ip));
}

bool str_to_ip(const char *s, ip_addr_t *out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a>255||b>255||c>255||d>255) return false;
    *out = IP(a, b, c, d);
    return true;
}

void print_ip_packet(const ip_packet_t *pkt) {
    const char *proto = (pkt->protocol==PROTO_TCP) ? "TCP" :
                        (pkt->protocol==PROTO_UDP) ? "UDP" :
                        (pkt->protocol==PROTO_ICMP)? "ICMP": "???";
    printf("[IP] " IP_FMT " -> " IP_FMT "  proto=%s  ttl=%d  len=%d\n",
           IP_ARGS(pkt->src_ip), IP_ARGS(pkt->dst_ip),
           proto, pkt->ttl, pkt->total_len);
}
