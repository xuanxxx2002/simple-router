#ifndef ROUTER_H
#define ROUTER_H

#include <stdint.h>
#include <stdbool.h>

typedef uint32_t ip_addr_t;
typedef uint8_t  mac_addr_t[6];

#define IP(a,b,c,d) (((uint32_t)(a)<<24)|((uint32_t)(b)<<16)|((uint32_t)(c)<<8)|(d))
#define IP_FMT      "%u.%u.%u.%u"
#define IP_ARGS(ip) ((ip)>>24)&0xFF,((ip)>>16)&0xFF,((ip)>>8)&0xFF,(ip)&0xFF
#define MAC_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_ARGS(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]

#define MAX_PAYLOAD   1500
#define PROTO_ICMP    1
#define PROTO_TCP     6
#define PROTO_UDP     17

typedef struct {
    uint8_t    version_ihl;
    uint8_t    dscp;
    uint16_t   total_len;
    uint16_t   id;
    uint16_t   flags_frag;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t   checksum;
    ip_addr_t  src_ip;
    ip_addr_t  dst_ip;
    uint8_t    data[MAX_PAYLOAD - 20];
    int        data_len;
} ip_packet_t;

#define ARP_TABLE_SIZE 64
typedef struct { ip_addr_t ip; mac_addr_t mac; bool valid; } arp_entry_t;
typedef struct { arp_entry_t entries[ARP_TABLE_SIZE]; int count; } arp_table_t;

#define ROUTE_TABLE_SIZE 32
typedef struct {
    ip_addr_t network; ip_addr_t mask; ip_addr_t gateway;
    char iface[16]; int metric;
} route_entry_t;
typedef struct { route_entry_t entries[ROUTE_TABLE_SIZE]; int count; } route_table_t;

#define ACL_TABLE_SIZE  64
#define ACL_PERMIT      1
#define ACL_DENY        0
#define ACL_PROTO_ANY   0xFF
typedef struct {
    ip_addr_t src_net; ip_addr_t src_mask;
    ip_addr_t dst_net; ip_addr_t dst_mask;
    uint8_t protocol; uint16_t src_port; uint16_t dst_port;
    int action; char name[32];
} acl_entry_t;
typedef struct { acl_entry_t entries[ACL_TABLE_SIZE]; int count; } acl_table_t;

#define MAX_IFACES 8
typedef struct {
    char name[16]; ip_addr_t ip; ip_addr_t mask; mac_addr_t mac; bool up;
    uint64_t rx_packets, tx_packets, rx_bytes, tx_bytes, dropped;
} iface_t;

typedef struct {
    iface_t ifaces[MAX_IFACES]; int iface_count;
    route_table_t rtable; arp_table_t arp; acl_table_t acl;
    uint64_t total_forwarded, total_dropped;
} router_t;

typedef struct {
    bool forwarded, acl_dropped, ttl_expired, no_route, arp_hit;
    char out_iface[16]; ip_addr_t next_hop; char reason[128];
} forward_result_t;

void router_init(router_t *r);
int  router_add_iface(router_t *r, const char *name,
                      ip_addr_t ip, ip_addr_t mask, const mac_addr_t mac);
int  route_add(router_t *r, ip_addr_t net, ip_addr_t mask,
               ip_addr_t gw, const char *iface, int metric);
int  route_del(router_t *r, ip_addr_t net, ip_addr_t mask);
const route_entry_t *route_lookup(const router_t *r, ip_addr_t dst);
void route_print(const router_t *r);
int  arp_add(router_t *r, ip_addr_t ip, const mac_addr_t mac);
const mac_addr_t *arp_lookup(const router_t *r, ip_addr_t ip);
void arp_print(const router_t *r);
int  acl_add(router_t *r, const acl_entry_t *e);
int  acl_del(router_t *r, const char *name);
bool acl_check(const router_t *r, const ip_packet_t *pkt);
void acl_print(const router_t *r);
forward_result_t packet_forward(router_t *r, ip_packet_t *pkt,
                                const char *in_iface);
uint16_t ip_checksum(const void *data, int len);
bool ip_in_network(ip_addr_t ip, ip_addr_t net, ip_addr_t mask);
void ip_to_str(ip_addr_t ip, char *buf);
bool str_to_ip(const char *s, ip_addr_t *out);
void print_ip_packet(const ip_packet_t *pkt);

#endif
