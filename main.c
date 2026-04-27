#include <stdio.h>
#include <string.h>
#include "router.h"

/* Helper to build a simple IP packet */
static ip_packet_t make_pkt(ip_addr_t src, ip_addr_t dst,
                             uint8_t proto, uint8_t ttl) {
    ip_packet_t p;
    memset(&p, 0, sizeof(p));
    p.version_ihl = 0x45;
    p.total_len   = 40;
    p.ttl         = ttl;
    p.protocol    = proto;
    p.src_ip      = src;
    p.dst_ip      = dst;
    p.checksum    = ip_checksum(&p, 20);
    return p;
}

static void print_stats(const router_t *r) {
    printf("\n=== Router Stats ===\n");
    printf("Total forwarded : %llu\n", (unsigned long long)r->total_forwarded);
    printf("Total dropped   : %llu\n", (unsigned long long)r->total_dropped);
    printf("\n%-8s %8s %8s %8s %8s %8s\n",
           "Iface","RX pkts","TX pkts","RX bytes","TX bytes","Dropped");
    printf("%-8s %8s %8s %8s %8s %8s\n",
           "--------","--------","--------","--------","--------","--------");
    for (int i = 0; i < r->iface_count; i++) {
        const iface_t *f = &r->ifaces[i];
        printf("%-8s %8llu %8llu %8llu %8llu %8llu\n",
               f->name,
               (unsigned long long)f->rx_packets,
               (unsigned long long)f->tx_packets,
               (unsigned long long)f->rx_bytes,
               (unsigned long long)f->tx_bytes,
               (unsigned long long)f->dropped);
    }
    printf("\n");
}

int main(void) {
    router_t r;
    router_init(&r);

    printf("=========================================\n");
    printf("   Simple Layer-3 Router Simulator\n");
    printf("=========================================\n\n");

    /* ── Interfaces ── */
    printf("--- Setup Interfaces ---\n");
    mac_addr_t mac0 = {0xAA,0xBB,0xCC,0x00,0x01,0x01};
    mac_addr_t mac1 = {0xAA,0xBB,0xCC,0x00,0x01,0x02};
    mac_addr_t mac2 = {0xAA,0xBB,0xCC,0x00,0x01,0x03};
    router_add_iface(&r, "eth0", IP(192,168,1,1),  IP(255,255,255,0), mac0);
    router_add_iface(&r, "eth1", IP(10,0,0,1),     IP(255,255,255,0), mac1);
    router_add_iface(&r, "eth2", IP(172,16,0,1),   IP(255,255,0,0),   mac2);

    /* ── Routing Table ── */
    printf("\n--- Setup Routing Table ---\n");
    route_add(&r, IP(192,168,1,0), IP(255,255,255,0), 0,             "eth0", 0);
    route_add(&r, IP(10,0,0,0),    IP(255,255,255,0), 0,             "eth1", 0);
    route_add(&r, IP(172,16,0,0),  IP(255,255,0,0),   0,             "eth2", 0);
    route_add(&r, IP(0,0,0,0),     IP(0,0,0,0),       IP(10,0,0,254),"eth1", 10); /* default */

    /* ── ARP Table ── */
    printf("\n--- Setup ARP Cache ---\n");
    mac_addr_t host1_mac = {0x11,0x22,0x33,0x44,0x55,0x01};
    mac_addr_t host2_mac = {0x11,0x22,0x33,0x44,0x55,0x02};
    mac_addr_t gw_mac    = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    arp_add(&r, IP(192,168,1,100), host1_mac);
    arp_add(&r, IP(10,0,0,100),    host2_mac);
    arp_add(&r, IP(10,0,0,254),    gw_mac);

    /* ── ACL Rules ── */
    printf("\n--- Setup ACL Rules ---\n");
    acl_entry_t rule;

    /* Block all TCP from 192.168.1.0/24 to 172.16.0.0/16 */
    memset(&rule, 0, sizeof(rule));
    snprintf(rule.name, 32, "block-tcp-172");
    rule.src_net  = IP(192,168,1,0);  rule.src_mask = IP(255,255,255,0);
    rule.dst_net  = IP(172,16,0,0);   rule.dst_mask = IP(255,255,0,0);
    rule.protocol = PROTO_TCP;
    rule.action   = ACL_DENY;
    acl_add(&r, &rule);

    /* Permit ICMP from anywhere to 10.0.0.0/24 */
    memset(&rule, 0, sizeof(rule));
    snprintf(rule.name, 32, "permit-icmp-10");
    rule.src_net  = IP(0,0,0,0);      rule.src_mask = IP(0,0,0,0);
    rule.dst_net  = IP(10,0,0,0);     rule.dst_mask = IP(255,255,255,0);
    rule.protocol = PROTO_ICMP;
    rule.action   = ACL_PERMIT;
    acl_add(&r, &rule);

    /* Print tables */
    route_print(&r);
    arp_print(&r);
    acl_print(&r);

    /* ── Test Packet Forwarding ── */
    printf("=========================================\n");
    printf("   Packet Forwarding Tests\n");
    printf("=========================================\n");

    ip_packet_t pkt;
    forward_result_t res;

    /* Test 1: Normal forward – eth0 -> eth1 */
    printf("\n[TEST 1] Normal: 192.168.1.100 -> 10.0.0.100 (ICMP, TTL=64)\n");
    pkt = make_pkt(IP(192,168,1,100), IP(10,0,0,100), PROTO_ICMP, 64);
    res = packet_forward(&r, &pkt, "eth0");
    printf("Result: %s\n", res.reason);

    /* Test 2: ACL block – TCP to 172.16 subnet */
    printf("\n[TEST 2] ACL DENY: 192.168.1.100 -> 172.16.1.50 (TCP, TTL=64)\n");
    pkt = make_pkt(IP(192,168,1,100), IP(172,16,1,50), PROTO_TCP, 64);
    res = packet_forward(&r, &pkt, "eth0");
    printf("Result: %s\n", res.reason);

    /* Test 3: Default route (internet) */
    printf("\n[TEST 3] Default route: 10.0.0.100 -> 8.8.8.8 (UDP, TTL=128)\n");
    pkt = make_pkt(IP(10,0,0,100), IP(8,8,8,8), PROTO_UDP, 128);
    res = packet_forward(&r, &pkt, "eth1");
    printf("Result: %s\n", res.reason);

    /* Test 4: TTL expired */
    printf("\n[TEST 4] TTL Expired: 192.168.1.100 -> 10.0.0.100 (ICMP, TTL=1)\n");
    pkt = make_pkt(IP(192,168,1,100), IP(10,0,0,100), PROTO_ICMP, 1);
    res = packet_forward(&r, &pkt, "eth0");
    printf("Result: %s\n", res.reason);

    /* Test 5: No route */
    printf("\n[TEST 5] No route (delete default first)\n");
    route_del(&r, IP(0,0,0,0), IP(0,0,0,0));
    pkt = make_pkt(IP(10,0,0,100), IP(8,8,8,8), PROTO_UDP, 64);
    res = packet_forward(&r, &pkt, "eth1");
    printf("Result: %s\n", res.reason);

    /* Final stats */
    print_stats(&r);

    return 0;
}
