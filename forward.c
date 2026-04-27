#include <stdio.h>
#include <string.h>
#include "router.h"

forward_result_t packet_forward(router_t *r, ip_packet_t *pkt,
                                const char *in_iface) {
    forward_result_t res;
    memset(&res, 0, sizeof(res));

    printf("\n--- Forwarding: " IP_FMT " -> " IP_FMT " TTL=%d ---\n",
           IP_ARGS(pkt->src_ip), IP_ARGS(pkt->dst_ip), pkt->ttl);

    /* 1. TTL check */
    if (pkt->ttl <= 1) {
        pkt->ttl = 0;
        res.ttl_expired = true;
        snprintf(res.reason, sizeof(res.reason), "TTL expired");
        r->total_dropped++;
        printf("[DROP] TTL expired\n");
        return res;
    }

    /* 2. ACL check */
    if (!acl_check(r, pkt)) {
        res.acl_dropped = true;
        snprintf(res.reason, sizeof(res.reason), "ACL denied");
        r->total_dropped++;
        /* update iface drop counter */
        for (int i = 0; i < r->iface_count; i++)
            if (strncmp(r->ifaces[i].name, in_iface, 16) == 0)
                r->ifaces[i].dropped++;
        printf("[DROP] ACL denied\n");
        return res;
    }

    /* 3. Route lookup (LPM) */
    const route_entry_t *route = route_lookup(r, pkt->dst_ip);
    if (!route) {
        res.no_route = true;
        snprintf(res.reason, sizeof(res.reason), "No route to host");
        r->total_dropped++;
        printf("[DROP] No route to " IP_FMT "\n", IP_ARGS(pkt->dst_ip));
        return res;
    }

    /* 4. Determine next-hop */
    ip_addr_t nexthop = (route->gateway != 0) ? route->gateway : pkt->dst_ip;
    res.next_hop = nexthop;
    strncpy(res.out_iface, route->iface, sizeof(res.out_iface)-1);

    /* 5. ARP lookup */
    const mac_addr_t *dmac = arp_lookup(r, nexthop);
    if (dmac) {
        res.arp_hit = true;
        printf("[ARP] Cache hit: " IP_FMT " -> " MAC_FMT "\n",
               IP_ARGS(nexthop), MAC_ARGS(*dmac));
    } else {
        printf("[ARP] Cache miss for " IP_FMT " – would send ARP request\n",
               IP_ARGS(nexthop));
    }

    /* 6. Decrement TTL & recompute checksum */
    pkt->ttl--;
    pkt->checksum = 0;
    pkt->checksum = ip_checksum(pkt, 20);

    /* 7. Update stats */
    r->total_forwarded++;
    for (int i = 0; i < r->iface_count; i++) {
        if (strncmp(r->ifaces[i].name, in_iface, 16) == 0) {
            r->ifaces[i].rx_packets++;
            r->ifaces[i].rx_bytes += pkt->total_len;
        }
        if (strncmp(r->ifaces[i].name, route->iface, 16) == 0) {
            r->ifaces[i].tx_packets++;
            r->ifaces[i].tx_bytes += pkt->total_len;
        }
    }

    res.forwarded = true;
    snprintf(res.reason, sizeof(res.reason),
             "Forwarded via %s nexthop " IP_FMT,
             route->iface, IP_ARGS(nexthop));
    printf("[FWD] " IP_FMT " -> " IP_FMT " via %s nexthop " IP_FMT " TTL->%d\n",
           IP_ARGS(pkt->src_ip), IP_ARGS(pkt->dst_ip),
           route->iface, IP_ARGS(nexthop), pkt->ttl);
    return res;
}
