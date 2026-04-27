#include <stdio.h>
#include <string.h>
#include "router.h"

int route_add(router_t *r, ip_addr_t net, ip_addr_t mask,
              ip_addr_t gw, const char *iface, int metric) {
    route_table_t *rt = &r->rtable;
    if (rt->count >= ROUTE_TABLE_SIZE) { fprintf(stderr,"Route table full\n"); return -1; }
    route_entry_t *e = &rt->entries[rt->count++];
    e->network = net & mask;
    e->mask    = mask;
    e->gateway = gw;
    e->metric  = metric;
    strncpy(e->iface, iface, sizeof(e->iface)-1);
    printf("[ROUTE] Added " IP_FMT "/" IP_FMT " via " IP_FMT " dev %s metric %d\n",
           IP_ARGS(net), IP_ARGS(mask), IP_ARGS(gw), iface, metric);
    return 0;
}

int route_del(router_t *r, ip_addr_t net, ip_addr_t mask) {
    route_table_t *rt = &r->rtable;
    for (int i = 0; i < rt->count; i++) {
        if (rt->entries[i].network == (net & mask) && rt->entries[i].mask == mask) {
            rt->entries[i] = rt->entries[--rt->count];
            printf("[ROUTE] Deleted " IP_FMT "/" IP_FMT "\n", IP_ARGS(net), IP_ARGS(mask));
            return 0;
        }
    }
    return -1;
}

/* Longest Prefix Match */
const route_entry_t *route_lookup(const router_t *r, ip_addr_t dst) {
    const route_table_t *rt = &r->rtable;
    const route_entry_t *best = NULL;
    uint32_t best_mask = 0;
    for (int i = 0; i < rt->count; i++) {
        const route_entry_t *e = &rt->entries[i];
        if (ip_in_network(dst, e->network, e->mask)) {
            if (e->mask >= best_mask) { best = e; best_mask = e->mask; }
        }
    }
    return best;
}

void route_print(const router_t *r) {
    const route_table_t *rt = &r->rtable;
    printf("\n=== Routing Table (%d entries) ===\n", rt->count);
    printf("%-18s %-16s %-16s %-8s %s\n",
           "Destination", "Mask", "Gateway", "Iface", "Metric");
    printf("%-18s %-16s %-16s %-8s %s\n",
           "------------------","----------------","----------------","--------","------");
    for (int i = 0; i < rt->count; i++) {
        const route_entry_t *e = &rt->entries[i];
        char net[16], mask[16], gw[16];
        ip_to_str(e->network, net);
        ip_to_str(e->mask,    mask);
        ip_to_str(e->gateway, gw);
        printf("%-18s %-16s %-16s %-8s %d\n",
               net, mask, gw, e->iface, e->metric);
    }
    printf("\n");
}
