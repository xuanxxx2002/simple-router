#include <stdio.h>
#include <string.h>
#include "router.h"

int arp_add(router_t *r, ip_addr_t ip, const mac_addr_t mac) {
    arp_table_t *t = &r->arp;
    /* update existing */
    for (int i = 0; i < t->count; i++) {
        if (t->entries[i].ip == ip) {
            memcpy(t->entries[i].mac, mac, 6);
            t->entries[i].valid = true;
            return 0;
        }
    }
    if (t->count >= ARP_TABLE_SIZE) { fprintf(stderr,"ARP table full\n"); return -1; }
    arp_entry_t *e = &t->entries[t->count++];
    e->ip    = ip;
    e->valid = true;
    memcpy(e->mac, mac, 6);
    printf("[ARP] " IP_FMT " -> " MAC_FMT "\n",
           IP_ARGS(ip), MAC_ARGS(mac));
    return 0;
}

const mac_addr_t *arp_lookup(const router_t *r, ip_addr_t ip) {
    const arp_table_t *t = &r->arp;
    for (int i = 0; i < t->count; i++)
        if (t->entries[i].valid && t->entries[i].ip == ip)
            return &t->entries[i].mac;
    return NULL;
}

void arp_print(const router_t *r) {
    const arp_table_t *t = &r->arp;
    printf("\n=== ARP Table (%d entries) ===\n", t->count);
    printf("%-16s  %s\n", "IP Address", "MAC Address");
    printf("%-16s  %s\n", "----------------", "-----------------");
    for (int i = 0; i < t->count; i++) {
        if (!t->entries[i].valid) continue;
        char ip[16]; ip_to_str(t->entries[i].ip, ip);
        printf("%-16s  " MAC_FMT "\n", ip, MAC_ARGS(t->entries[i].mac));
    }
    printf("\n");
}
