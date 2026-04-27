#include <stdio.h>
#include <string.h>
#include "router.h"

void router_init(router_t *r) {
    memset(r, 0, sizeof(*r));
}

int router_add_iface(router_t *r, const char *name,
                     ip_addr_t ip, ip_addr_t mask, const mac_addr_t mac) {
    if (r->iface_count >= MAX_IFACES) return -1;
    iface_t *ifc = &r->ifaces[r->iface_count++];
    strncpy(ifc->name, name, sizeof(ifc->name)-1);
    ifc->ip   = ip;
    ifc->mask = mask;
    ifc->up   = true;
    memcpy(ifc->mac, mac, 6);
    printf("[IFACE] Added %s  " IP_FMT "/" IP_FMT "\n",
           name, IP_ARGS(ip), IP_ARGS(mask));
    return 0;
}
