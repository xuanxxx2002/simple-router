#include <stdio.h>
#include <string.h>
#include "router.h"

int acl_add(router_t *r, const acl_entry_t *e) {
    acl_table_t *t = &r->acl;
    if (t->count >= ACL_TABLE_SIZE) { fprintf(stderr,"ACL table full\n"); return -1; }
    t->entries[t->count++] = *e;
    printf("[ACL] Rule '%s': %s " IP_FMT "/" IP_FMT " -> " IP_FMT "/" IP_FMT " proto=%d\n",
           e->name, e->action==ACL_PERMIT?"PERMIT":"DENY",
           IP_ARGS(e->src_net), IP_ARGS(e->src_mask),
           IP_ARGS(e->dst_net), IP_ARGS(e->dst_mask), e->protocol);
    return 0;
}

int acl_del(router_t *r, const char *name) {
    acl_table_t *t = &r->acl;
    for (int i = 0; i < t->count; i++) {
        if (strncmp(t->entries[i].name, name, 32) == 0) {
            t->entries[i] = t->entries[--t->count];
            printf("[ACL] Deleted rule '%s'\n", name);
            return 0;
        }
    }
    return -1;
}

bool acl_check(const router_t *r, const ip_packet_t *pkt) {
    const acl_table_t *t = &r->acl;
    for (int i = 0; i < t->count; i++) {
        const acl_entry_t *e = &t->entries[i];
        if (!ip_in_network(pkt->src_ip, e->src_net, e->src_mask)) continue;
        if (!ip_in_network(pkt->dst_ip, e->dst_net, e->dst_mask)) continue;
        if (e->protocol != ACL_PROTO_ANY && e->protocol != pkt->protocol) continue;
        /* matched */
        printf("[ACL] Rule '%s' matched -> %s\n",
               e->name, e->action==ACL_PERMIT?"PERMIT":"DENY");
        return e->action == ACL_PERMIT;
    }
    return true; /* default permit (implicit allow) */
}

void acl_print(const router_t *r) {
    const acl_table_t *t = &r->acl;
    printf("\n=== ACL Table (%d rules) ===\n", t->count);
    printf("%-16s %-8s %-18s %-18s %-6s\n",
           "Name","Action","Src Net/Mask","Dst Net/Mask","Proto");
    printf("%-16s %-8s %-18s %-18s %-6s\n",
           "----------------","--------","------------------","------------------","------");
    for (int i = 0; i < t->count; i++) {
        const acl_entry_t *e = &t->entries[i];
        char sn[16],sm[16],dn[16],dm[16];
        ip_to_str(e->src_net, sn); ip_to_str(e->src_mask, sm);
        ip_to_str(e->dst_net, dn); ip_to_str(e->dst_mask, dm);
        char src[36], dst[36];
        snprintf(src, sizeof(src), "%s/%s", sn, sm);
        snprintf(dst, sizeof(dst), "%s/%s", dn, dm);
        char proto[8];
        if (e->protocol == ACL_PROTO_ANY) snprintf(proto, 8, "any");
        else if (e->protocol == PROTO_TCP) snprintf(proto, 8, "TCP");
        else if (e->protocol == PROTO_UDP) snprintf(proto, 8, "UDP");
        else if (e->protocol == PROTO_ICMP) snprintf(proto, 8, "ICMP");
        else snprintf(proto, 8, "%d", e->protocol);
        printf("%-16s %-8s %-18s %-18s %-6s\n",
               e->name, e->action==ACL_PERMIT?"PERMIT":"DENY",
               src, dst, proto);
    }
    printf("\n");
}
