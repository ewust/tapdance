#include "station.h"
#include "flow.h"

struct flow *add_flow(struct flow_map *conn_map, struct flow *new_flow)
{
    struct flow *cur;
    int idx = HASH_IDX(new_flow->src_ip, new_flow->dst_ip, new_flow->src_port, new_flow->dst_port);

    // Add to head of keys linked list
    struct flow_key *new_key = malloc(sizeof(struct flow_key));
    new_key->next = conn_map->keys;
    new_key->cur = new_flow;
    conn_map->keys = new_key;

    // Add to the hash map
    cur = conn_map->map[idx];
    if (cur == NULL) {
        // Common case: we are the only entry in this bucket
        conn_map->map[idx] = new_flow;
        return;
    }

    // Walk bucket linked list
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = new_flow;
}

// bi-directional lookup
struct flow *lookup_flow(struct flow_map *conn_map, uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port)
{
    struct flow *ret;

    ret = conn_map->map[HASH_IDX(src_ip, dst_ip, src_port, dst_port)];
    while (ret != NULL) {
        if ((ret->src_ip == src_ip && ret->dst_ip == dst_ip &&
             ret->src_port == src_port && ret->dst_port == dst_port) ||
            (ret->src_ip == dst_ip && ret->dst_ip == src_ip &&
             ret->src_port == dst_port && ret->dst_port == src_port)) {
            return ret;
        }
        ret = ret->next;
    }

    return NULL;
}


