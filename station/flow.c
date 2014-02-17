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

void cleanup_flow(struct flow_key *key, struct flow_key *prev_key, struct config *conf)
{
    struct flow *cur_flow = key->cur;
    int idx = HASH_IDX(cur_flow->src_ip, cur_flow->dst_ip, cur_flow->src_port, cur_flow->dst_port);

    //printf("cleaning up flow %08x:%04x:%04x\n", key->cur->ip, key->cur->port, key->cur->txid);

    // Find previous element in hashtable
    struct flow *prev_bucket = NULL;
    struct flow *cur_bucket = conf->conn_map.map[idx];
    assert(cur_bucket != NULL);
    while (cur_bucket != NULL && cur_bucket != cur_flow) {
        prev_bucket = cur_bucket;
        cur_bucket = cur_bucket->next;
    }
    assert(cur_bucket == cur_flow);

    // Fixup map linked list
    if (prev_bucket != NULL) {
        prev_bucket->next = cur_flow->next;
    } else {
        // First element in list
        conf->conn_map.map[idx] = cur_flow->next;
    }

    // Remove from keys list
    if (prev_key != NULL) {
        prev_key->next = key->next;
    } else {
        // First key in list, set head of list
        conf->conn_map.keys = key->next;
    }

    // Free key entry
    free(key);

    // Free self
    free(cur_flow);

    conf->stats.cur_flows--;
}

int cleanup_expired(struct config *conf)
{
    struct flow_key *cur_key = conf->conn_map.keys;
    struct timeval cur_ts;
    struct flow_key *prev_key = NULL;
    int num_removed = 0;

    // TODO: use packet time or is real time good enough?
    // possible easy fix: pad TCP_EXPIRE_SEC with the max processing delay we expect
    gettimeofday(&cur_ts, NULL);

    while (cur_key != NULL) {
        assert(cur_key->cur != NULL);
        if (cur_key->cur->expire.tv_sec < cur_ts.tv_sec ||
            (cur_key->cur->expire.tv_sec == cur_ts.tv_sec &&
            cur_key->cur->expire.tv_usec <= cur_ts.tv_usec)) {
            // Expired
            struct flow_key *tmp_key = cur_key->next;   // because cleanup_flow will free(cur_key)
            cleanup_flow(cur_key, prev_key, conf);
            cur_key = tmp_key;  // Don't update prev_key

            num_removed++;
        } else {
            prev_key = cur_key;
            cur_key = cur_key->next;
        }
    }

    return num_removed;
}


