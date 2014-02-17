
#include "station.h"
#include "proxy_map.h"

struct telex_st *lookup_conn_id(struct config *conf, char *conn_id)
{
    int idx = PROXY_HASH_IDX(conn_id);
    struct proxy_map_entry *entry = conf->proxy_map[idx];

    while (entry) {
        if (memcmp(entry->state->proxy_id, conn_id,
                   sizeof(entry->state->proxy_id))==0) {
            return entry->state;
        }
        entry = entry->next;
    }
    return NULL;
}

// Assumes it is not already in the map
void insert_conn_id(struct telex_st *state)
{
    struct config *conf = state->conf;
    int idx = PROXY_HASH_IDX(state->proxy_id);
    struct proxy_map_entry *new_entry;

    struct proxy_map_entry *entry = conf->proxy_map[idx];
    state->proxy_entry = entry;

    new_entry = malloc(sizeof(struct proxy_map_entry));
    if (!new_entry) {
        LogError(state->name, "can't malloc new_entry for proxy map");
        return;
    }
    new_entry->state = state;
    new_entry->next = NULL;

    if (!entry) {
        conf->proxy_map[idx] = new_entry;
        return;
    }

    while (entry->next != NULL) {
        entry = entry->next;
    }
    entry->next = new_entry;
}

void remove_conn_id(struct telex_st *state)
{
    struct config *conf = state->conf;
    struct proxy_map_entry *entry = state->proxy_entry;
    int idx = PROXY_HASH_IDX(state->proxy_id);
    struct proxy_map_entry *cur = conf->proxy_map[idx];
    struct proxy_map_entry *prev = NULL;

    if (entry == NULL) {
        LogError(state->name, "NULL proxy_entry but have ID");
        return;
    }

    while (cur && cur != entry) {
        prev = cur;
        cur = cur->next;
    }
    assert(cur == entry);   // Or you tried to remove a non-existent proxy

    if (prev) {
        prev->next = cur->next;
    } else {
        conf->proxy_map[idx] = cur->next;
    }

    // Free this entry
    free(entry);
    state->proxy_entry = NULL;
}


