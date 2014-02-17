#ifndef PROXY_MAP_H
#define PROXY_MAP_H

#include "station.h"

struct proxy_map_entry {
    struct proxy_map_entry *next;
    struct telex_st *state;
};
#define PROXY_MAP_ENTRIES   (1<<18)
#define PROXY_HASH_IDX(id)  (((uint64_t*)id)[0] % PROXY_MAP_ENTRIES)

struct telex_st *lookup_conn_id(struct config *conf, char *conn_id);
void insert_conn_id(struct telex_st *state);
void remove_conn_id(struct telex_st *state);

#endif
