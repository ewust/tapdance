#ifndef FLOW_H
#define FLOW_H

// Generic type used in a map[(ip,port)] -> flow.value
// used for both TCP and UDP, though UDP only uses dst_packets and pcap_file.
// Need to be uniform for cleanup to be able to loop through a single map (could do two maps, but they are very sparse)
struct flow_t {
    FILE *pcap_file;    // if non-null, write packets to this
    struct packets *src_packets;
    struct packets *dst_packets;

    uint32_t    max_seq;    // TCP optimization: if we receive a higher seq than this, no need to check overlap (host-order)

    struct timeval expire;
};

struct flow {
    // Key
    struct flow *next;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    // Value
    struct timeval expire;
};

// Linked list of keys
struct flow_key {
    struct flow_key *next;  // next key

    struct flow *cur;
};

struct flow_map {
    struct flow **map;  // actual map

    struct flow_key *keys;
};

#define MAP_ENTRIES         (1<<18)
#define HASH_IDX(src_ip,dst_ip,src_port,dst_port)   (((59*(dst_port^src_port))^(src_ip^dst_ip))%MAP_ENTRIES)




struct flow *add_flow(struct flow_map *conn_map, struct flow *new_flow);

struct flow *lookup_flow(struct flow_map *conn_map, uint32_t src_ip,
                         uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);



#endif
