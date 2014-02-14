#ifndef TELEX_STATE
#define TELEX_STATE

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <openssl/ssl.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>

#include "pfring.h"
#include "ssl_api.h"
#include "gcm.h"
#include "logger.h"



#define FLOW_EXPIRE_SECS    10      // note: this is the time between TLS data packets...
#define PCAP_FILTER_STR     "tcp and port 443"
#define STEGO_DATA_LEN      200

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


struct stats_t {
    uint64_t    tot_pkts;
    uint32_t    cur_flows;
    uint32_t    delta_bits;
};

struct config {
    char    *dev;
    pfring  *ring;
    pcap_t  *pcap;
    int     pcap_fd;
    struct event_base *base;

    struct event *status_ev;
    struct event *pkt_ev;

    struct stats_t  stats;

    struct flow_map conn_map;

    int pfring_id;

    struct sockaddr_in proxy_addr_sin;
    uint64_t num_tunnels;
    uint32_t num_open_tunnels;
};


struct telex_st {
    struct config *conf;
    SSL *ssl;
    int client_sock;
    int proxy_sock;
    uint64_t id;
    char name[32];

    struct bufferevent *client_bev;
    struct bufferevent *proxy_bev;
};

#endif
