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
#include "flow.h"
#include "proxy_map.h"



#define FLOW_EXPIRE_SECS    10      // note: this is the time between TLS data packets...
#define PCAP_FILTER_STR     "tcp and port 443"
#define STEGO_DATA_LEN      200

struct stats_t {
    uint64_t    tot_pkts;
    uint32_t    cur_flows;
    uint32_t    delta_bits;
};

struct config {
    char    *dev;
    pfring  *ring;
    pcap_t  *pcap;
    int     raw_sock;
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

    // Lookup by proxy_id
    struct proxy_map_entry **proxy_map;
};


struct telex_st {
    struct config *conf;
    SSL *ssl;
    int client_sock;
    int proxy_sock;
    uint64_t id;
    char name[32];
    char proxy_id[16];
    struct proxy_map_entry *proxy_entry;

    char rst_pkt[sizeof(struct iphdr)+sizeof(struct tcphdr)];

    struct bufferevent *client_bev;
    struct bufferevent *proxy_bev;
    struct event *rst_event;

    uint64_t client_read_tot;
    uint64_t proxy_read_tot;
    uint32_t client_read_limit;
};

#endif
