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
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include "pfring.h"


#define FLOW_EXPIRE_SECS    10      // note: this is the time between TLS data packets...
#define PCAP_FILTER_STR     "tcp and port 443"
#define STEGO_DATA_LEN      128

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

struct telex_state_st {
    int sock;
    //SSL *ssl;

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
};

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

uint16_t tcp_checksum(unsigned short len_tcp,
        uint32_t saddr, uint32_t daddr, struct tcphdr *tcp_pkt)
{
    uint16_t *src_addr = (uint16_t *) &saddr;
    uint16_t *dest_addr = (uint16_t *) &daddr;

    unsigned char prot_tcp = 6;
    unsigned long sum = 0;
    int nleft = len_tcp;
    unsigned short *w;

    w = (unsigned short *) tcp_pkt;
    // calculate the checksum for the tcp header and tcp data
    while(nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    // if nleft is 1 there ist still on byte left.
    // We add a padding byte (0xFF) to build a 16bit word
    if (nleft > 0) {
        sum += *w & ntohs(0xFF00);
    }
    // add the pseudo header
    sum += src_addr[0];
    sum += src_addr[1];
    sum += dest_addr[0];
    sum += dest_addr[1];
    sum += htons(len_tcp);
    sum += htons(prot_tcp);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    // Take the one's complement of sum
    return (unsigned short) (~sum);
}

int is_tcp_checksum_correct(struct iphdr *ip_ptr, struct tcphdr *th, uint32_t th_len)
{
    uint16_t csum = th->check;
    th->check = 0;
    uint16_t correct_csum = tcp_checksum(th_len, ip_ptr->saddr, ip_ptr->daddr, th);
    th->check = csum;
    return (csum == correct_csum);
}

int is_tls_data_packet(struct tcphdr *th, size_t tcp_len)
{
    assert(tcp_len >= sizeof(struct tcphdr));

    char *data = (((char*)th) + 4*th->doff);
    tcp_len -= 4*th->doff;

    return ((tcp_len > 1) && ((*data) == '\x17'));
}

void extract_telex_tag(char *data, size_t data_len, char *out, size_t out_len)
{

}

void handle_pkt(void *ptr, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct config *conf = ptr;
    size_t pkt_len = pkthdr->caplen;
    struct iphdr *ip_ptr = (struct iphdr*)(packet+sizeof(struct ether_header));

    conf->stats.tot_pkts++;
    conf->stats.delta_bits += 8*pkthdr->caplen;

    if (ip_ptr->protocol != IPPROTO_TCP) {
        return;
    }

    if (pkt_len < (sizeof(struct ether_header) + 4*(ip_ptr->ihl) + sizeof(struct tcphdr))) {
        return;
    }
    pkt_len -= sizeof(struct ether_header) + 4*(ip_ptr->ihl);   // size of tcp header + data
    struct tcphdr *th = (struct tcphdr*)(packet+sizeof(struct ether_header)+(4*(ip_ptr->ihl)));
    uint32_t tcp_len = ntohs(ip_ptr->tot_len) - 4*(ip_ptr->ihl);

    if (tcp_len > pkt_len) {
        return;
    }

    // We can do the following in really any order.
    // We sort it this way to minimize work for common packets (TODO: measure)
    // #1. Check if this a TLS application data packet
    //      (TODO: if it's a (valid?) FIN or RST, remove the flow from the map)
    // #2. Check if this is part of a flow we care about
    //      (we only care about new flows; i.e. client's first request packet)
    // #3. Check TCP checksum

    if (!is_tls_data_packet(th, tcp_len)) {
        return;
    }

    struct flow *cur_flow = lookup_flow(&conf->conn_map, ip_ptr->saddr, ip_ptr->daddr, th->source, th->dest);
    if (cur_flow != NULL) {
        // We have heard of this before; either it's a non-Telex flow (in which case we don't care),
        // or it's a Telex flow (in which case our forge-socket will pickup this packet)
        memcpy(&cur_flow->expire, &pkthdr->ts, sizeof(struct timeval));
        cur_flow->expire.tv_sec += FLOW_EXPIRE_SECS;
        return;
    }

    // Checkchecksum.
    if (!is_tcp_checksum_correct(ip_ptr, th, tcp_len)) {
        return;
    }


    // Create new flow
    // Check if this is tagged
    // if not, just leave flow telex_flow_st == NULL
    // otherwise, setup the telex flow

    cur_flow = malloc(sizeof(*cur_flow));
    assert(cur_flow != NULL);
    cur_flow->next = NULL;
    cur_flow->src_ip = ip_ptr->saddr;
    cur_flow->dst_ip = ip_ptr->daddr;
    cur_flow->src_port = th->source;
    cur_flow->dst_port = th->dest;

    // set expiration
    memcpy(&cur_flow->expire, &pkthdr->ts, sizeof(struct timeval));
    cur_flow->expire.tv_sec += FLOW_EXPIRE_SECS;

    add_flow(&conf->conn_map, cur_flow);
    conf->stats.cur_flows++;


    // Attempt to extract stego channel
    char stego_data[STEGO_DATA_LEN];
    char *tcp_data = (((char*)th) + 4*th->doff);
    extract_telex_tag(tcp_data, tcp_len - 4*th->doff, stego_data, sizeof(stego_data));

    
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

void print_status(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;
    struct pcap_stat stats;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (conf->ring == NULL) {
        pcap_stats(conf->pcap, &stats);
    } else {
        memset(&stats, 0, sizeof(stats));
    }

    int num_removed = cleanup_expired(conf);

    struct timeval tv_end;
    gettimeofday(&tv_end, NULL);
    uint32_t diff_ms = (tv_end.tv_sec - tv.tv_sec)*1000 + (tv_end.tv_usec - tv.tv_usec)/1000;

    char *bw_unit = "b/s";
    float bw = (float)(conf->stats.delta_bits);
    if (bw > 1000) {
        bw /= 1000;
        bw_unit = "kb/s";
    }
    if (bw > 1000) {
        bw /= 1000;
        bw_unit = "mb/s";
    }

    printf("%d.%03d: %d flows (%u pkts, %.1f %s) drop %u (if %u) (cleanup %d in %d ms)\n",
        (uint32_t)tv.tv_sec, (int)tv.tv_usec/1000, conf->stats.cur_flows, stats.ps_recv, bw, bw_unit, stats.ps_drop, stats.ps_ifdrop,
        num_removed, diff_ms);
    fflush(stdout);
    conf->stats.delta_bits = 0;
}


void pkt_cb(evutil_socket_t fd, short what, void *ptr)
{
    struct config *conf = ptr;
    const char *pkt;
    struct pcap_pkthdr pkt_hdr;

    if (conf->ring != NULL) {
        int ret;
        struct pfring_pkthdr hdr;
        unsigned char buffer[9000]; //NO_ZC_BUFFER_LEN];
        unsigned char *buffer_p = buffer;
        ret = pfring_recv(conf->ring, &buffer_p, 0, &hdr, 0);
        if (ret > 0) {
            handle_pkt(conf, (struct pcap_pkthdr*)&hdr, buffer_p);
        }
        return;
    }

    // file or pcap (non pfring)
    pkt = pcap_next(conf->pcap, &pkt_hdr);
    if (pkt == NULL) {
        return;
    }

    handle_pkt(conf, &pkt_hdr, pkt);
}

int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct config conf;
    struct bpf_program bpf;
    char *pcap_fname = NULL;
    FILE *pcap_fstream;

    memset(&conf, 0, sizeof(conf));
    conf.dev = "eth0";

    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"iface",   optional_argument, 0, 'i'},
        {"file", optional_argument, 0, 'f'},
        {"pfring_id", optional_argument, 0, 'p'},
        {0, 0, 0, 0}
    };
    while (1) {
        c = getopt_long(argc, argv, "i:f:p:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;
        case 'i':
            conf.dev = optarg;
            break;
        case 'f':
            pcap_fname = optarg;
            break;
        case 'p':
            conf.pfring_id = atoi(optarg);
            break;
        }
    }



    //pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    if (pcap_fname != NULL) {
        // open pcap file
        pcap_fstream = fopen(pcap_fname, "r");
        if (!pcap_fstream) {
            perror("fopen");
            return -1;
        }

        int saved_flags;
        saved_flags = fcntl(fileno(pcap_fstream), F_GETFL);

        fcntl(fileno(pcap_fstream), F_SETFL, saved_flags | O_NONBLOCK);

        conf.pcap = pcap_fopen_offline(pcap_fstream, errbuf);

        if (pcap_compile(conf.pcap, &bpf, PCAP_FILTER_STR, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            printf("pcap_compile error\n");
            return -1;
        }
        if (pcap_setfilter(conf.pcap, &bpf) < 0) {
            printf("pcap_setfilter error\n");
            return -1;
        }

        conf.pcap_fd = fileno(pcap_fstream);

    } else if (conf.pfring_id) {
        conf.ring = pfring_open(conf.dev, 65535, PF_RING_PROMISC);
        if (!conf.ring) {
            perror("pfring failure");
            exit(-1);
        }
        printf("setting cluster id %d\n", conf.pfring_id);

        if (pfring_set_bpf_filter(conf.ring, PCAP_FILTER_STR) != 0) {
            printf("Error: pfring_set_bpf_filter");
            exit(-1);
        }
        pfring_set_cluster(conf.ring, conf.pfring_id, cluster_per_flow_5_tuple);
        pfring_set_application_name(conf.ring, "rexmit");
        if (pfring_set_socket_mode(conf.ring, recv_only_mode) != 0) {
            printf("Error: pfring_set_socket_mode\n");
            exit(-1);
        }
        if (pfring_enable_ring(conf.ring) != 0) {
            pfring_close(conf.ring);
            printf("Error: pfring_enable_ring\n");
            exit(-1);
        }

        conf.pcap_fd = conf.ring->fd;
        printf("using fd %d\n", conf.pcap_fd);
    }


    // Setup libevent
    event_init();
    conf.base = event_base_new();

    // Event on pcap fd EV_READ
    conf.pkt_ev = event_new(conf.base, conf.pcap_fd, EV_READ|EV_PERSIST, pkt_cb, &conf);
    event_add(conf.pkt_ev, NULL);

    // Status timer
    struct timeval one_sec = {1, 0};
    conf.status_ev = event_new(conf.base, -1, EV_PERSIST, print_status, &conf);
    event_add(conf.status_ev, &one_sec);


    // Init map
    conf.conn_map.map = calloc(sizeof(struct flow*), MAP_ENTRIES);


    if (pcap_fname == NULL) {
        // pfring/pcap
        event_base_dispatch(conf.base);
    } else {
        printf("reading from file\n");
        while (1) {
            pkt_cb(0, 0, &conf);
        }
    }

    printf("done\n");

    return 0;
}
