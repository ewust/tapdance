#include <event2/bufferevent_ssl.h>
#include "station.h"
#include "libforge_socket.h"

void send_rst_pkt(struct telex_st *state);

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

void cleanup_telex(struct telex_st **_state)
{
    if (!_state) {
        return;
    }
    struct telex_st *state = *_state;
    *_state = NULL;

    LogTrace(state->name, "cleanup");

    if (state->rst_event) {
        event_free(state->rst_event);
        state->rst_event = NULL;
    }

    if (state->proxy_bev) {
        bufferevent_free(state->proxy_bev);
        state->proxy_bev = NULL;
    }

    if (state->ssl && state->client_bev && state->client_sock) {
        SSL_set_shutdown(state->ssl, SSL_RECEIVED_SHUTDOWN);
        SSL_shutdown(state->ssl);
        close(state->client_sock);
    }

    if (state->client_bev) {
        bufferevent_free(state->client_bev);
        state->client_bev = NULL;
    }

    if (state->ssl) {
        SSL_free(state->ssl);
        state->ssl = NULL;
    }

    if (state->client_sock) {
        // should be done by client_bev free?
        //close(state->client_sock);
        state->client_sock = 0;
    }

    state->conf->num_open_tunnels--;
    LogDebug(state->name, "Closed");

    free(state);
}

void rst_and_close(evutil_socket_t fd, short events, void *arg)
{
    struct telex_st *state = arg;

    LogTrace(state->name, "Close and RST timeout");

    send_rst_pkt(state);
    cleanup_telex(&state);
}

#define ISCLIENT(bev, state) ((bev) == (state)->client_bev)
#define ISPROXY(bev, state) ((bev) == (state)->proxy_bev)
#define PARTY(bev, state) (ISCLIENT((bev),(state)) ? "client" : \
    (ISPROXY((bev),(state)) ? "proxy" : "other" ))
#define OTHER_BEV(bev, state) (ISCLIENT((bev),(state)) ? state->proxy_bev : \
    (ISPROXY((bev),(state)) ? state->client_bev : NULL ))

void eventcb(struct bufferevent *bev, short events, void *arg)
{
    struct telex_st *state = arg;
    struct bufferevent *other_bev = OTHER_BEV(bev, state);

    if (events & BEV_EVENT_CONNECTED) {
        LogTrace(state->name, "%s EVENT_CONNECTED", PARTY(bev, state));

        bufferevent_enable(state->proxy_bev, EV_READ|EV_WRITE);
        bufferevent_enable(state->client_bev, EV_READ|EV_WRITE);
    } else if (events & BEV_EVENT_EOF) {
        LogTrace(state->name, "%s EVENT_EOF", PARTY(bev, state));

        if (other_bev) {
            size_t bytes_remain = evbuffer_get_length(bufferevent_get_input(bev));
            if (bytes_remain) {
                LogWarn(state->name, "%d bytes remain after EOF");
                // flush?
                // readcb(bev, state);
            }
        }
        send_rst_pkt(state);
        cleanup_telex(&state);
    } else if (events & BEV_EVENT_ERROR) {
        LogWarn(state->name, "%s EVENT_ERROR", PARTY(bev, state));
        if (ISCLIENT(bev, state)) {
            // Give the client a small amount of time to create a new connection
            // to continue this one
            send_rst_pkt(state);    // make sure this one closes...
        } else {
            // Tear down both connections
            //close_telex_conn(state);
            send_rst_pkt(state);
            cleanup_telex(&state);
        }
    }

}

enum { MSG_DATA=0, MSG_INIT, MSG_RECONNECT, MSG_CLOSE };
// Here we read from the proxy, and package it into a MSG_DATA header
// to the client
void proxy_readcb(struct bufferevent *bev, void *arg)
{
    struct telex_st *state = arg;
    struct config *conf = state->conf;

    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *dst = bufferevent_get_output(state->client_bev);
    size_t buffer_len = evbuffer_get_length(src);
    uint16_t msg_len;
    uint8_t msg_type = MSG_DATA;

    state->proxy_read_tot += buffer_len;
    LogTrace(state->name, "proxy readcb %d bytes -> %d bytes dst (totals: %d client, %d proxy)",
        buffer_len, evbuffer_get_length(dst), state->client_read_tot, state->proxy_read_tot);

    while (buffer_len) {
        msg_len = buffer_len & 0xffff;
        uint16_t msg_len_n = htons(msg_len);
        evbuffer_add(dst, &msg_type, sizeof(msg_type));
        evbuffer_add(dst, &msg_len_n, sizeof(msg_len_n));
        evbuffer_remove_buffer(src, dst, msg_len);

        buffer_len -= msg_len;
    }
}

// For now, the client's data should be directed into the proxy pipe.
// This isn't really saving us much; the bulk of data goes the other way
// and has to be encoded in proxy_readcb.
void client_readcb(struct bufferevent *bev, void *arg)
{
    struct telex_st *state = arg;
    struct config *conf = state->conf;

    if (!state->proxy_bev) {
        // Note: this could be because we are waiting for the client to
        // reconnect to this connection; but we should not have gotten
        // this callback because we should have bufferevent_disable'd it
        LogError(state->name, "client has null partner in read_cb");
        cleanup_telex(&state);
        return;
    }
    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *dst = bufferevent_get_output(state->proxy_bev);

    state->client_read_tot += evbuffer_get_length(src);
    LogTrace(state->name, "client readcb %d bytes -> %d bytes dst (totals: %d client, %d proxy)",
        evbuffer_get_length(src), evbuffer_get_length(dst), state->client_read_tot, state->proxy_read_tot);

    evbuffer_remove_buffer(src, dst, evbuffer_get_length(src));

    if (evbuffer_get_length(src)) {
        LogWarn(state->name, "Still have %d bytes left in buffer", evbuffer_get_length(src));
    }

    if (state->client_read_tot > state->client_read_limit) {
        // need to send client MSG_RECONNECT
        // but really, the client should know this...?
        LogWarn(state->name, "client should have reconnected by now");
    }
}


int extract_telex_tag(char *data, size_t data_len, char *out, size_t out_len)
{
    int ret_len = 0;
    if (data_len < 5) {
        return ret_len;
    }

    unsigned char *p = data;
    char content_type = *p++;
    uint16_t version = (*p++ << 8);
    version |= *p++;
    uint16_t ssl_length = (*p++ << 8);
    ssl_length |= *p++;

    if (ssl_length + 5 > data_len) {
        return ret_len;
    }
    p+=56;  // stego starts 8+48 bytes in for GCM
    int i = 0;
    while (i<ssl_length-59) {
        char ca, cb, cc, cd;
        uint32_t x;
        ca = p[i++];
        cb = p[i++];
        cc = p[i++];
        cd = p[i++];

        x = (ca & 0x3f)*(64*64*64) + (cb & 0x3f)*(64*64) + (cc & 0x3f)*(64) + (cd & 0x3f);

        *out++ = (x >> 16) & 0xff;
        ret_len++;
        if (ret_len >= out_len)
            break;

        *out++ = (x >> 8) & 0xff;
        ret_len++;
        if (ret_len >= out_len)
            break;

        *out++ = (x & 0xff);
        ret_len++;
        if (ret_len >= out_len)
            break;
    }
    return ret_len;
}

uint16_t csum(uint16_t *buf, int nwords, uint32_t init_sum)
{
    uint32_t sum;

    for (sum=init_sum; nwords>0; nwords--) {
        sum += ntohs(*buf++);
    }
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}


void make_rst_pkt(struct telex_st *state, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq)
{
    size_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    struct iphdr *iph = (struct iphdr*)state->rst_pkt;
    struct tcphdr *th = (struct tcphdr*)(&iph[1]);

    memset(iph, 0, sizeof(struct iphdr));
    iph->ihl = sizeof(struct iphdr) >> 2;
    iph->version     = 4;
    iph->tot_len     = htons(tot_len);
    iph->frag_off    = htons(0x4000); //don't fragment
    iph->ttl         = 64;
    iph->id          = htons(1337);
    iph->protocol    = IPPROTO_TCP;
    iph->saddr       = saddr;
    iph->daddr       = daddr;

    //fill in tcp header
    memset(th, 0, sizeof(struct tcphdr));
    th->source     = sport;
    th->dest       = dport;
    th->seq        = seq;
    th->doff       = sizeof(struct tcphdr) >> 2;
    th->rst        = 1;
    th->window     = htons(4096);

    // checksums
    th->check = tcp_checksum(sizeof(struct tcphdr), saddr, daddr, th);
    iph->check = htons(csum((uint16_t *)iph, iph->ihl*2, 0));
}

void send_rst_pkt(struct telex_st *state)
{
    struct iphdr *iph = (struct iphdr*)state->rst_pkt;
    struct tcphdr *th = (struct tcphdr*)(&iph[1]);
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = th->dest;
    sin.sin_addr.s_addr = iph->daddr;

    int res = sendto(state->conf->raw_sock, iph, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&sin, sizeof(sin));
}

// Returns 1 if there is a tcp timestamp option present, and sets ts_val and ts_ecr respectively
// Returns 0 otherwise
int get_tcp_ts_val(struct tcphdr *th, uint32_t *ts_val, uint32_t *ts_ecr)
{
    unsigned char *opts = (unsigned char *)(&th[1]);
    size_t opts_len = 4*th->doff - sizeof(struct tcphdr);
    unsigned char kind, cur_opt_len;
    int i = 0;
    while (i < opts_len) {
        kind = opts[i];
        if (kind == 0x00) {
            break;
        }

        if (kind == 0x01) {
            // NOP, no opt_len
            i++;
            continue;
        }

        cur_opt_len = opts[i+1];

        if (kind == 0x08) {
            // TCP timestamp
            if (ts_val)
                *ts_val = ntohl(*(uint32_t*)(&opts[i+2]));
            if (ts_ecr)
                *ts_ecr = ntohl(*(uint32_t*)(&opts[i+6]));
            return 1;
        }

        i += cur_opt_len;
    }
    return 0;
}

struct init_msg_st {
    uint8_t type;
    uint16_t len;
    uint16_t magic_val; // Prevent accidental init (do we need this?)
    uint16_t win_size;
} __attribute__((packed));
#define SPTELEX_MAGIC_VAL 0x2a75

void send_init_msg(struct telex_st *state)
{
    struct init_msg_st msg;
    msg.type = MSG_INIT;
    msg.len = htons(sizeof(msg) - 3);
    msg.magic_val = htons(SPTELEX_MAGIC_VAL);
    // TODO: lookup
    msg.win_size = htons(16384);
    evbuffer_add(bufferevent_get_output(state->client_bev), &msg, sizeof(msg));
}

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

void init_forge_socket_conn(struct telex_st *state, struct iphdr *iph, struct tcphdr *th, uint32_t server_ack)
{
    state->client_sock = socket(AF_INET, SOCK_FORGE, 0);
    if (state->client_sock < 0) {
        LogError(state->name, "forget_socket socket() error");
        perror("(forge_)socket");
        cleanup_telex(&state);
    }

    struct tcp_state *tcp_st = forge_socket_get_default_state();
    tcp_st->src_ip  = iph->daddr;
    tcp_st->dst_ip  = iph->saddr;
    tcp_st->sport   = th->dest;
    tcp_st->dport   = th->source;
    tcp_st->seq     = ntohl(th->ack_seq);   // There is no good reason why these are little endian, and the rest are big...
    tcp_st->ack     = server_ack;

    tcp_st->snd_una = tcp_st->seq;
    // TODO: options based on flow
    // where are we going to get these values?
    // The client can send us some if they can get it
    // from userspace, otherwise we can only know client window
    // scale from SYN; can't be guaranteed to get SYN-ACK
    tcp_st->sack_ok = 1;
    tcp_st->wscale_ok = 1;
    tcp_st->snd_wscale = 7;
    tcp_st->rcv_wscale = 10;
    tcp_st->rcv_wnd = 139;
    tcp_st->snd_wnd = 5;

    //tcp_st->tstamp_ok = get_tcp_ts_val(th, &tcp_st->ts_recent, &tcp_st->ts_val);
    // TODO: update kernel to one that uses tcp_sk(sk)->tsoffset for each sock;
    // 3.5 uses jiffies as a global timestamp. v3.9 looks like it adds in a sock-specific
    // tsoffset that we could use to get what we want. v3.9 might have other goodies, too...
    tcp_st->tstamp_ok = 0;
    //tcp_st->ts_val += 100;

    tcp_st->mss_clamp = 1460;

    forge_socket_set_state(state->client_sock, tcp_st);
    evutil_make_socket_nonblocking(state->client_sock);
    free(tcp_st);
}

void init_telex_conn(struct config *conf, struct iphdr *iph, struct tcphdr *th, size_t tcp_len,
                     char *tcp_data, char *stego_data, size_t stego_len)
{
    size_t master_key_len;
    char *master_key;
    unsigned char *server_random, *client_random;
    char *conn_id;
    int i;


    // Unpack master key
    master_key_len = stego_data[7];
    if (master_key_len > stego_len - 8) {
        master_key_len = stego_len - 8;
    }
    master_key = &stego_data[8];

    // Unpack client/server randoms
    server_random = (unsigned char*)&stego_data[8+master_key_len];
    client_random = (unsigned char*)&stego_data[8+master_key_len+32];
    conn_id = &stego_data[8+master_key_len+64];

    SSL *ssl;
    ssl = get_live_ssl_obj(master_key, master_key_len, htons(0x009e), server_random, client_random);

    char *req_plaintext;
    if (ssl_decrypt(ssl, tcp_data, tcp_len - 4*th->doff, &req_plaintext) < 0) {
        return;
    }

    char dst_addr[INET_ADDRSTRLEN], src_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &iph->daddr, dst_addr, INET_ADDRSTRLEN);

    // Setup new TCP forge socket
    // Attach SSL to it
    // Send response "HTTP/1.1 299 OK SPTELEX\r\n"
    // create new connection to socks/http proxy
    // Setup bufferevents for both proxy and forge_socket/TLS and forward between
    struct telex_st *state;

    state = lookup_conn_id(conf, conn_id);
    if (!state) {
        // New, never-before seen connection/proxy connection
        state = malloc(sizeof(struct telex_st));
        memset(state, 0, sizeof(struct telex_st));
        state->conf = conf;
        if (state == NULL) {
            LogError("station", "Error: out of memory\n");
            return;
        }

        state->proxy_read_tot = 0;
        conf->num_open_tunnels++;
        state->id = conf->num_tunnels++;

        snprintf(state->name, sizeof(state->name), "tunnel %lu" , state->id);

        HexDump(LOG_TRACE, state->name, "Created, conn_id: ", conn_id, 16);

        // Setup new proxy connection
        state->proxy_bev = bufferevent_socket_new(conf->base, -1, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(state->proxy_bev, proxy_readcb, NULL, eventcb, state);
        if (bufferevent_socket_connect(state->proxy_bev,
                (struct sockaddr *)&conf->proxy_addr_sin, sizeof(struct sockaddr_in)) < 0) {
            LogError(state->name, "Bufferevent_socket_connect failed for connecting to proxy");
            cleanup_telex(&state);
            return;
        }
    }

    LogDebug(state->name, "opened %s:%d -> %s:%d", src_addr, ntohs(th->source), dst_addr, ntohs(th->dest));

    if (state->ssl) {
        LogWarn(state->name, "someone left an ssl here...");
        SSL_free(state->ssl);
    }
    state->ssl = ssl;

    if (state->client_bev) {
        LogWarn(state->name, "someone left a client_bev here...");
        bufferevent_free(state->client_bev);
    }

    if (state->client_sock) {
        LogWarn(state->name, "someone left a client sock here...");
        close(state->client_sock);
    }

    // Setup client forge sock
    uint32_t server_ack = ntohl(th->seq) + (tcp_len - 4*th->doff);  // host order
    init_forge_socket_conn(state, iph, th, server_ack);
    state->client_read_tot = 0;

    // change SSL bio to use our forge_socket
    BIO *bio = BIO_new_socket(state->client_sock, BIO_NOCLOSE);
    SSL_set_bio(state->ssl, bio, bio);

    // Setup client "connection"
    // TODO: maybe don't use BEV_OPT_CLOSE_ON_FREE, so we can shut it down cleanly
    state->client_bev = bufferevent_openssl_socket_new(conf->base,
                                                       state->client_sock,
                                                       state->ssl,
                                                       BUFFEREVENT_SSL_OPEN,
                                                       0);
    bufferevent_setcb(state->client_bev, client_readcb, NULL, eventcb, state);

    // Prepare (but don't send) RST packet for server once we need to tear-down connection
    make_rst_pkt(state, iph->saddr, iph->daddr, th->source, th->dest, htonl(server_ack));

    // Write the ACK mesage!
    send_init_msg(state);

    // Set timeout on connection
    // TODO: timeout/window per server that we are impersonating
    state->client_read_limit = 16384;
    struct timeval rst_tv = {18, 0};
    state->rst_event = event_new(state->conf->base, -1, 0, rst_and_close, state);
    event_add(state->rst_event, &rst_tv);
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
    memset(stego_data, 0, sizeof(stego_data));
    int extract_len = extract_telex_tag(tcp_data, tcp_len - 4*th->doff, stego_data, sizeof(stego_data));

    if (memcmp(stego_data, "SPTELEX", 7)==0) { // || ip_ptr->saddr == 0x236fd48d) {

        // Tagged connection
        init_telex_conn(conf, ip_ptr, th, tcp_len, tcp_data, stego_data, extract_len);
   }

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

    //(uint32_t)tv.tv_sec, (int)tv.tv_usec/1000, 
    LogInfo("station", "%d flows (%u pkts, %.1f %s) drop %u (if %u) (cleanup %d in %d ms)",
        conf->stats.cur_flows, stats.ps_recv, bw, bw_unit, stats.ps_drop, stats.ps_ifdrop,
        num_removed, diff_ms);
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

void print_help(char *prog_name)
{
    printf("SPTelex Station\n\n"
           "\tUsage: %s [options]\n"
           "\t\t--iface IFACE, -i IFACE         interface to listen on (default eth0)\n"
           "\t\t--file FNAME, -f FNAME          .pcap file to read from instead of listen\n"
           "\t\t--pfring_id ID, -p ID           PF_RING cluster ID to use (default 0)\n"
           "\t\t--proxy HOST:PORT -c HOST:PORT  host (ipv4 address) to connect to for each new HTTP proxy (default 127.0.0.1:8123)\n"
           "\t\t--verbosity LEVEL, -v LEVEL     verbosity level; 0=fatal, 5=trace (default 3)\n\n",
            prog_name);
}

int main(int argc,char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct config conf;
    struct bpf_program bpf;
    char *pcap_fname = NULL;
    FILE *pcap_fstream;
    char *pstr = NULL;

    memset(&conf, 0, sizeof(conf));
    conf.dev = "eth0";
    conf.pfring_id = 0;
    conf.proxy_addr_sin.sin_family = AF_INET;
    conf.proxy_addr_sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    conf.proxy_addr_sin.sin_port = htons(8123);

    LogOutputLevel(LOG_INFO); // show warnings and more severe
    LogOutputStream(stdout);

    int c;
    int option_index = 0;
    static struct option long_options[] = {
        {"iface",   optional_argument, 0, 'i'},
        {"file", optional_argument, 0, 'f'},
        {"pfring_id", optional_argument, 0, 'p'},
        {"verbosity", optional_argument, 0, 'v'},
        {"proxy", optional_argument, 0, 'c'},
        {0, 0, 0, 0}
    };
    while (1) {
        c = getopt_long(argc, argv, "i:f:p:v:c:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            LogError("station", "option %s", long_options[option_index].name);
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
        case 'v':
            LogOutputLevel(atoi(optarg));
            break;
        case 'c':

            conf.proxy_addr_sin.sin_addr.s_addr = inet_addr(strtok(optarg, ":"));
            pstr = strtok(NULL, ":");
            if (pstr) {
                int port = strtol(pstr, NULL, 10);
                if (port < 1 || port > 65535) {
                    fprintf(stderr, "Invalid remote port: %d", port);
                    return 1;
                }
                conf.proxy_addr_sin.sin_port = htons(port);
            }
            break;
        default:
            print_help(argv[0]);
            return -1;
        }
    }


    LogDebug("station", "using proxy host %s:%d", inet_ntoa(conf.proxy_addr_sin.sin_addr),
             ntohs(conf.proxy_addr_sin.sin_port));

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
            LogError("station", "pcap_compile");
            return -1;
        }
        if (pcap_setfilter(conf.pcap, &bpf) < 0) {
            LogError("station", "pcap_setfilter error");
            return -1;
        }

        conf.pcap_fd = fileno(pcap_fstream);

    } else if (conf.pfring_id) {
        conf.ring = pfring_open(conf.dev, 65535, PF_RING_PROMISC);
        if (!conf.ring) {
            perror("pfring failure");
            exit(-1);
        }
        LogDebug("station", "setting cluster id %d", conf.pfring_id);

        if (pfring_set_bpf_filter(conf.ring, PCAP_FILTER_STR) != 0) {
            LogError("station", "Error: pfring_set_bpf_filter");
            exit(-1);
        }
        pfring_set_cluster(conf.ring, conf.pfring_id, cluster_per_flow_5_tuple);
        pfring_set_application_name(conf.ring, "station");
        if (pfring_set_socket_mode(conf.ring, recv_only_mode) != 0) {
            LogError("station", "Error: pfring_set_socket_mode");
            exit(-1);
        }
        if (pfring_enable_ring(conf.ring) != 0) {
            pfring_close(conf.ring);
            LogError("station", "Error: pfring_enable_ring");
            exit(-1);
        }

        conf.pcap_fd = conf.ring->fd;
        LogDebug("station", "using fd %d", conf.pcap_fd);
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

    // Init raw sock
    conf.raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (conf.raw_sock < 0) {
        LogError("station", "could not open raw sock for sending RSTs");
    }


    if (pcap_fname == NULL) {
        // pfring/pcap
        event_base_dispatch(conf.base);
    } else {
        LogInfo("station", "reading from file");
        while (1) {
            pkt_cb(0, 0, &conf);
        }
    }

    LogInfo("station", "done\n");

    return 0;
}
