#include "station.h"
#include "tcp.h"

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

int tcp_is_checksum_correct(struct iphdr *ip_ptr, struct tcphdr *th, uint32_t th_len)
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

// This is really an IP function, but we'll let it slide
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


void tcp_make_rst_pkt(struct telex_st *state, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq)
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

void tcp_send_rst_pkt(struct telex_st *state)
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
int tcp_get_ts_val(struct tcphdr *th, uint32_t *ts_val, uint32_t *ts_ecr)
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




