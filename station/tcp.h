#ifndef TCP_H
#define TCP_H

#include "station.h"

uint16_t tcp_checksum(unsigned short len_tcp,
        uint32_t saddr, uint32_t daddr, struct tcphdr *tcp_pkt);

int tcp_is_checksum_correct(struct iphdr *ip_ptr, struct tcphdr *th,
                            uint32_t th_len);


int is_tls_data_packet(struct tcphdr *th, size_t tcp_len);

void tcp_make_rst_pkt(struct telex_st *state, uint32_t saddr, uint32_t daddr,
                  uint16_t sport, uint16_t dport, uint32_t seq);


void tcp_send_rst_pkt(struct telex_st *state);

int tcp_get_ts_val(struct tcphdr *th, uint32_t *ts_val, uint32_t *ts_ecr);

#endif


