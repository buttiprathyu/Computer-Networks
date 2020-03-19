#ifndef SR_DEBUG_H
#define SR_DEBUG_H

#include <stdio.h>
#include <inttypes.h>

#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_pwospf_graph.h"

void sr_deb_print_str(FILE *stream, char *str);

void sr_deb_print_bool(FILE *stream, int val);
void sr_deb_print_mac_address(FILE *stream, uint8_t mac_addr[]);
void sr_deb_print_ip_address(FILE *stream, uint32_t ip_addr);

void sr_deb_print_packet(FILE *stream, struct sr_ethernet_hdr *pkt, size_t pkt_size);
void sr_deb_print_ether_header(FILE *stream, struct sr_ethernet_hdr *hdr);
void sr_deb_print_ip_header(FILE *stream, struct ip *hdr);
void sr_deb_print_arp_header(FILE *stream, struct sr_arphdr *hdr);
void sr_deb_print_icmp_header(FILE *stream, struct icmp_hdr *hdr);
void sr_deb_print_ospf_header(FILE *stream, struct ospfv2_hdr *hdr);
void sr_deb_print_ospf_hello_header(FILE *stream, struct ospfv2_hello_hdr *hdr);
void sr_deb_print_ospf_lsu_header(FILE *stream, struct ospfv2_lsu_hdr *hdr);
void sr_deb_print_ospf_lsu(FILE *stream, struct ospfv2_lsu *lsu);
void sr_deb_print_ospf_lsu_list(FILE *stream, struct ospfv2_lsu *array, size_t array_len);

void sr_deb_print_pwospf_graph(FILE *f, struct pwospf_node *g);
void sr_deb_print_pwospf_node(FILE *f, struct pwospf_node *n);
void sr_deb_print_pwospf_edge(FILE *f, struct pwospf_edge *e);

void sr_deb_print_incoming(FILE *stream, size_t pack_size);
void sr_deb_print_outgoing(FILE *stream, size_t pack_size);

void sr_deb_print_mem(FILE *stream, uint8_t *buf, size_t size);

#endif // SR_DEBUG_H
