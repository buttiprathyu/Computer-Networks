#ifndef SR_DEBUG_H
#define SR_DEBUG_H

#include <stdio.h>
#include <inttypes.h>

#include "sr_protocol.h"

void sr_deb_print_bool(FILE *stream, int val);
void sr_deb_print_mac_address(FILE *stream, uint8_t mac_addr[]);
void sr_deb_print_ip_address(FILE *stream, uint32_t ip_addr);

void sr_deb_print_packet(FILE *stream, struct sr_ethernet_hdr *pkt, size_t pkt_size);
void sr_deb_print_ether_header(FILE *stream, struct sr_ethernet_hdr *hdr);
void sr_deb_print_ip_header(FILE *stream, struct ip *hdr);
void sr_deb_print_arp_header(FILE *stream, struct sr_arphdr *hdr);
void sr_deb_print_icmp_header(FILE *stream, struct icmp_hdr *hdr);

void sr_deb_print_incoming(FILE *stream, size_t pack_size);
void sr_deb_print_outgoing(FILE *stream, size_t pack_size);

#endif // SR_DEBUG_H
