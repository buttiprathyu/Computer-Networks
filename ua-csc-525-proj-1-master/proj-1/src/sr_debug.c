#include "sr_debug.h"

void sr_deb_print_bool(FILE *stream, int val)
{
#ifdef _DEBUG_
    fprintf(stream, val ? "true" : "false");
#endif
}

void sr_deb_print_mac_address(FILE *stream, uint8_t mac_addr[])
{
#ifdef _DEBUG_
    for(size_t i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if(i != 0) fprintf(stream, ":");
        fprintf(stream, "%2.2x", mac_addr[i]);
    }
#endif
}

void sr_deb_print_packet(FILE *stream, struct sr_ethernet_hdr *pkt, size_t pkt_size)
{
#ifdef _DEBUG_
    sr_deb_print_ether_header(stream, pkt);
    switch(ntohs(pkt->ether_type))
    {
    case ETHERTYPE_IP:
        sr_deb_print_ip_header(stream, (struct ip *)(pkt + 1));
        switch(((struct ip *)(pkt + 1))->ip_p)
        {
        case IPPROTO_ICMP:
            sr_deb_print_icmp_header(stream, (struct icmp_hdr *)((struct ip *)(pkt + 1) + 1));
        default:;
        }
        break;
    case ETHERTYPE_ARP:
        sr_deb_print_arp_header(stream, (struct sr_arphdr *)(pkt + 1));
        break;
    default:;
    }
#endif
}

void sr_deb_print_ip_address(FILE *stream, uint32_t ip_addr)
{
#ifdef _DEBUG_
    for(size_t i = 0; i < 4; i++)
    {
        if(i != 0) fprintf(stream, ".");
        fprintf(stream, "%hhu", (uint8_t)(ip_addr >> (8 * (3 - i))));
    }
#endif
}

void sr_deb_print_ether_header(FILE *stream, struct sr_ethernet_hdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---ETHERNET HEADER---\n");
    fprintf(stream, "Dest:       ");
    sr_deb_print_mac_address(stream, hdr->ether_dhost);
    fprintf(stream, "\n");
    fprintf(stream, "Src:        ");
    sr_deb_print_mac_address(stream, hdr->ether_shost);
    fprintf(stream, "\n");
    fprintf(stream, "Ether_type: 0x%4.4x\n", ntohs(hdr->ether_type));
    fprintf(stream, "---------------------\n");
#endif
}

void sr_deb_print_ip_header(FILE *stream, struct ip *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---IP HEADER---\n");
    fprintf(stream, "Version:           0x%1.1x\n", hdr->ip_v);
    fprintf(stream, "Header len:        0x%1.1x\n", hdr->ip_hl);
    fprintf(stream, "Type of service:   0x%2.2x\n", hdr->ip_tos);
    fprintf(stream, "Total length:      %hu\n", ntohs(hdr->ip_len));
    fprintf(stream, "ID:                %hu\n", ntohs(hdr->ip_id));
    uint16_t ip_off = ntohs(hdr->ip_off);
    fprintf(stream, "Reserved Fragment: ");
    sr_deb_print_bool(stream, ip_off & IP_RF);
    fprintf(stream, "\n");
    fprintf(stream, "Don't Fragment:    ");
    sr_deb_print_bool(stream, ip_off & IP_DF);
    fprintf(stream, "\n");
    fprintf(stream, "More Fragments:    ");
    sr_deb_print_bool(stream, ip_off & IP_MF);
    fprintf(stream, "\n");
    fprintf(stream, "Fragment offset:   %hu\n", ip_off & IP_OFFMASK);
    fprintf(stream, "TTL:               %hhu\n", hdr->ip_ttl);
    fprintf(stream, "Protocol:          0x%2.2x\n", hdr->ip_p);
    fprintf(stream, "Checksum:          0x%4.4x\n", ntohs(hdr->ip_p));
    fprintf(stream, "Src IP:            ");
    sr_deb_print_ip_address(stream, ntohl(hdr->ip_src.s_addr));
    fprintf(stream, "\n");
    fprintf(stream, "Dest IP:           ");
    sr_deb_print_ip_address(stream, ntohl(hdr->ip_dst.s_addr));
    fprintf(stream, "\n");
    fprintf(stream, "---------------\n");
#endif
}

void sr_deb_print_arp_header(FILE *stream, struct sr_arphdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---ARP HEADER---\n");
    fprintf(stream, "Hardware type:     %hu\n", ntohs(hdr->ar_hrd));
    fprintf(stream, "Protocol type:     0x%4.4x\n", ntohs(hdr->ar_pro));
    fprintf(stream, "Physical addr len: %hhu\n", hdr->ar_hln);
    fprintf(stream, "Protocol addr len: %hhu\n", hdr->ar_pln);
    fprintf(stream, "Operation:         0x%4.4x\n", ntohs(hdr->ar_op));
    fprintf(stream, "Sender MAC:        ");
    sr_deb_print_mac_address(stream, hdr->ar_sha);
    fprintf(stream, "\n");
    fprintf(stream, "Sender IP Addr:    ");
    sr_deb_print_ip_address(stream, ntohl(hdr->ar_sip));
    fprintf(stream, "\n");
    fprintf(stream, "Target MAC:        ");
    sr_deb_print_mac_address(stream, hdr->ar_tha);
    fprintf(stream, "\n");
    fprintf(stream, "Target IP Addr:    ");
    sr_deb_print_ip_address(stream, ntohl(hdr->ar_tip));
    fprintf(stream, "\n");
    fprintf(stream, "----------------\n");
#endif
}

void sr_deb_print_icmp_header(FILE *stream, struct icmp_hdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---ICMP HEADER---\n");
    fprintf(stream, "Type:     %hhu\n", hdr->type);
    fprintf(stream, "Code:     %hhu\n", hdr->code);
    fprintf(stream, "Checksum: 0x%4.4x\n", ntohs(hdr->checksum));
    fprintf(stream, "-----------------\n");
#endif
}

void sr_deb_print_incoming(FILE *stream, size_t pack_size)
{
#ifdef _DEBUG_
    fprintf(stream, "INCOMING: Received packet of length %lu \n", pack_size);
#endif
}

void sr_deb_print_outgoing(FILE *stream, size_t pack_size)
{
#ifdef _DEBUG_
    fprintf(stream, "OUTGOING: Sending packet of length %lu\n", pack_size);
#endif
}
