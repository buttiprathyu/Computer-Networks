#include "sr_debug.h"

void sr_deb_print_str(FILE *stream, char *str)
{
#ifdef _DEBUG_
    fprintf(stream, "%s", str);
#endif
}

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
    {
        struct ip *ip_hdr = (struct ip *)(pkt + 1);
        sr_deb_print_ip_header(stream, ip_hdr);
        switch(ip_hdr->ip_p)
        {
        case IPPROTO_ICMP:
        {
            struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(ip_hdr + 1);
            sr_deb_print_icmp_header(stream, icmp_hdr);
            break;
        }
        case IPPROTO_OSPF:
        {
            struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(ip_hdr + 1);
            sr_deb_print_ospf_header(stream, ospf_hdr);
            if(ospf_hdr->type == OSPF_TYPE_HELLO)
            {
                struct ospfv2_hello_hdr *ospf_hello_hdr = (struct ospfv2_hello_hdr *)(ospf_hdr + 1);
                sr_deb_print_ospf_hello_header(stream, ospf_hello_hdr);
                break;
            }
            else if(ospf_hdr->type == OSPF_TYPE_LSU)
            {
                struct ospfv2_lsu_hdr *ospf_lsu_hdr = (struct ospfv2_lsu_hdr *)(ospf_hdr + 1);
                sr_deb_print_ospf_lsu_header(stream, ospf_lsu_hdr);
                struct ospfv2_lsu *lsu_list = (struct ospfv2_lsu *)(ospf_lsu_hdr + 1);
                sr_deb_print_ospf_lsu_list(stream, lsu_list, ntohl(ospf_lsu_hdr->num_adv));
                break;
            }
            break;
        }
        default:
            break;
        }
        break;
    }
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
    fprintf(stream, "Checksum:          0x%4.4x\n", ntohs(hdr->ip_sum));
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

void sr_deb_print_ospf_header(FILE *stream, struct ospfv2_hdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---OSPF COMMON HEADER---\n");
    fprintf(stream, "Version:  %hhu\n", hdr->version);
    fprintf(stream, "Type:     %hhu\n", hdr->type);
    fprintf(stream, "Length:   %hu\n", htons(hdr->len));
    fprintf(stream, "RID:      ");
    sr_deb_print_ip_address(stream, ntohl(hdr->rid));
    fprintf(stream, "\n");
    fprintf(stream, "AID:      0x%8.8x\n", ntohl(hdr->aid));
    fprintf(stream, "Checksum: 0x%4.4x\n", ntohs(hdr->csum));
    fprintf(stream, "Au Type:  %hu\n", ntohs(hdr->autype));
    // TODO there is no ntohll
    fprintf(stream, "Au Data:  %lu\n", hdr->audata);
    fprintf(stream, "------------------------\n");
#endif
}

void sr_deb_print_ospf_hello_header(FILE *stream, struct ospfv2_hello_hdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---OSPF HELLO HEADER---\n");
    fprintf(stream, "Network Mask: ");
    sr_deb_print_ip_address(stream, ntohl(hdr->nmask));
    fprintf(stream, "\n");
    fprintf(stream, "Hello Int:    %hu\n", ntohs(hdr->helloint));
    fprintf(stream, "-----------------------\n");
#endif
}

void sr_deb_print_ospf_lsu_header(FILE *stream, struct ospfv2_lsu_hdr *hdr)
{
#ifdef _DEBUG_
    fprintf(stream, "---OSPF LSU HEADER---\n");
    fprintf(stream, "Seq #:   %hu\n", ntohs(hdr->seq));
    fprintf(stream, "TTL:     %hhu\n", hdr->ttl);
    fprintf(stream, "Num Adv: %u\n", ntohl(hdr->num_adv));
    fprintf(stream, "---------------------\n");
#endif
}

void sr_deb_print_ospf_lsu(FILE *stream, struct ospfv2_lsu *lsu)
{
#ifdef _DEBUG_
    fprintf(stream, "Subnet: ");
    sr_deb_print_ip_address(stream, ntohl(lsu->subnet));
    fprintf(stream, "\n");
    fprintf(stream, "Mask: ");
    sr_deb_print_ip_address(stream, ntohl(lsu->mask));
    fprintf(stream, "\n");
    fprintf(stream, "RID: ");
    sr_deb_print_ip_address(stream, ntohl(lsu->rid));
    fprintf(stream, "\n");
#endif
}

void sr_deb_print_ospf_lsu_list(FILE *stream, struct ospfv2_lsu *array, size_t array_len)
{
#ifdef _DEBUG_
    fprintf(stream, "---OSPF LSU LIST---\n");
    for(size_t i = 0; i < array_len; i++)
    {
        sr_deb_print_ospf_lsu(stream, array + i);
    }
    fprintf(stream, "-------------------\n");
#endif
}

void sr_deb_print_pwospf_graph(FILE *f, struct pwospf_node *g)
{
#ifdef _DEBUG_
    struct pwospf_node *cur_node = g;
    fprintf(f, "---OSPF GRAPH STRUCTURE---\n");
    while(cur_node)
    {
        sr_deb_print_pwospf_node(f, cur_node);
        struct pwospf_edge_list *el = cur_node->edges;
        while(el)
        {
            sr_deb_print_pwospf_edge(f, el->data);
            el = el->next;
        }
        cur_node = cur_node->next;
    }
    fprintf(f, "---END OSPF GRAPH STRUCTURE---\n");
#endif
}

void sr_deb_print_pwospf_node(FILE *f, struct pwospf_node *n)
{
#ifdef _DEBUG_
    fprintf(f, "NODE: { RID = ");
    sr_deb_print_ip_address(f, ntohl(n->rid));
    fprintf(f, ", SENT_SEQ_NUM = ");
    sr_deb_print_bool(f, n->sent_seq_num);
    fprintf(f, ", LAST_SEQ_NUM = %us }\n", n->last_seq_num);
#endif
}

void sr_deb_print_pwospf_edge(FILE *f, struct pwospf_edge *e)
{
#ifdef _DEBUG_
    fprintf(f, "EDGE: { EDGE_SUBNET_MASK = ");
    sr_deb_print_ip_address(f, ntohl(e->edge_subnet.mask));
    fprintf(f, ", EDGE_SUBNET_PREFIX = ");
    sr_deb_print_ip_address(f, ntohl(e->edge_subnet.prefix));
    fprintf(f, ", LAST_HELLO = %li, IS_INTERNAL = ", e->last_hello);
    sr_deb_print_bool(f, e->is_internal);
    fprintf(f, ", EP1_RID = ");
    sr_deb_print_ip_address(f, e->ep1 ? ntohl(e->ep1->rid) : 0);
    fprintf(f, ", EP1_IP = ");
    sr_deb_print_ip_address(f, ntohl(e->ip1));
    fprintf(f, ", EP2_RID = ");
    sr_deb_print_ip_address(f, e->ep2 ? ntohl(e->ep2->rid) : 0);
    fprintf(f, ", EP2_IP = ");
    sr_deb_print_ip_address(f, ntohl(e->ip2));
    fprintf(f, " }\n");
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

void sr_deb_print_mem(FILE *stream, uint8_t *buf, size_t size)
{
#ifdef _DEBUG_
    fprintf(stream, "{");
    for(size_t i = 0; i < size; i++)
    {
        if(i != 0) fprintf(stream, ", ");
        fprintf(stream, "%2.2x", buf[i]);
    }
    fprintf(stream, "}\n");
#endif
}
