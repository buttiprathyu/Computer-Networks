/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_debug.h"
#include "sr_util.h"

#define DEFAULT_TTL 64

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    assert(sr);
} /* -- sr_init -- */

static void handle_arp_request(struct sr_instance *sr, char *iface_name, struct sr_arphdr *hdr, size_t len)
{
    // If someone is requesting our MAC (the dest IP matches our IP),
    // we need to ARP_REPLY.
    struct sr_if *iface = sr_get_interface(sr, iface_name);
    // ARP requests are useful for updating our ARP table, even if they 
    // don't target us, since they give us an (ip, mac) match.
    sr_add_or_update_arp_entry(sr, iface_name, hdr->ar_sip, hdr->ar_sha);
    if(hdr->ar_tip != iface->ip)
    {
        // we don't care if it's not us.
        return;
    }

    // Set the ethernet fields
    struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *)hdr - 1;
    memcpy(eth_hdr->ether_dhost, hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    // Set the arp fields
    hdr->ar_op = htons(ARP_REPLY);
    memcpy(hdr->ar_tha, hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    hdr->ar_tip = hdr->ar_sip;
    hdr->ar_sip = iface->ip;
    sr_deb_print_outgoing(stdout, len + sizeof(struct sr_ethernet_hdr));
    sr_deb_print_packet(stdout, eth_hdr, len + sizeof(struct sr_ethernet_hdr));
    sr_send_packet(sr, (uint8_t *)eth_hdr, len + sizeof(struct sr_ethernet_hdr), iface_name);
}

static void handle_arp_reply(struct sr_instance *sr, char *iface_name, struct sr_arphdr *hdr, size_t len)
{
    sr_add_or_update_arp_entry(sr, iface_name, hdr->ar_sip, hdr->ar_sha);
}

static void handle_arp(struct sr_instance *sr, char *iface_name, struct sr_arphdr *hdr, size_t len)
{
    uint8_t arp_operation = ntohs(hdr->ar_op);
    if(arp_operation == ARP_REQUEST)
    {
        handle_arp_request(sr, iface_name, hdr, len);
    }
    else if(arp_operation == ARP_REPLY)
    {
        handle_arp_reply(sr, iface_name, hdr, len);
    }
    else
    {
        // Don't think we need to handle anything else here.
    }
}

static void send_arp_request(struct sr_instance *sr, char *iface_name, uint32_t ip)
{
    struct sr_if *iface = sr_get_interface(sr, iface_name);
    struct sr_ethernet_hdr *new_packet = (struct sr_ethernet_hdr *)calloc(
        1, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    memset(new_packet->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(
        new_packet->ether_shost,
        iface->addr,
        ETHER_ADDR_LEN
    );
    new_packet->ether_type = htons(ETHERTYPE_ARP);
    struct sr_arphdr *arp_hdr = (struct sr_arphdr *)(new_packet + 1);
    arp_hdr->ar_hrd = htons(ARPHDR_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ARP_REQUEST);
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;
    // arp_hdr->ar_tha is zeroed out from calloc already
    arp_hdr->ar_tip = ip;
    sr_deb_print_outgoing(stdout, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    sr_deb_print_packet(stdout, new_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    sr_send_packet(sr, (uint8_t *)new_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), iface_name);
}

static int handle_icmp(struct sr_instance *sr, char *iface_name, struct icmp_hdr *hdr, size_t len)
{
    if(hdr->type != ICMP_ECHO_REQ_TYPE) return 0;

    hdr->type = ICMP_ECHO_REPLY_TYPE;
    // all 0's uses the IP header's checksum
    hdr->checksum = 0;
    struct ip *ip_hdr = (struct ip *)((uint8_t *)hdr - sizeof(struct ip));
    ip_hdr->ip_ttl = DEFAULT_TTL;
    uint32_t tmp = ip_hdr->ip_src.s_addr;
    ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
    ip_hdr->ip_dst.s_addr = tmp;
    ip_hdr->ip_sum = sr_util_ip_checksum((uint16_t *)ip_hdr, sizeof(struct ip) / 2);
    return 1;
}

// Length here is excluding the ethernet header, which was already stripped off.
static void handle_ip(struct sr_instance *sr, char *iface_name, struct ip *hdr, size_t len)
{


    if(hdr->ip_v != 4) return;
    // checksum
    if(sr_util_ip_checksum((uint16_t *)hdr, sizeof(struct ip) / 2)) return;
    hdr->ip_ttl--;
    if(!hdr->ip_ttl) return;

    // check if we're the dest. we need to handle ping requests.
    // Since we have multiple interfaces, we have multiple IP addresses.
    int dst_is_us = 0;
    for(struct sr_if *cur_iface = sr->if_list; cur_iface != NULL; cur_iface = cur_iface->next)
    {
        if(hdr->ip_dst.s_addr == cur_iface->ip) dst_is_us = 1;
    }
    if(dst_is_us)
    {
        if(hdr->ip_p == IPPROTO_ICMP)
        {
            // modifies hdr so that its destination and source are swapped.
            // Also sets the ICMP type to echo reply.
            // Result is 1 on successful handling, 0 otherwise.
            if(!handle_icmp(sr, iface_name, (struct icmp_hdr *)(hdr + 1), len - sizeof(struct ip))) return;
        }
        else return;
    }

    hdr->ip_sum = 0x0000;
    hdr->ip_sum = htons(sr_util_ip_checksum((uint16_t *)hdr, sizeof(struct ip) / 2));

    // lookup in routing table
    struct sr_rt *default_next = NULL;
    struct sr_rt *match = NULL;
    struct sr_rt *cur = sr->routing_table;
    while(cur)
    {
        // FIND OUT NEXT HOP
        if(cur->dest.s_addr == 0) default_next = cur;

        if((hdr->ip_dst.s_addr & cur->mask.s_addr) == cur->dest.s_addr)
        {
            match = cur;
        }

        cur = cur->next;
    }
    if(!match)
    {
        match = default_next;
    }
    uint32_t next_ip = 0;
    if(match->gw.s_addr == 0)
    {
        next_ip = hdr->ip_dst.s_addr;
    } 
    else
    {
        next_ip = match->gw.s_addr;
    }
    struct sr_if *matched_iface = sr_get_interface(sr, match->interface);

    // find out if we know the next hop's mac
    struct sr_ethernet_hdr *ether_hdr = (struct sr_ethernet_hdr *)hdr - 1;
    memcpy(ether_hdr->ether_shost, matched_iface->addr, ETHER_ADDR_LEN);
    uint8_t next_mac[6];
    if(!sr_get_mac_from_ip(sr, match->interface, next_ip, next_mac))
    {
        send_arp_request(sr, matched_iface->name, next_ip);
        sr_cache_packet_until_arp(sr, matched_iface->name, next_ip, (uint8_t *)ether_hdr, len + sizeof(struct sr_ethernet_hdr));
    }
    else
    {
        memcpy(ether_hdr->ether_dhost, next_mac, ETHER_ADDR_LEN);
        sr_deb_print_outgoing(stdout, len + sizeof(struct sr_ethernet_hdr));
        sr_deb_print_packet(stdout, ether_hdr, len);
        sr_send_packet(sr, (uint8_t *)ether_hdr, len + sizeof(struct sr_ethernet_hdr), matched_iface->name);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    sr_deb_print_incoming(stdout, len);
    struct sr_ethernet_hdr *h_eth = (struct sr_ethernet_hdr *)packet;
    sr_deb_print_packet(stdout, h_eth, len);

    uint16_t ether_type = ntohs(h_eth->ether_type);
    if(ether_type == ETHERTYPE_ARP)
    {
        handle_arp(
            sr,
            interface,
            (struct sr_arphdr *)(h_eth + 1),
            len - sizeof(struct sr_ethernet_hdr));
    }
    else if(ether_type == ETHERTYPE_IP)
    {
        handle_ip(sr, interface, (struct ip *)(h_eth + 1), len - sizeof(struct sr_ethernet_hdr));
    }
    else
    {
        printf("Unknown ether type: %hu\n", h_eth->ether_type);
        return;
    }


}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
