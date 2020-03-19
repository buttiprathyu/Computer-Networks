/*-----------------------------------------------------------------------------
 * file:  sr_inface.
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handling interfaces
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>

#ifdef _DARWIN_
#include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_debug.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_util.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_get_interface
 * Scope: Global
 *
 * Given an interface name return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(!strncmp(if_walker->name,name,SR_IFACE_NAMELEN))
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface -- */

/*--------------------------------------------------------------------- 
 * Method: sr_add_interface(..)
 * Scope: Global
 *
 * Add and interface to the router's list
 *
 *---------------------------------------------------------------------*/

void sr_add_interface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->if_list == 0)
    {
        sr->if_list = (struct sr_if*)malloc(sizeof(struct sr_if));
        assert(sr->if_list);
        sr->if_list->arp_list = NULL;
        sr->if_list->saved_packet_list = NULL;
        sr->if_list->next = NULL;
        strncpy(sr->if_list->name,name,SR_IFACE_NAMELEN);
        return;
    }

    /* -- find the end of the list -- */
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    if_walker->next = (struct sr_if*)malloc(sizeof(struct sr_if));
    assert(if_walker->next);
    if_walker = if_walker->next;
    if_walker->arp_list = NULL;
    if_walker->saved_packet_list = NULL;
    if_walker->next = NULL;
    strncpy(if_walker->name,name,SR_IFACE_NAMELEN);
} /* -- sr_add_interface -- */ 

/*--------------------------------------------------------------------- 
 * Method: sr_sat_ether_addr(..)
 * Scope: Global
 *
 * set the ethernet address of the LAST interface in the interface list 
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_addr(struct sr_instance* sr, const unsigned char* addr)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    memcpy(if_walker->addr,addr,ETHER_ADDR_LEN);

} /* -- sr_set_ether_addr -- */

/*--------------------------------------------------------------------- 
 * Method: sr_set_ether_ip(..)
 * Scope: Global
 *
 * set the IP address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_ip(struct sr_instance* sr, uint32_t ip_nbo)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    if_walker->ip = ip_nbo;

} /* -- sr_set_ether_ip -- */

/*--------------------------------------------------------------------- 
 * Method: sr_print_if_list(..)
 * Scope: Global
 *
 * print out the list of interfaces to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if_list(struct sr_instance* sr)
{
    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
    {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;
    
    sr_print_if(if_walker);
    while(if_walker->next)
    {
        if_walker = if_walker->next; 
        sr_print_if(if_walker);
    }

} /* -- sr_print_if_list -- */

/*--------------------------------------------------------------------- 
 * Method: sr_print_if(..)
 * Scope: Global
 *
 * print out a single interface to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if(struct sr_if* iface)
{
    struct in_addr ip_addr;

    /* -- REQUIRES --*/
    assert(iface);
    assert(iface->name);

    ip_addr.s_addr = iface->ip;

    Debug("%s\tHWaddr",iface->name);
    DebugMAC(iface->addr);
    Debug("\n");
    Debug("\tinet addr %s\n",inet_ntoa(ip_addr));
} /* -- sr_print_if -- */

static struct arp_entry *arp_entry_new(uint32_t ip, uint8_t mac[])
{
    struct arp_entry *r = (struct arp_entry *)calloc(1, sizeof(struct arp_entry));
    if(!r) return r;
    r->ip = ip;
    memcpy(r->mac, mac, sizeof(r->mac));
    r->next = NULL;
    r->timestamp = sr_util_monotonic_secs();
    return r;
}

void sr_check_can_send_cached_packets(
        struct sr_instance *instance,
        const char *iface_name
);

// Side-effect: sends all saved packets that it can.
void sr_add_or_update_arp_entry(
    struct sr_instance* instance,
    const char* iface_name,
    uint32_t ip,
    uint8_t mac[])
{
    struct sr_if *iface = sr_get_interface(instance, iface_name);
    if(!iface) return;
    // Need access to the previous node's next pointer to cause it to 
    // point to a new node if we have to add a new entry.
    // This is also handy because we can handle empty list 
    // the same exact way.
    unsigned updated = 0;
    struct arp_entry **prev_next_ptr = &(iface->arp_list);
    struct arp_entry *cur = iface->arp_list;
    while(cur)
    {
        if(memcmp(cur->mac, mac, ETHER_ADDR_LEN) == 0)
        {
            cur->ip = ip;
            cur->timestamp = sr_util_monotonic_secs();
            sr_print_arp_list(instance, iface_name);
            updated = 1;
        }
        if(cur->timestamp + STALE_TIME <= sr_util_monotonic_secs())
        {
            *prev_next_ptr = cur->next;
            struct arp_entry *tmp = cur;
            cur = tmp->next;
            free(tmp);
        }
        else
        {
            prev_next_ptr = &(cur->next);
            cur = cur->next;
        }
    }
    // cur == NULL, that is, we're at the end of the list with no
    // matches.
    if(!updated)
        *prev_next_ptr = arp_entry_new(ip, mac);
    sr_check_can_send_cached_packets(instance, iface_name);
    sr_print_arp_list(instance, iface_name);
}


int sr_get_mac_from_ip(
    struct sr_instance* instance,
    const char* iface_name,
    uint32_t ip_address, 
    uint8_t mac_retval[])
{
    struct sr_if *iface = sr_get_interface(instance, iface_name);
    if(!iface) return 0;
    struct arp_entry **prev_next_ptr = &(iface->arp_list);
    struct arp_entry *cur = iface->arp_list;
    while(cur)
    {
        if((cur->ip == ip_address) && (cur->timestamp + STALE_TIME > sr_util_monotonic_secs()))
        {
            memcpy(mac_retval, cur->mac, sizeof(cur->mac));
            return 1;
        }
        if(cur->timestamp + STALE_TIME <= sr_util_monotonic_secs())
        {
            *prev_next_ptr = cur->next;
            struct arp_entry *tmp = cur;
            cur = tmp->next;
            free(tmp);
        }
        else
        {
            prev_next_ptr = &(cur->next);
            cur = cur->next;
        }
    }
    return 0;
}

void sr_print_arp_list(struct sr_instance *sr, const char *iface_name)
{
#ifdef _DEBUG_
    struct sr_if *iface = sr_get_interface(sr, iface_name);
    if(!iface) return;
    struct arp_entry *aent = iface->arp_list;
    while(aent)
    {
        printf("IP: ");
        sr_deb_print_ip_address(stdout, aent->ip);
        printf(", MAC: ");
        sr_deb_print_mac_address(stdout, aent->mac);
        Debug("\n");
        aent = aent->next;
    }
#endif
}

static struct saved_packet *new_saved_packet(
        uint32_t next_hop,
        uint8_t *pack_buff, // borrowed
        size_t pack_size)
{
    struct saved_packet *r = (struct saved_packet *)calloc(1, sizeof(struct saved_packet) + pack_size);
    if(!r) return r;
    r->next = NULL;
    r->next_hop = next_hop;
    r->packet = (struct sr_ethernet_hdr *)(r + 1);
    r->packet_len = pack_size;
    memcpy(r->packet, pack_buff, pack_size);
    return r;
}

void sr_cache_packet_until_arp(
        struct sr_instance *instance,
        const char *iface_name,
        uint32_t next_hop,
        uint8_t *packet, // borrowed
        size_t pack_size
)
{
    struct sr_if *iface = sr_get_interface(instance, iface_name);
    struct saved_packet **prev_next_ptr = &(iface->saved_packet_list);
    while(*prev_next_ptr)
    {
        prev_next_ptr = &((*prev_next_ptr)->next);
    }
    *prev_next_ptr = new_saved_packet(next_hop, packet, pack_size);
}

// Basically iterates through each cached packet, checks if an entry exists in the arp cache
// that matches the IP address of the packet, then calls sr_send_packet
void sr_check_can_send_cached_packets(
        struct sr_instance *instance,
        const char *iface_name
)
{
    struct sr_if *iface = sr_get_interface(instance, iface_name);
    struct saved_packet **prev_next_ptr = &(iface->saved_packet_list);
    struct saved_packet *cur = iface->saved_packet_list;
    while(cur)
    {
        uint32_t next_hop = cur->next_hop;
        uint8_t mac_dst[ETHER_ADDR_LEN];
        if(sr_get_mac_from_ip(instance, iface_name, next_hop, mac_dst))
        {
            memcpy(cur->packet->ether_dhost, mac_dst, ETHER_ADDR_LEN);
            sr_deb_print_outgoing(stdout, cur->packet_len);
            sr_deb_print_packet(stdout, cur->packet, cur->packet_len);
            sr_send_packet(instance, (uint8_t *)cur->packet, cur->packet_len, iface_name);

            *prev_next_ptr = cur->next;
            struct saved_packet *tmp = cur;
            cur = tmp->next;
            free(tmp);
        }
        else
        {
            prev_next_ptr = &(cur->next);
            cur = cur->next;
        }
    }
}
