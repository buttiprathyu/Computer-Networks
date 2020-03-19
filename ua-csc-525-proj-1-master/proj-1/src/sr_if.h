/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#include <stddef.h>

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif


#define SR_IFACE_NAMELEN 32

// Project requirement: stale in less than 15 seconds.
#define STALE_TIME 14

struct sr_instance;

// Need a separate table of maps from 
// ip address <-> mac address
// for each ethernet interface
struct arp_entry
{
    uint32_t ip;
    uint8_t mac[6];
    struct arp_entry *next;
    __time_t timestamp;
};

// Essentially, we want this structure to hold a nearly completely constructed packet. Also, we will
// store this in a linked list just like the arp_list to make things easier to program.
// When entries are constructed, we can just allocate this size and the correct size for the packet
// contiguously and point packet right after the struct saved_packet.
struct saved_packet
{
    struct saved_packet *next;
    uint32_t next_hop;
    struct sr_ethernet_hdr *packet;
    size_t packet_len;
};

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * Node in the interface list for each router
 *
 * -------------------------------------------------------------------------- */

struct sr_if
{
    char name[SR_IFACE_NAMELEN];
    unsigned char addr[6];
    uint32_t ip;
    uint32_t speed;
    // Each ethernet interface has a collection of connected devices. 
    // We need an ARP entry for each device we need to communicate 
    // directly to, i.e., each next-hop to resolve MAC address from 
    // the IP address that's found in the routing table.
    struct arp_entry *arp_list;
    struct saved_packet *saved_packet_list;
    struct sr_if* next;
};

struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name);
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t ip_nbo);
void sr_print_if_list(struct sr_instance*);
void sr_print_if(struct sr_if*);

void sr_add_or_update_arp_entry(
    struct sr_instance* instance,
    const char* iface_name,
    uint32_t ip,
    uint8_t mac[]);
// return value indicates success (1) or error (0).
int sr_get_mac_from_ip(
    struct sr_instance* instance,
    const char* iface_name,
    uint32_t ip_address, 
    uint8_t mac_retval[]);
void sr_print_arp_list(struct sr_instance *sr, const char *iface_name);

// Copies the data at packet and holds onto it until the an arp entry is added for
// that IP address.
// The arp cache will not be checked until it receives an arp_reply. Thus, figure
// out if we already know the mac (sr_get_mac_from_ip), then only cache the
// packet if we don't.
// The only field that is assumed to be in an uninitialized state is
// (struct sr_ethernet_hdr *)packet->ether_dhost.
// All other fields should be properly initialized.
void sr_cache_packet_until_arp(
        struct sr_instance *instance,
        const char *iface_name,
        uint32_t next_hop,
        uint8_t *packet, // borrowed
        size_t pack_size
);

#endif /* --  sr_INTERFACE_H -- */
