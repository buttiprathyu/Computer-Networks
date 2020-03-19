/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>

#include "sr_if.h"
#include "pwospf_protocol.h"
#include "sr_pwospf_graph.h"

/* forward declare */
struct sr_instance;

// A list of edges representing adjacent subnets and corresponding
// interfaces.
struct pwospf_edge_iface_map
{
    struct pwospf_edge *e;
    char iface_name[SR_IFACE_NAMELEN];
    struct pwospf_edge_iface_list *next;
};

struct pwospf_subsys
{
    __time_t my_last_hello;
    __time_t my_last_lsu;

    // store our own rid in pwospf_graph. The first node entry in "graph"
    // represents ourself.
    struct pwospf_node *graph;

    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

int pwospf_init(struct sr_instance *sr);

void pwospf_handle_packet(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr, size_t remaining_len, uint32_t ip);
void pwospf_handle_hello(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr, uint32_t ip);
void pwospf_handle_lsu(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr);


#endif /* SR_PWOSPF_H */
