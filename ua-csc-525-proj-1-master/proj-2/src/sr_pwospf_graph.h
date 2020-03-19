#ifndef SR_PWOSPF_GRAPH_H
#define SR_PWOSPF_GRAPH_H

#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>

#include "sr_if.h"

struct pwospf_edge_list;

// The first bit of data for a "PWOSPF interface."
// See PWOSPF specification for more info.
struct pwospf_subnet
{
    uint32_t prefix;
    uint32_t mask;
};

enum pwospf_link_type
{
    PNT_ADJACENT,
    PNT_REMOTE
};

// Data required for a PWOSPF router.
// See PWOSPF specification for more info.
// Also includes a list of edges representing
// interfaces in the PWOSPF specification.
struct pwospf_node
{
    uint32_t rid;

    // hello messages don't have a sequence number.
    // we need to make sure, when we check sequence
    // numbers for a LSU, if no LSUs were sent yet,
    // we don't invalidate the LSU just because the
    // initial contents of the memory at last_seq_num
    // was some value. (0 if we assume calloc.)
    bool sent_seq_num;
    uint16_t last_seq_num;

    bool visited; // used in the searching algorithm.

    struct pwospf_edge_list *edges;
    struct pwospf_node *next;
};

// Each edge represents either (1) a connection to another internal router or
// (2) an external, i.e., gateway edge.
// Conceptually, this is equivalent to the "PWOSPF interface" abstraction.
struct pwospf_edge
{
    struct pwospf_subnet edge_subnet;

    __time_t last_hello;

    // whether this edge was at any point connected between ourself and
    // another OSPF router. If this is the case, we need to differentiate
    // it between external connections. Namely, if this was internal at
    // any point, but its other endpoint is no longer connected to an OSPF
    // router (either ep1 or ep2 is NULL), we need to exclude it from LSUs.
    bool is_internal;

    // If this is an adjacent edge, it has an associated interface. This
    // is useful for excluding the incoming interface when we determine
    // the next hop.
    // There should be a 1-1 correspondence between adjacent links and
    // adjacent interfaces.
    struct sr_if *interface;

    struct pwospf_node *ep1;
    uint32_t ip1;
    struct pwospf_node *ep2;
    uint32_t ip2;
};

// used by nodes to walk the list of edges.
// since edges contain data, it is not as simple
// as holding "next" in the edge struct.
// this is because edges can appear in the data-structure
// twice, once for each connected, internal node (router).
struct pwospf_edge_list
{
    struct pwospf_edge *data;
    struct pwospf_edge_list *next;
};

enum pwospf_graph_add_or_update_result
{
    PGAOUR_ADD,
    PGAOUR_UPDATE,
    PGAOUR_ERR
};

bool pwospf_subnet_eq(struct pwospf_subnet *a, struct pwospf_subnet *b);

void pwospf_node_init(struct pwospf_node *g, uint32_t rid, uint16_t *seq_num);

struct pwospf_node *pwospf_graph_get_node(struct pwospf_node *g, uint32_t rid);
struct pwospf_edge *pwospf_graph_get_edge(struct pwospf_node *g, struct pwospf_subnet *subnet);

enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_node(struct pwospf_node *g, uint32_t rid, uint16_t *seq_num);
enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_edge_from_lsu(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet);
enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_edge_from_hello(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet, uint32_t ip);
struct pwospf_edge *pwospf_graph_add_edge_initial(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet, uint32_t ip, struct sr_if *interface);

void pwospf_graph_remove_endpoint(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet);

// returns whether any edges were pruned.
bool pwospf_graph_prune_neighbors(struct pwospf_node *g);

// this is going to walk the graph and change visited
// so this needs to reset visited back to false at the end.
// ensure next hop is not the prev subnet link.
struct pwospf_edge *pwospf_graph_next_hop(struct pwospf_node *g, uint32_t ip, struct pwospf_subnet *prev_subnet);

struct pwospf_subnet *pwospf_graph_get_subnet_from_iface(struct pwospf_node *g, char *iface_name);

#endif
