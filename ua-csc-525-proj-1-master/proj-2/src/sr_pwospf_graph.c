#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <arpa/inet.h>

#include "sr_pwospf_graph.h"
#include "sr_util.h"
#include "pwospf_protocol.h"
#include "sr_debug.h"

static struct pwospf_edge *find_next_link_helper(struct pwospf_node *cur, struct pwospf_subnet *subnet)
{
    assert(cur);
    assert(subnet);
    if(cur->visited) return NULL;
#ifdef _DEBUG_
    printf("visting node: \n");
#endif
    sr_deb_print_pwospf_node(stdout, cur);
    cur->visited = true;
    struct pwospf_edge_list *cur_edge = cur->edges;
    while(cur_edge)
    {
        struct pwospf_edge *cur_edge_data = cur_edge->data;
#ifdef _DEBUG_
        printf("visiting edge: \n");
#endif
        sr_deb_print_pwospf_edge(stdout, cur_edge_data);
        struct pwospf_node *other = NULL;
        if(cur_edge_data->ep1 == cur)
        {
            other = cur_edge_data->ep2;
        }
        else
        {
            other = cur_edge_data->ep1;
        }
        if(!other)
        {
            // if null (gateway)
            // check if this edge leads to the subnet given
            if(pwospf_subnet_eq(subnet, &(cur_edge_data->edge_subnet)))
            {
#ifdef _DEBUG_
                printf("found a gateway edge: \n");
#endif
                sr_deb_print_pwospf_edge(stdout, cur_edge_data);
                return cur_edge_data;
            }
        }
        else
        {
            // if not null (internal)
            if(find_next_link_helper(other, subnet))
            {
#ifdef _DEBUG_
                printf("found a helper edge: \n");
#endif
                sr_deb_print_pwospf_edge(stdout, cur_edge_data);
                return cur_edge_data;
            }
        }

        cur_edge = cur_edge->next;
    }
    // could not reach the given subnet
    return NULL;
}

// the node passed to this function should represent the root node (first node in the list).
static struct pwospf_edge *find_next_link(struct pwospf_node *cur, struct pwospf_subnet *subnet, struct pwospf_subnet *prev_subnet)
{
#ifdef _DEBUG_
    printf("=====ATTEMPTING TO FIND NEXT LINK=====\n");
    printf("for subnet: (");
    sr_deb_print_ip_address(stdout, ntohl(subnet->mask));
    printf(", ");
    sr_deb_print_ip_address(stdout, ntohl(subnet->prefix));
    printf(")\n");
#endif
    // visit the previous subnet immediately
    struct pwospf_edge_list *el = cur->edges;
    while(el)
    {
        if(el->data->is_internal
                && pwospf_subnet_eq(&(el->data->edge_subnet), prev_subnet))
        {
            if(el->data->ep1 && el->data->ep1->rid != cur->rid)
            {
                el->data->ep1->visited = true;
            }
            else if(el->data->ep2 && el->data->ep2->rid != cur->rid)
            {
                el->data->ep2->visited = true;
            }
        }
        el = el->next;
    }
    struct pwospf_edge *result = find_next_link_helper(cur, subnet);

    // reset the visited flags
    while(cur)
    {
        cur->visited = false;
        cur = cur->next;
    }
#ifdef _DEBUG_
    printf("======================================\n");
#endif
    return result;
}

static void set_node_data(struct pwospf_node *n, uint32_t rid, uint16_t *seq_num)
{
    assert(n);
    n->rid = rid;
    if(seq_num)
    {
        n->last_seq_num = *seq_num;
        n->sent_seq_num = true;
    }
}

// side-effect: adds this edge to the
// announcing router's edge list if one of
// this edge's pointers was set (new connection)
static void set_edge_data(struct pwospf_edge *e, struct pwospf_subnet *subnet, struct pwospf_node *announcing_router)
{
    assert(e);
    assert(subnet);
    assert(announcing_router);
    memcpy(&(e->edge_subnet), subnet, sizeof(struct pwospf_subnet));

    // find a good endpoint pointer to store a reference to the announcing router.
    // assert we never run into a situation where both endpoints are
    // set and neither is the announcing router.
    struct pwospf_node **endpoints[2];
    endpoints[0] = &(e->ep1);
    endpoints[1] = &(e->ep2);
    for(int i = 0; i < 2; i++)
    {
        struct pwospf_node **cur = endpoints[i];
        struct pwospf_node *other = *endpoints[(i + 1) % 2];

        /*
                                | cur is null      | cur is not router         | cur is router
                                ---------------------------------------------------------------
            other is null       | set cur & ret    | set other (iterate) & ret | return
            other is not router | set cur & ret    | error                     | return
            other is router     | return (iterate) | return                    | error
        */

        if(!(*cur))
        {
            // found a slot in cur
            if(other && (other == announcing_router))
            {
                // make sure the other is not the announcing router
                return;
            }
            else
            {
                // when we connect a node to a subnet,
                // ensure we add it to the node's edge list.
                struct pwospf_edge_list *new_edge_list = (struct pwospf_edge_list *)calloc(1, sizeof(struct pwospf_edge_list));
                new_edge_list->data = e;
                new_edge_list->next = announcing_router->edges;
                announcing_router->edges = new_edge_list;
                *cur = announcing_router;
                return;
            }
        }
        else if(*cur == announcing_router)
        {
            // cur is already set to be the announcing router
            return;
        }
    }
    assert(1);
}

bool pwospf_subnet_eq(struct pwospf_subnet *a, struct pwospf_subnet *b)
{
    assert(a);
    assert(b);
    return (a->mask == b->mask) && (a->prefix == b->prefix);
}

void pwospf_node_init(struct pwospf_node *g, uint32_t rid, uint16_t *seq_num)
{
    set_node_data(g, rid, seq_num);
    if(!seq_num) { g->sent_seq_num = false; }
    g->visited = false;
    g->edges = NULL;
    g->next = NULL;
}

struct pwospf_node *pwospf_graph_get_node(struct pwospf_node *g, uint32_t rid)
{
    while(g)
    {
        if(g->rid == rid) return g;
        g = g->next;
    }
    return NULL;
}

struct pwospf_edge *pwospf_graph_get_edge(struct pwospf_node *g, struct pwospf_subnet *subnet)
{
    while(g)
    {
        struct pwospf_edge_list *cur_edge_list = g->edges;
        // we will end up walking each internal edge twice.
        // not a huge performance hit, though.
        while(cur_edge_list)
        {
            if(pwospf_subnet_eq(&(cur_edge_list->data->edge_subnet), subnet)) return cur_edge_list->data;
            cur_edge_list = cur_edge_list->next;
        }
        g = g->next;
    }
    return NULL;
}

enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_node(struct pwospf_node *g, uint32_t rid, uint16_t *seq_num)
{
    struct pwospf_node **prev_ptr = &g;
    while(*prev_ptr)
    {
        // found one
        if((*prev_ptr)->rid == rid)
        {
            set_node_data(*prev_ptr, rid, seq_num);
            return PGAOUR_UPDATE;
        }
        prev_ptr = &((*prev_ptr)->next);
    }
    // didn't find any
    *prev_ptr = (struct pwospf_node *)calloc(1, sizeof(struct pwospf_node));
    pwospf_node_init(*prev_ptr, rid, seq_num);
    return PGAOUR_ADD;
}

enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_edge_from_lsu(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet)
{
    assert(g);
    assert(subnet);
    struct pwospf_node *router = pwospf_graph_get_node(g, rid);
    assert(router);

    struct pwospf_edge *existing_edge;
    if((existing_edge = pwospf_graph_get_edge(g, subnet)))
    {
        // update
        set_edge_data(existing_edge, subnet, router);
        return PGAOUR_UPDATE;
    }
    else
    {
        // add new
        struct pwospf_edge *new_edge = (struct pwospf_edge *)calloc(1, sizeof(struct pwospf_edge));
        set_edge_data(new_edge, subnet, router);
        return PGAOUR_ADD;
    }
}

enum pwospf_graph_add_or_update_result pwospf_graph_add_or_update_edge_from_hello(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet, uint32_t ip)
{
    enum pwospf_graph_add_or_update_result r = pwospf_graph_add_or_update_edge_from_lsu(g, rid, subnet);
    struct pwospf_edge *e = pwospf_graph_get_edge(g, subnet);
    // we should be guaranteed to have ep1 and ep2 be non-null at this point
    assert(e->ep1 && e->ep2);
    if(e->ep1->rid == rid)
    {
        e->ip1 = ip;
    }
    else
    {
        e->ip2 = ip;
    }
    e->last_hello = sr_util_monotonic_secs();
    return r;
}

struct pwospf_edge *pwospf_graph_add_edge_initial(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet, uint32_t ip, struct sr_if *interface)
{
    struct pwospf_edge *new_edge = (struct pwospf_edge *)calloc(1, sizeof(struct pwospf_edge));
    set_edge_data(new_edge, subnet, g);
    new_edge->interface = interface;
    if(new_edge->ep1 == g)
    {
        new_edge->ip1 = ip;
    }
    else
    {
        new_edge->ip2 = ip;
    }
    return new_edge;
}

void pwospf_graph_remove_endpoint(struct pwospf_node *g, uint32_t rid, struct pwospf_subnet *subnet)
{
    // need to remove this edge's endpoint based on the rid.
    // if both endpoints are removed, we need to free the edge.

    struct pwospf_edge *e = pwospf_graph_get_edge(g, subnet);
    struct pwospf_node *n;
    if(e->ep1 && e->ep1->rid == rid)
    {
        n = e->ep1;
        e->ep1 = NULL;
    }
    else
    {
        n = e->ep2;
        e->ep2 = NULL;
    }
    struct pwospf_edge_list **edge_list = &(n->edges);
    while(*edge_list)
    {
        if(pwospf_subnet_eq(
                &((*edge_list)->data->edge_subnet),
                subnet))
        {
            struct pwospf_edge_list *removed = *edge_list;
            *edge_list = (*edge_list)->next;
            free(removed);
            break;
        }
        edge_list = &((*edge_list)->next);
    }
    if(e->ep1 == NULL && e->ep2 == NULL) free(e);
}

bool pwospf_graph_prune_neighbors(struct pwospf_node *g)
{
    bool result = false;
    __time_t cur_time = sr_util_monotonic_secs();
    struct pwospf_edge_list *cur_el = g->edges;
    while(cur_el)
    {
        if(cur_el->data->last_hello < (cur_time - OSPF_NEIGHBOR_TIMEOUT) && cur_el->data->ep1 && cur_el->data->ep2)
        {
            pwospf_graph_remove_endpoint(
                    g,
                    // remove the other endpoint
                    (cur_el->data->ep1->rid == g->rid) ? cur_el->data->ep2->rid : cur_el->data->ep1->rid,
                    &(cur_el->data->edge_subnet)
            );
            result = true;
        }
        cur_el = cur_el->next;
    }
    return result;
}

struct pwospf_edge *pwospf_graph_next_hop(struct pwospf_node *g, uint32_t ip, struct pwospf_subnet *prev_subnet)
{
    // this is kind of a dumb, brute-force way, to try every prefix with longest first,
    // but the topology is so small for this project that a graph search over
    // 3 nodes and 6 edges for 32 bits doesn't really cause a performance penalty.
    struct pwospf_subnet longest_subnet;
    longest_subnet.mask = 0xffffffff;
    longest_subnet.prefix = ip;
    struct pwospf_edge *result = NULL;
    while(!(result = find_next_link(g, &longest_subnet, prev_subnet)) && (longest_subnet.mask != 0))
    {
        longest_subnet.mask = htonl(ntohl(longest_subnet.mask) << 1);
        longest_subnet.prefix = ip & longest_subnet.mask;
    }
    return result;
}

struct pwospf_subnet *pwospf_graph_get_subnet_from_iface(struct pwospf_node *g, char *iface_name)
{
    struct pwospf_edge_list *el = g->edges;
    while(el)
    {
        if(!strcmp(iface_name, el->data->interface->name))
        {
            // ! indicates equal
            return &(el->data->edge_subnet);
        }
        el = el->next;
    }
    return NULL;
}
