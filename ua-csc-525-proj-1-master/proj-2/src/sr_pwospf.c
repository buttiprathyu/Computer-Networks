/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_util.h"
#include "sr_debug.h"
#include "sr_rt.h"
#include "sr_router.h"


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    pthread_mutex_lock(&(sr->ospf_subsys->lock));

    // intitialize all interfaces' static routes to false
    struct sr_if *interface = sr->if_list;
    while(interface)
    {
        interface->static_route = false;
        interface = interface->next;
    }


    /* -- handle subsystem initialization here! -- */
    sr->ospf_subsys->my_last_hello = sr_util_monotonic_secs();
    sr->ospf_subsys->my_last_lsu = sr_util_monotonic_secs();

    // add ourself to the graph as the root node (first in the list)
    sr->ospf_subsys->graph = (struct pwospf_node *)calloc(1, sizeof(struct pwospf_node));
    // init our sequence number to 0.
    uint16_t seq_num = 0;
    pwospf_node_init(sr->ospf_subsys->graph, sr->if_list->ip, &seq_num);

    // add each static route as an edge
    struct sr_rt *rt = sr->routing_table;
    while(rt)
    {
        struct pwospf_subnet subnet;
        subnet.mask = rt->mask.s_addr;
        subnet.prefix = rt->dest.s_addr & subnet.mask;
        interface = sr_get_interface(sr, rt->interface);
        struct pwospf_edge *e = pwospf_graph_add_edge_initial(sr->ospf_subsys->graph, sr->if_list->ip, &subnet, interface->ip, interface);
        if(e->ep1)
        {
            e->ip2 = rt->gw.s_addr;
        }
        else
        {
            e->ip1 = rt->gw.s_addr;
        }
        interface->static_route = true;
        rt = rt->next;
    }

    // add each interface as an edge if no static route was already set for that
    // interface
    interface = sr->if_list;
    while(interface)
    {
        if(!interface->static_route)
        {
            struct pwospf_subnet subnet;
            subnet.mask = interface->mask;
            subnet.prefix = interface->ip & subnet.mask;
            if(!pwospf_graph_get_edge(sr->ospf_subsys->graph, &subnet))
            {
                pwospf_graph_add_edge_initial(sr->ospf_subsys->graph, sr->if_list->ip, &subnet, interface->ip, interface);
            }
        }
        interface = interface->next;
    }

    sr_deb_print_pwospf_graph(stdout, sr->ospf_subsys->graph);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

    pthread_mutex_unlock(&(sr->ospf_subsys->lock));

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

static void send_hello(struct sr_instance *sr, struct sr_if *interface)
{
    struct ospfv2_hello_hdr_complete hello_hdr;

    memset(&(hello_hdr.eth.ether_dhost), 0xFF, ETHER_ADDR_LEN);
    memcpy(&(hello_hdr.eth.ether_shost), interface->addr, ETHER_ADDR_LEN);
    hello_hdr.eth.ether_type = htons(ETHERTYPE_IP);

    hello_hdr.ip_hdr.ip_hl = 5;
    hello_hdr.ip_hdr.ip_v = 4;
    hello_hdr.ip_hdr.ip_tos = 0;
    hello_hdr.ip_hdr.ip_len = htons(sizeof(hello_hdr) - sizeof(struct sr_ethernet_hdr));
    hello_hdr.ip_hdr.ip_id = 0;
    hello_hdr.ip_hdr.ip_off = 0;
    hello_hdr.ip_hdr.ip_ttl = 0xFF;
    hello_hdr.ip_hdr.ip_p = IPPROTO_OSPF;
    hello_hdr.ip_hdr.ip_sum = 0;
    hello_hdr.ip_hdr.ip_src.s_addr = interface->ip;
    hello_hdr.ip_hdr.ip_dst.s_addr = htonl(OSPF_AllSPFRouters);
    hello_hdr.ip_hdr.ip_sum = sr_util_ip_checksum((void *)&(hello_hdr.ip_hdr), sizeof(struct ip));

    hello_hdr.pwospf_shared.version = OSPF_V2;
    hello_hdr.pwospf_shared.type = OSPF_TYPE_HELLO;
    hello_hdr.pwospf_shared.len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    hello_hdr.pwospf_shared.rid = sr->ospf_subsys->graph->rid;
    hello_hdr.pwospf_shared.aid = htonl(OSPF_AREA_ID);
    hello_hdr.pwospf_shared.autype = 0;
    hello_hdr.pwospf_shared.audata = 0;

    hello_hdr.pwospf_hello.nmask = interface->mask;
    hello_hdr.pwospf_hello.helloint = htons(OSPF_DEFAULT_LSUINT);
    hello_hdr.pwospf_hello.padding = 0;

    hello_hdr.pwospf_shared.csum = sr_util_ip_checksum(
            // we just want a checksum of the OSPF header
            (void *)&(hello_hdr.pwospf_shared),
            // and the corresponding size
            sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));

    sr_deb_print_outgoing(stdout, sizeof(hello_hdr));
    sr_deb_print_packet(stdout, (struct sr_ethernet_hdr *)&hello_hdr, sizeof(hello_hdr));
    sr_send_packet(sr, (uint8_t *)&hello_hdr, sizeof(hello_hdr), interface->name);
}


static void pwospf_send_hello_all(struct sr_instance *sr)
{
    for(struct sr_if *cur_if = sr->if_list; cur_if != NULL; cur_if = cur_if->next)
    {
        send_hello(sr, cur_if);
    }
}

// allocates a new LSU from this router's adjacent edges.
// the calling function must take ownership of this new memory.
// some of the fields, namely for the IP and Ethernet headers,
// will still need to be populated based on the interface.
// the graph is locked throughout this function
static void generate_lsu(struct sr_instance *sr, struct ospfv2_lsu_hdr_complete **out_lsu_hdr, size_t *out_lsu_hdr_len)
{
    size_t num_edges = 0;
    struct pwospf_edge_list *el = sr->ospf_subsys->graph->edges;
    while(el)
    {
        // external edge
        if(!(el->data->is_internal)) num_edges++;
        // internal edge and both routers are connected
        else if(el->data->ep1 && el->data->ep2) num_edges++;
        el = el->next;
    }

    size_t packet_len = sizeof(struct ospfv2_lsu_hdr_complete)
            + num_edges * sizeof(struct ospfv2_lsu);
    *out_lsu_hdr_len = packet_len;
    *out_lsu_hdr = (struct ospfv2_lsu_hdr_complete *)calloc(1, packet_len);

    (*out_lsu_hdr)->eth.ether_type = htons(ETHERTYPE_IP);

    (*out_lsu_hdr)->ip_hdr.ip_hl = 5;
    (*out_lsu_hdr)->ip_hdr.ip_v = 4;
    (*out_lsu_hdr)->ip_hdr.ip_tos = 0;
    (*out_lsu_hdr)->ip_hdr.ip_len = htons(packet_len - sizeof(struct sr_ethernet_hdr));
    (*out_lsu_hdr)->ip_hdr.ip_id = 0;
    (*out_lsu_hdr)->ip_hdr.ip_off = 0;
    (*out_lsu_hdr)->ip_hdr.ip_ttl = 0xFF;
    (*out_lsu_hdr)->ip_hdr.ip_p = IPPROTO_OSPF;

    (*out_lsu_hdr)->pwospf_shared.version = OSPF_V2;
    (*out_lsu_hdr)->pwospf_shared.type = OSPF_TYPE_LSU;
    (*out_lsu_hdr)->pwospf_shared.len = htons(packet_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
    (*out_lsu_hdr)->pwospf_shared.rid = sr->ospf_subsys->graph->rid;
    (*out_lsu_hdr)->pwospf_shared.aid = htonl(OSPF_AREA_ID);

    (*out_lsu_hdr)->pwospf_lsu.seq = htons(sr->ospf_subsys->graph->last_seq_num);
    (*out_lsu_hdr)->pwospf_lsu.ttl = OSPF_MAX_LSU_TTL;
    (*out_lsu_hdr)->pwospf_lsu.num_adv = htonl(num_edges);

    struct ospfv2_lsu *cur_lsu = (struct ospfv2_lsu *)((*out_lsu_hdr) + 1);
    el = sr->ospf_subsys->graph->edges;
    while(el)
    {
        if(!(el->data->is_internal))
        {
            cur_lsu->subnet = el->data->edge_subnet.prefix;
            cur_lsu->mask = el->data->edge_subnet.mask;
            cur_lsu->rid = 0;
            cur_lsu++;
        }
        else if(el->data->ep1 && el->data->ep2)
        {
            // we presume these are all already in network ordering, so
            // no need to call htonl
            cur_lsu->subnet = el->data->edge_subnet.prefix;
            cur_lsu->mask = el->data->edge_subnet.mask;
            cur_lsu->rid = (el->data->ep1->rid == sr->ospf_subsys->graph->rid) ? el->data->ep2->rid : el->data->ep1->rid;
            cur_lsu++;
        }
        el = el->next;
    }

    // now we've populated the header, calculate the checksum
    (*out_lsu_hdr)->pwospf_shared.csum = sr_util_ip_checksum(
            (void *)&((*out_lsu_hdr)->pwospf_shared),
            packet_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));

}

// the graph is locked throughout this function
static void send_lsu(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_lsu_hdr_complete *lsu_hdr, size_t lsu_hdr_len)
{
    struct pwospf_subnet subnet;
    subnet.mask = interface->mask;
    subnet.prefix = interface->ip & subnet.mask;
    struct pwospf_edge *e = pwospf_graph_get_edge(sr->ospf_subsys->graph, &subnet);
    // check if the other endpoint is connected. If not, just return early and save some work.
    // first, if the interface is already consumed by a static route, it's possible
    // that e will be null, since the subnet won't match the static route
    if(!e) return;
    if(!(e->ep1 && e->ep2)) return;
    // otherwise, find the IP of the next hop
    uint32_t ip;
    if(e->ep1->rid == sr->ospf_subsys->graph->rid)
    {
        // pick the other one's ip
        ip = e->ip2;
    }
    else
    {
        ip = e->ip1;
    }

    memcpy(&(lsu_hdr->eth.ether_shost), interface->addr, ETHER_ADDR_LEN);

    lsu_hdr->ip_hdr.ip_sum = 0;
    lsu_hdr->ip_hdr.ip_src.s_addr = interface->ip;
    lsu_hdr->ip_hdr.ip_dst.s_addr = ip;
    lsu_hdr->ip_hdr.ip_sum = sr_util_ip_checksum(
            (void *)&(lsu_hdr->ip_hdr),
            sizeof(struct ip)
    );

    // see if we know the MAC
    uint8_t mac[ETHER_ADDR_LEN];
    if(!sr_get_mac_from_ip(sr, interface->name, ip, mac))
    {
        sr_send_arp_request(sr, interface->name, ip);
        sr_cache_packet_until_arp(sr, interface->name, ip, (uint8_t *)lsu_hdr, lsu_hdr_len);
    }
    else
    {
        memcpy(lsu_hdr->eth.ether_dhost, mac, ETHER_ADDR_LEN);
        sr_deb_print_outgoing(stdout, lsu_hdr_len);
        sr_deb_print_packet(stdout, (struct sr_ethernet_hdr *)lsu_hdr, lsu_hdr_len);
        sr_send_packet(sr, (uint8_t *)lsu_hdr, lsu_hdr_len, interface->name);
    }
}

// the graph is locked throughout this function
static void send_lsu_all(struct sr_instance *sr)
{
    sr->ospf_subsys->graph->last_seq_num++;
    struct ospfv2_lsu_hdr_complete *lsu_hdr;
    size_t lsu_hdr_len;
    generate_lsu(sr, &lsu_hdr, &lsu_hdr_len);
    sr->ospf_subsys->my_last_lsu = sr_util_monotonic_secs();
    for(struct sr_if *cur_if = sr->if_list; cur_if != NULL; cur_if = cur_if->next)
    {
        send_lsu(sr, cur_if, lsu_hdr, lsu_hdr_len);
    }
    free(lsu_hdr);
}

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;



    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);

        // send hellos
        __time_t now = sr_util_monotonic_secs();
        if(now - OSPF_DEFAULT_HELLOINT > sr->ospf_subsys->my_last_hello)
        {
            pwospf_send_hello_all(sr);
            sr_deb_print_str(stdout, "sending hello\n");
            sr->ospf_subsys->my_last_hello = now;
        }

        // prune database and see if we need to send an update
        if(pwospf_graph_prune_neighbors(sr->ospf_subsys->graph)
                || sr->ospf_subsys->my_last_lsu < sr_util_monotonic_secs() - OSPF_DEFAULT_LSUINT)
        {
            sr_deb_print_pwospf_graph(stdout, sr->ospf_subsys->graph);
            send_lsu_all(sr);
            sr_deb_print_str(stdout, "sent LSU\n");
        }

        sr_deb_print_str(stdout, " pwospf subsystem sleeping \n");
        pwospf_unlock(sr->ospf_subsys);
        sleep(2);
        sr_deb_print_str(stdout, " pwospf subsystem awake \n");
    }
    return NULL;
} /* -- run_ospf_thread -- */

void pwospf_handle_packet(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr, size_t remaining_len, uint32_t ip)
{
    pwospf_lock(sr->ospf_subsys);
    if(hdr->aid != htonl(OSPF_AREA_ID))
    {
        sr_deb_print_str(stdout, "Wrong AID");
        goto unlock;
    }
    if(hdr->version != OSPF_V2)
    {
        sr_deb_print_str(stdout, "Received wrong version");
        goto unlock;
    }
    // TODO figure out why the checksum is wrong
    /*
    uint16_t csum = sr_util_ip_checksum((void *)hdr, remaining_len);
    if(csum != 0 && csum != 0xffff)
    {
        printf("Wrong checksum: 0x%4.4x", ntohs(csum));
        return;
    }
    */
    if(hdr->type == OSPF_TYPE_HELLO)
    {
        pwospf_handle_hello(sr, interface, hdr, ip);
    }
    else if(hdr->type == OSPF_TYPE_LSU)
    {
        pwospf_handle_lsu(sr, interface, hdr);
    }
    else
    {
        sr_deb_print_str(stdout, "Unknown OSPF packet type");
    }
unlock:
    pwospf_unlock(sr->ospf_subsys);
}

void pwospf_handle_hello(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr, uint32_t ip)
{
    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(hdr + 1);
    enum pwospf_graph_add_or_update_result added_or_updated =
            pwospf_graph_add_or_update_node(sr->ospf_subsys->graph, hdr->rid, NULL);
    struct pwospf_subnet subnet;
    subnet.mask = hello_hdr->nmask;
    subnet.prefix = interface->ip & subnet.mask;
    // since the directly-connected subnets would have already been added to the graph
    // as edges in the initialization code, the "add edge" here should be able to
    // find that edge and just set the newly-added router as the other endpoint.
    pwospf_graph_add_or_update_edge_from_hello(sr->ospf_subsys->graph, hdr->rid, &subnet, ip);
    // set the edge to internal
    struct pwospf_edge *e = pwospf_graph_get_edge(sr->ospf_subsys->graph, &subnet);
    e->is_internal = true;
    if(added_or_updated == PGAOUR_ADD)
    {
        send_lsu_all(sr);
    }
    sr_deb_print_pwospf_graph(stdout, sr->ospf_subsys->graph);
}

void pwospf_handle_lsu(struct sr_instance *sr, struct sr_if *interface, struct ospfv2_hdr *hdr)
{
    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(hdr + 1);

    struct ospfv2_lsu *lsu = (struct ospfv2_lsu *)(lsu_hdr + 1);

    uint16_t seq = ntohs(lsu_hdr->seq);

    struct pwospf_node *n = pwospf_graph_get_node(sr->ospf_subsys->graph, hdr->rid);
    if(n && n->sent_seq_num && !(sr_util_is_in_window(n->last_seq_num, OSPF_SEQ_NUM_WINDOW, seq, sizeof(uint16_t))))
    {
        // sequence number outside window, so ignore it.
        return;
    }
    pwospf_graph_add_or_update_node(sr->ospf_subsys->graph, hdr->rid, &seq);
    if(!n) n = pwospf_graph_get_node(sr->ospf_subsys->graph, hdr->rid);

    // we actually need to handle two cases here:
    // we are removing an endpoint that previously existed in the graph
    // or we are adding an endpoint that did not exist in the graph

    // case 1: removing edges which are not present in the LSU list
    struct pwospf_edge_list *el = n->edges;
    while(el)
    {
        bool present = false;
        struct pwospf_subnet *edge_subnet = &(el->data->edge_subnet);
        for(size_t i = 0; i < ntohl(lsu_hdr->num_adv); i++)
        {
            struct pwospf_subnet subnet;
            subnet.mask = lsu[i].mask;
            subnet.prefix = lsu[i].subnet;
            if(pwospf_subnet_eq(edge_subnet, &subnet))
            {
                present = true;
                break;
            }
        }
        if(!present)
        {
            pwospf_graph_remove_endpoint(sr->ospf_subsys->graph, hdr->rid, edge_subnet);
        }
        el = el->next;
    }

    // now add/update the edges which are present in the advertisement
    for(size_t i = 0; i < ntohl(lsu_hdr->num_adv); i++)
    {
        struct pwospf_subnet subnet;
        subnet.mask = lsu[i].mask;
        subnet.prefix = lsu[i].subnet;
        struct pwospf_edge *existing_edge = pwospf_graph_get_edge(sr->ospf_subsys->graph, &subnet);
        if(existing_edge && existing_edge->ep1 && existing_edge->ep2)
        {
            // check if the other advertised rid is consistent. otherwise ignore this LSU.
            if((existing_edge->ep1->rid == hdr->rid)
                    && (existing_edge->ep2->rid != lsu[i].rid))
            {
                continue;
            }
            else if((existing_edge->ep2->rid == hdr->rid)
                    && (existing_edge->ep1->rid != lsu[i].rid))
            {
                continue;
            }
        }
        pwospf_graph_add_or_update_edge_from_lsu(sr->ospf_subsys->graph, hdr->rid, &subnet);
    }

    sr_deb_print_pwospf_graph(stdout, sr->ospf_subsys->graph);
    // finally, send this packet out to all the other internal interfaces
    struct sr_if *cur_if = sr->if_list;
    while(cur_if)
    {
        if(cur_if != interface)
        {
            send_lsu(
                    sr,
                    cur_if,
                    (struct ospfv2_lsu_hdr_complete *)((uint8_t *)hdr - sizeof(struct ip) - sizeof(struct sr_ethernet_hdr)),
                    sizeof(struct ospfv2_lsu_hdr_complete) + ntohl(lsu_hdr->num_adv) * sizeof(struct ospfv2_lsu)
            );
        }
        cur_if = cur_if->next;
    }
}
