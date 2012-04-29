/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_icmp_proto.h"
#include "sr_checksum.h"
#include "sr_arpcache.h"

void prettyprintIP(uint32_t ipaddr);
void respondToIcmpEcho(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface, struct sr_ethernet_hdr* e_hdr,
        struct ip* ip_hdr, struct icmp_hdr* icmp_hdr);
void sendArpReply(struct sr_ethernet_hdr* ehdr, struct sr_arphdr* arph,
        struct sr_instance* sr, char*);
void sendArpRequest(struct sr_instance* sr, uint32_t src_ip,
        struct in_addr dst_ip, char *interface);
void sendQueue(uint32_t ip, unsigned char * ha,
        struct sr_instance *sr, char *interface);
void printEthernetHeader(struct sr_ethernet_hdr* ehdr);
void printArpHeader(struct sr_arphdr* ahdr);
void printIpHeader(struct ip* iphdr);
void printIcmpHeader(struct icmp_hdr* icmp_h);
bool iAmDestination(struct in_addr* ip_src,struct sr_instance* sr);
void sendIcmpError(struct sr_instance* sr, char* interface, uint8_t *packet,
        struct sr_ethernet_hdr* e_hdr, struct ip*, uint8_t type, uint8_t code);
uint8_t decrement_ttl(struct ip *ip_hdr);
void route(struct sr_instance* sr, uint8_t* packet, unsigned int len,
        char* interface, struct sr_ethernet_hdr* e_hdr, struct ip* ip_hdr);
void sendOff(struct sr_instance *sr, struct waitingpacket *pack,
        struct sr_if *inter, const uint8_t *ha);
struct flowTableEntry * searchForFlow(struct sr_instance* sr, char * srcIp,
        uint16_t srcPort, char * dstIP, uint16_t dstPort, uint8_t protocol);
void addFlowToTable(struct sr_instance* sr, char * srcIp,
        uint16_t srcPort, char * dstIP, uint16_t dstPort, uint8_t protocol);
char* prettyprintIPHelper(uint32_t ipaddr);
void resendAllArps(struct sr_instance *sr);
void resendArps(struct sr_instance *sr, struct sr_if *inter);

const double DEATH = 5;
const unsigned char BROADCAST_ADDR[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */
    init_arpcache();
    sr->flowTable = NULL;
//    Debug("Mac for 171.67.242.68 is ");
//    DebugMAC(getarp("171.67.242.68"));
//    Debug("\n");
//    Debug("Mac for 171.67.242.70 is ");
//    DebugMAC(getarp("171.67.242.70"));
//    Debug("\n");

} /* -- sr_init -- */



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

    resendAllArps(sr);

    //figure out what kind of packet we got
    struct sr_ethernet_hdr* e_hdr = 0;
    e_hdr = (struct sr_ethernet_hdr*)packet;

    Debug("*** -> Received packet of length %d \n",len);
    Debug("Ethernet Header:\n");
    //printEthernetHeader(e_hdr);

    // Case on type of packet
    if (e_hdr->ether_type == htons(ETHERTYPE_ARP)) {
        // ARP:
        //
        struct sr_arphdr*       a_hdr = 0;
        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));

        Debug("\nPacket was an Arp:\n");
        //Debug("Arp Header:\n");
        //printArpHeader(a_hdr);

        if(a_hdr->ar_op == ntohs(ARP_REQUEST)) {
            // Arp request: reply based on which interface it came in on
            addarp(a_hdr->ar_sip, a_hdr->ar_sha);
            sendArpReply(e_hdr,a_hdr,sr,interface);
        } else if(a_hdr->ar_op == ntohs(ARP_REPLY)) {
            // Arp reply: add to cache, send all the packets in the queue
            addarp(a_hdr->ar_sip, a_hdr->ar_sha);
            sendQueue(a_hdr->ar_sip, a_hdr->ar_sha, sr, interface);
        } else {
            Debug("ARP packet received with bad op code.");
        }
    }
    else if (e_hdr->ether_type == htons(ETHERTYPE_IP)) {
        // IP
        struct ip* ip_hdr = 0;
        ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
        Debug("\nPacket was an IP:\n");

        if(sr->firewall_enabled) {
            char* t1 = prettyprintIPHelper(*(uint32_t*)&ip_hdr->ip_src);
            char* t2 = prettyprintIPHelper(*(uint32_t*)&ip_hdr->ip_dst);
            if(strncmp(sr->external, interface, sr_IFACE_NAMELEN) == 0) {
                struct flowTableEntry* result = searchForFlow(sr,
                    t1,0, t2,0,ip_hdr->ip_p);
                if(result == NULL){
                    Debug("Dropped packet into interface %s\n", interface);
                    free(t1);
                    free(t2);
                    return;
                }
                Debug("Let a packet through the firewall");
            }
            addFlowToTable(sr,t1,0, t2,0,ip_hdr->ip_p);
            free(t1);
            free(t2);
        }

        // ICMP
        if(ip_hdr->ip_p == 1) {
            struct icmp_hdr *icmp_h = 0;
            icmp_h = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) +
                   sizeof(struct ip));
            Debug("ICMP Header:\n");
            //printIcmpHeader(icmp_h);

            // Case on ICMP Type:
            if (icmp_h->icmp_type == 30 && icmp_h->icmp_code == 0) {
                // Traceroute:
                Debug("Reply to Traceroute not implemented");
                if(!iAmDestination(&(ip_hdr->ip_dst), sr)) {
                    Debug("Decrement TTD not implemented (Don't forget to recalculate checksum)");
                    route(sr, packet, len, interface, e_hdr, ip_hdr);
                }
            } else if(icmp_h->icmp_type == 8 && icmp_h->icmp_code == 0) {
                // Echo Request:
                if(iAmDestination(&(ip_hdr->ip_dst), sr)) {
                    respondToIcmpEcho(sr, packet, len, interface, e_hdr, ip_hdr, icmp_h);
                } else {
                    route(sr, packet, len, interface, e_hdr, ip_hdr);
                }
            } else {
                // Other ICMPs
                if(!iAmDestination(&(ip_hdr->ip_dst), sr)) {
                    route(sr, packet, len, interface, e_hdr, ip_hdr);
                }
            }
        }
        // Not ICMP
        else {
            if(iAmDestination(&(ip_hdr->ip_dst), sr)) {
                sendIcmpError(sr, interface, packet, e_hdr, ip_hdr, 3, 3);
            } else {
                route(sr, packet, len, interface, e_hdr, ip_hdr);
            }
        }
    }
    else if (e_hdr->ether_type == htons(IPPROTO_ICMP)) {
        Debug("Something had type IPPROTO_ICMP...I'm confused\n");
    }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: pretty print ipaddr
 * Scope: Local
 *
 *---------------------------------------------------------------------*/

//allocates a char[15]; caller responsible for freeing it.
char* prettyprintIPHelper(uint32_t ipaddr){
    // char output[15];
    unsigned char octet[4] = {0,0,0,0};
    for (int i=0;i<4;i++){
        octet[i]=(ipaddr >> (i*8) ) & 0xFF;
    }
    // sprintf(output,"%d.%d.%d.%d", octet[3],octet[2],octet[1],octet[0]);
    char * output = malloc(15 * sizeof(char)); //127.127.127.127
    sprintf(output, "%d.%d.%d.%d", octet[0],octet[1],octet[2],octet[3]);
    return output;
}

void prettyprintIP(uint32_t ipaddr){
    char * pretty = prettyprintIPHelper(ipaddr);
    printf("%s", pretty);
    free(pretty);
}



void sendArpReply(struct sr_ethernet_hdr* ehdr, struct sr_arphdr* arph, struct sr_instance* sr,char* interface){

    // Find hardward address corresponding to interface
    unsigned char* macaddr = (sr_get_interface(sr, interface))->addr;

    // Allocate a packet for the buffer
    unsigned int len = sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arphdr);
    uint8_t buf[len];

    // Insert ethernet header
    struct sr_ethernet_hdr *newe_hdr = (struct sr_ethernet_hdr*) buf;
    memcpy(newe_hdr->ether_dhost, ehdr->ether_shost,6);
    memcpy(newe_hdr->ether_shost, macaddr,6);
    newe_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Insert arp header
    struct sr_arphdr *newa_hdr = (struct sr_arphdr*) (buf + sizeof(struct sr_ethernet_hdr));

    newa_hdr->ar_hrd = arph->ar_hrd;
    newa_hdr->ar_pro = arph->ar_pro;
    newa_hdr->ar_hln = arph->ar_hln;
    newa_hdr->ar_pln = arph->ar_pln;
    newa_hdr->ar_op = htons(ARP_REPLY);
    memcpy(newa_hdr->ar_sha, macaddr,6);
    newa_hdr->ar_sip = arph->ar_tip;
    newa_hdr->ar_tip = arph->ar_sip;
    // newa_hdr->ar_tha = arph->ar_sha;
    memcpy(newa_hdr->ar_tha,arph->ar_sha,6);

    //Debug("\nPacket to send:\n");
    //Debug("Ethernet Header:\n");
    //printEthernetHeader(newe_hdr);
    //printf("Arp Header:\n");
    //printArpHeader(newa_hdr);


    //then send
    // int sr_send_packet(struct sr_instance* sr /* borrowed */,
    //                      uint8_t* buf /* borrowed */ ,
    //                      unsigned int len,
    //                      const char* iface /* borrowed */)
    sr_send_packet(sr, buf,len, interface);
    Debug("Sent Arp Reply\n");
}

void sendArpRequest(struct sr_instance* sr, uint32_t src_ip, struct in_addr dst_ip, char *interface) {
    // Find hardward address corresponding to interface
    unsigned char* macaddr = (sr_get_interface(sr, interface))->addr;

    // Allocate a packet for the buffer
    unsigned int len = sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arphdr);
    uint8_t buf[len];

    // Insert ethernet header
    struct sr_ethernet_hdr *newe_hdr = (struct sr_ethernet_hdr*) buf;
    memcpy(newe_hdr->ether_dhost, BROADCAST_ADDR,6);
    memcpy(newe_hdr->ether_shost, macaddr,6);
    newe_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Insert arp header
    struct sr_arphdr *newa_hdr = (struct sr_arphdr*) (buf + sizeof(struct sr_ethernet_hdr));

    newa_hdr->ar_hrd = htons(1);
    newa_hdr->ar_pro = htons(0x0800);
    newa_hdr->ar_hln = 0x06;
    newa_hdr->ar_pln = 0x04;
    newa_hdr->ar_op = htons(ARP_REQUEST);
    memcpy(newa_hdr->ar_sha, macaddr,6);
    newa_hdr->ar_sip = (src_ip);
    memcpy(newa_hdr->ar_tha, BROADCAST_ADDR,6);
    newa_hdr->ar_tip = (*((uint32_t*)(&dst_ip)));

    //Debug("\nPacket to send:\n");
    //Debug("Ethernet Header:\n");
    //printEthernetHeader(newe_hdr);
    //printf("Arp Header:\n");
    //printArpHeader(newa_hdr);

    sr_send_packet(sr, buf,len, interface);
    Debug("Sent ARP Request\n");

}

void delete_waiting(struct waitingpacket* doomed){
    free(doomed->data);
    free(doomed);
}

void sendQueue(uint32_t ip, unsigned char * ha,
        struct sr_instance *sr, char *interface) {
    struct sr_if *inter = sr_get_interface(sr, interface);

    struct waitingpacket *last = NULL;
    struct waitingpacket *me = inter->queue;

    while( me != NULL ) {
        //Debug("Looking for Ip address: %s\n", prettyprintIPHelper(ip));
        //Debug("Found Ip address: %s\n", prettyprintIPHelper(me->ip_dst));
        if( me->ip_dst == ip ) {
            sendOff(sr, me, inter, ha);
            if(last == NULL){
                inter->queue = me->next;
            } else {
                last->next = me->next;
            }
            struct waitingpacket *temp = me;
            me = temp->next;
            delete_waiting(temp);
        } else {
            last = me;
            me = me->next;
        }
    }
}

void respondToIcmpEcho(struct sr_instance* sr, uint8_t* packet,
       unsigned int len, char* interface, struct sr_ethernet_hdr* e_hdr,
       struct ip* ip_hdr, struct icmp_hdr* icmp_hdr) {

    uint8_t buf[len];
    memset(buf, 0, len);

    // Change Ethernet Header
    struct sr_ethernet_hdr *newe_hdr = (struct sr_ethernet_hdr*) buf;
    memcpy(newe_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(newe_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);
    newe_hdr->ether_type = e_hdr->ether_type;

    // Change Ip Header (src and dst)
    struct ip *newip_hdr = (struct ip*) (buf + sizeof(struct sr_ethernet_hdr));
    newip_hdr->ip_hl = ip_hdr->ip_hl;
    newip_hdr->ip_v = ip_hdr->ip_v;
    newip_hdr->ip_tos = ip_hdr->ip_tos;
    newip_hdr->ip_len = ip_hdr->ip_len;
    newip_hdr->ip_id = ip_hdr->ip_id;
    newip_hdr->ip_off = ip_hdr->ip_off;
    newip_hdr->ip_ttl = IP_MAX_TTL;
    newip_hdr->ip_p = ip_hdr->ip_p;
    newip_hdr->ip_sum = 0;
    newip_hdr->ip_src = ip_hdr->ip_dst;
    newip_hdr->ip_dst = ip_hdr->ip_src;
    //Recalculate Check Sum
    newip_hdr->ip_sum = checksum(sizeof(struct ip), (uint8_t*)newip_hdr);

    // Change Icmp Header
    struct icmp_hdr *newi_hdr = (struct icmp_hdr*) (buf +
            sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    newi_hdr->icmp_type = 0;
    newi_hdr->icmp_code = 0;
    newi_hdr->icmp_sum = 0;
    newi_hdr->icmp_ident = icmp_hdr->icmp_ident;
    newi_hdr->icmp_seqnum = icmp_hdr->icmp_seqnum;

    // Put in data
    int header_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmp_hdr);
    int data_len = len - header_len;
    uint8_t *data = buf + header_len;
    memcpy(data, packet + header_len, data_len);

    //Recalculate Check Sum
    newi_hdr->icmp_sum = checksum(sizeof(struct icmp_hdr) + data_len,
            (uint8_t*) (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)));

    sr_send_packet(sr, buf,len, interface);
    Debug("Sent Icmp Echo Reply\n");
}

bool iAmDestination(struct in_addr* ip_dest,struct sr_instance* sr) {
    struct sr_if* curr = sr->if_list;
    bool answer = false;
    char * frompacket =inet_ntoa(*ip_dest);
    while(curr != NULL){
        char* fromsr = prettyprintIPHelper(curr->ip);
        answer = answer || (strncmp(fromsr, frompacket, 15) == 0);
        free(fromsr);
        curr = curr->next;
    }
    return answer;
}

/*---------------------------------------------------------------------
 * Method: printEthernetHeader
 * Scope: Local
 * Purpose: Debugging
 *---------------------------------------------------------------------*/
void printEthernetHeader(struct sr_ethernet_hdr* ehdr) {
    Debug("dhost: ");
    DebugMAC(ehdr->ether_dhost);
    Debug("\nshost: ");
    DebugMAC(ehdr->ether_shost);
    Debug("\ntype: %x\n", ntohs(ehdr->ether_type));
}

/*---------------------------------------------------------------------
 * Method: printArpHeader
 * Scope: Local
 * Purpose: Debugging
 *---------------------------------------------------------------------*/
void printArpHeader(struct sr_arphdr* ahdr) {
    Debug("op: %d", ntohs(ahdr->ar_op));
    Debug("\nsha: ");
    DebugMAC(ahdr->ar_sha);
    Debug("\nsip: ");
    prettyprintIP(ahdr->ar_sip);
    Debug("\ntha: ");
    DebugMAC(ahdr->ar_tha);
    Debug("\ntip: ");
    prettyprintIP(ahdr->ar_tip);
    Debug("\n");
}

/*---------------------------------------------------------------------
 * Method: printIpHeader
 * Scope: Local
 * Purpose: Debugging
 *---------------------------------------------------------------------*/
void printIpHeader(struct ip* iphdr) {
    Debug("tos: %d\n",        iphdr->ip_tos );
    Debug("len: %d\n", ntohs( iphdr->ip_len));
    Debug("id: %d\n",  ntohs( iphdr->ip_id ));
    Debug("off: %d\n", ntohs( iphdr->ip_off));
    Debug("ttl: %d\n",        iphdr->ip_ttl );
    Debug("p: %d\n",          iphdr->ip_p   );
    Debug("sum: %d\n", ntohs( iphdr->ip_sum));
    Debug("src: %s\n", inet_ntoa(iphdr->ip_src));
    Debug("dst: %s\n", inet_ntoa(iphdr->ip_dst));
}

/*---------------------------------------------------------------------
 * Method: printIcmpHeader
 * Scope: Local
 * Purpose: Debugging
 *---------------------------------------------------------------------*/
void printIcmpHeader(struct icmp_hdr* icmp_h) {
    Debug("Type: %d\n", icmp_h->icmp_type);
    Debug("Code: %d\n", icmp_h->icmp_code);
    Debug("Sum: %d\n", ntohs(icmp_h->icmp_sum));
    Debug("Identifier: %d\n", ntohs(icmp_h->icmp_ident));
    Debug("SeqNum: %d\n", ntohs(icmp_h->icmp_seqnum));
}

void sendIcmpError(struct sr_instance* sr, char* interface, uint8_t *packet,
        struct sr_ethernet_hdr* e_hdr, struct ip *ip_hdr,
        uint8_t type, uint8_t code) {

    int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmp_hdr) + sizeof(struct ip) + 8;
    uint8_t buf[len];

    // Change Ethernet Header
    struct sr_ethernet_hdr *newe_hdr = (struct sr_ethernet_hdr*) buf;
    memcpy(newe_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(newe_hdr->ether_shost, e_hdr->ether_dhost, ETHER_ADDR_LEN);
    newe_hdr->ether_type = htons(ETHERTYPE_IP);

    // Change Ip Header (src and dst)
    struct ip *newip_hdr = (struct ip*) (buf + sizeof(struct sr_ethernet_hdr));
    newip_hdr->ip_hl = ip_hdr->ip_hl;
    newip_hdr->ip_v = ip_hdr->ip_v;
    newip_hdr->ip_tos = 0;
    newip_hdr->ip_len = len;
    newip_hdr->ip_id = 0;
    newip_hdr->ip_off = 0;
    newip_hdr->ip_ttl = IP_MAX_TTL;
    newip_hdr->ip_p = 1;
    newip_hdr->ip_sum = 0;
    newip_hdr->ip_src = ip_hdr->ip_dst;
    newip_hdr->ip_dst = ip_hdr->ip_src;
    //Recalculate Check Sum
    newip_hdr->ip_sum = checksum(sizeof(struct ip), (uint8_t*)newip_hdr);

    // Change Icmp Header
    struct icmp_hdr *newi_hdr = (struct icmp_hdr*) (buf +
            sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    newi_hdr->icmp_type = type;
    newi_hdr->icmp_code = code;
    newi_hdr->icmp_sum = 0;
    newi_hdr->icmp_ident = 0;
    newi_hdr->icmp_seqnum = 0;

    uint8_t *data = buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
        sizeof(struct icmp_hdr);
    memcpy(data, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip) + 8);

    //Recalculate Check Sum
    newi_hdr->icmp_sum = checksum(
            sizeof(struct icmp_hdr) + sizeof(struct ip) + 8,
            (uint8_t*)newi_hdr);

    sr_send_packet(sr, buf, len, interface);
    Debug("Sent ICMP type:%u code:%u.\n", type, code);
}

struct sr_rt * get_rt_entry(struct sr_instance* sr, struct in_addr dst) {
    struct sr_rt* rt_walker = sr->routing_table;
    struct sr_rt* default_rt = NULL;

    char dest[15];
    strncpy(dest, inet_ntoa(dst), 15);
    //Debug("Searching routing table for %s\n", dest);
    while(rt_walker)
    {
        if(memcmp(&dst, &(rt_walker->dest), sizeof(dst))==0) {
            //Debug("Found in routing table %s\n", inet_ntoa(rt_walker->dest));
            return rt_walker;
        }
        if(strcmp(inet_ntoa(rt_walker->dest), "0.0.0.0")==0) {
            default_rt = rt_walker;
        }
        rt_walker = rt_walker->next;
    }
    Debug("Routing to default route.\n");
    return default_rt;
}

uint8_t decrement_ttl(struct ip *ip_hdr) {
    if(ip_hdr->ip_ttl == 0) {
        return 0;
    }
    ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
    return ip_hdr->ip_ttl;
}

void route(struct sr_instance* sr, uint8_t* packet, unsigned int len,
        char* interface, struct sr_ethernet_hdr* e_hdr, struct ip* ip_hdr) {

    struct sr_rt * rt_entry = get_rt_entry(sr, ip_hdr->ip_dst);
    if(rt_entry != NULL) {
        if(decrement_ttl(ip_hdr) == 0) {
            sendIcmpError(sr, interface, packet, e_hdr, ip_hdr, 11, 0);
            return;
        }

        struct sr_if *inter = sr_get_interface(sr, rt_entry->interface);
        // Create a new packet to queue
        struct waitingpacket *newpacket = malloc(sizeof(struct waitingpacket));
        newpacket->ip_dst = *((uint32_t*) &(rt_entry->gw));
        newpacket->data = calloc(sizeof(uint8_t), len);
        memcpy(newpacket->data, packet, len);
        newpacket->len = len;
        newpacket->arpt = time(NULL);
        newpacket->arpn = 0;
        newpacket->next = inter->queue;

        const uint8_t *ha = getarp(newpacket->ip_dst);
        if(ha != NULL) {
            sendOff(sr, newpacket, inter, ha);
            delete_waiting(newpacket);
        } else {
            // Queue new packet
            inter->queue = newpacket;

            // send arp request over interface
            sendArpRequest(sr, inter->ip, rt_entry->gw, inter->name);
        }
    } else {
        Debug("Failed to grab default routing table entry in get_rt_entry.\n");
    }
}

void sendOff(struct sr_instance *sr, struct waitingpacket *pack,
        struct sr_if *inter, const uint8_t *ha) {
    struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr*) pack->data;
    memcpy(e_hdr->ether_shost, (uint8_t*) inter->addr, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_dhost, ha, ETHER_ADDR_LEN);
    sr_send_packet(sr, pack->data, pack->len, inter->name);

    char * prettyIP = prettyprintIPHelper(pack->ip_dst);
    Debug("Routed packet to %s\n", prettyIP);
    free(prettyIP);

}

bool compareIPandPort(char * Ip1, char * Ip2, uint16_t port1, uint16_t port2){
    return((strncmp(Ip1, Ip2, 15) == 0)&&(port1 == port2));
}

void deleteFTE(struct flowTableEntry* doomed){
    Debug("Deleted flow for %s to %s\n", doomed->srcIP, doomed->dstIP);
    free(doomed);
}

struct flowTableEntry * searchForFlow(struct sr_instance* sr, char * srcIp,
        uint16_t srcPort, char * dstIp, uint16_t dstPort, uint8_t protocol){
    struct flowTableEntry* current = sr->flowTable;
    struct flowTableEntry* prev = NULL;
    while(current != NULL){
        if(difftime(time(NULL),current->ttl) > DEATH){
            if(prev == NULL){
                sr->flowTable = current->next;
            }
            else {
                prev->next = current->next;
            }
            struct flowTableEntry* temp = current;
            current = current->next;
            deleteFTE(temp);
        }
        else if(((compareIPandPort(current->srcIP, srcIp,current->srcPort,srcPort) &&
            compareIPandPort(current->dstIP, dstIp,current->srcPort,dstPort))
                ||
            (compareIPandPort(current->srcIP, dstIp,current->srcPort,dstPort)&&
            compareIPandPort(current->dstIP, srcIp,current->srcPort,srcPort)))
            &&
            (protocol == current->ipProtocol)){
            return current;
        }
        else {
            prev = current;
            current = current->next;
        }
    }
    return NULL;
}

void addFlowToTable(struct sr_instance* sr, char * srcIp,
        uint16_t srcPort, char * dstIp, uint16_t dstPort, uint8_t protocol){
    struct flowTableEntry* result = searchForFlow(sr, srcIp, srcPort, dstIp, dstPort, protocol);
    if(result == NULL){
        Debug("Adding flow for %s to %s\n", srcIp, dstIp);
        result = malloc(sizeof(struct flowTableEntry));
        strncpy(result->srcIP,srcIp,15);
        result->srcIPw = false;
        result->srcPort = srcPort;
        result->srcPortw = false;
        strncpy(result->dstIP,dstIp,15);
        result->dstIPw = false;
        result->dstPort = dstPort;
        result->dstPortw = false;
        result->ipProtocol = protocol;
        result->ipProtow = false;
        result->ttl = time(NULL);
        result->next = sr->flowTable;
        sr->flowTable = result;
    }
    else {
        result->ttl = time(NULL);
    }
}

void resendAllArps(struct sr_instance *sr) {
    struct sr_if* inter = sr->if_list;
    while(inter != NULL) {
        resendArps(sr, inter);
        inter = inter->next;
    }
}

void resendArps(struct sr_instance *sr, struct sr_if *inter) {
    struct waitingpacket *me = inter->queue;
    struct waitingpacket *last = NULL;
    time_t now = time(NULL);
    while(me != NULL) {
        if(difftime(now, me->arpt) > ARP_TIMEOUT) {
            me->arpn = me->arpn + 1;
            me->arpt = now;
            if(me->arpt >= 5) {
                struct sr_ethernet_hdr *e_hdr = 
                    (struct sr_ethernet_hdr*) me->data;
                struct ip *ip_hdr = (struct ip*) 
                    (me->data + sizeof(struct sr_ethernet_hdr));
                //ICMP Host Unreachable
                sendIcmpError(sr, inter->name, me->data, e_hdr, ip_hdr, 3, 1);
                // Remove from queue
                if(last == NULL) {
                    inter->queue = me->next;
                } else {
                    last->next = me->next;
                }
            } else {
                sendArpRequest(sr, inter->ip, 
                        *((struct in_addr*) &me->ip_dst), inter->name);
                last = me;
            }
        } else {
            last = me;
        }
        me = me->next;
    }
}
