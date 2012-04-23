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

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_icmp_proto.h"
#include "sr_checksum.h"

void prettyprintIP(uint32_t ipaddr);
void respondToIcmpEcho(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface, struct sr_ethernet_hdr* e_hdr,
        struct ip* ip_hdr, struct icmp_hdr* icmp_hdr);
void sendArpReply(struct sr_ethernet_hdr* ehdr, struct sr_arphdr* arph, struct sr_instance* sr, char*);
void printEthernetHeader(struct sr_ethernet_hdr* ehdr);
void printArpHeader(struct sr_arphdr* ahdr);
void printIpHeader(struct ip* iphdr);
void printIcmpHeader(struct icmp_hdr* icmp_h);
bool iAmDestination(struct in_addr* ip_src,struct sr_instance* sr);
void sendIcmpError(struct sr_instance* sr, char* interface, uint8_t *packet,
        struct sr_ethernet_hdr* e_hdr, struct ip*);
void route(struct sr_instance* sr, uint8_t* packet, unsigned int len,
        char* interface, struct sr_ethernet_hdr* e_hdr, struct ip* ip_hdr);
uint16_t calculate_check_sum(size_t length, uint16_t* vdata);
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

    //figure out what kind of packet we got
    struct sr_ethernet_hdr* e_hdr = 0;
    e_hdr = (struct sr_ethernet_hdr*)packet;

    Debug("*** -> Received packet of length %d \n",len);
    Debug("Ethernet Header:\n");
    printEthernetHeader(e_hdr);

    // Case on type of packet
    if (e_hdr->ether_type == htons(ETHERTYPE_ARP)) {
        // ARP:
        //
        struct sr_arphdr*       a_hdr = 0;
        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));

        Debug("\nPacket was an Arp:\n");
        Debug("Arp Header:\n");
        printArpHeader(a_hdr);

        if(a_hdr->ar_op == ntohs(ARP_REQUEST)) {
            // Arp request
            // TODO: Add to Cache
            sendArpReply(e_hdr,a_hdr,sr,interface);
        } else if(a_hdr->ar_op == ntohs(ARP_REPLY)) {
            // Arp reply
            Debug("ARP reply is not implemented");
        } else {
            Debug("ARP packet received with bad op code.");
        }
    }
    else if (e_hdr->ether_type == htons(ETHERTYPE_IP)) {
        // IP

        struct ip* ip_hdr = 0;
        ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));

        Debug("\nPacket was an IP:\n");
        Debug("IP Header:\n");
        printIpHeader(ip_hdr);

        // ICMP
        if(ip_hdr->ip_p == 1) { //ip_hdr->ip_tos == 0 && ip_hdr->ip_p == 1) {
            struct icmp_hdr *icmp_h = 0;
            icmp_h = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) +
                   sizeof(struct ip));
            Debug("ICMP Header:\n");
            printIcmpHeader(icmp_h);

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
                sendIcmpError(sr, interface, packet, e_hdr, ip_hdr);
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

    // Allocate a packet for the buffer
    unsigned int len = sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arphdr);
    uint8_t buf[len];

    // Insert ethernet header
    struct sr_ethernet_hdr *newe_hdr = (struct sr_ethernet_hdr*) buf;
    memcpy(newe_hdr->ether_dhost,ehdr->ether_shost,6);
    memcpy(newe_hdr->ether_shost,sr->if_list->addr,6);
    newe_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Insert arp header
    struct sr_arphdr *newa_hdr = (struct sr_arphdr*) (buf + sizeof(struct sr_ethernet_hdr));

    newa_hdr->ar_hrd = arph->ar_hrd;
    newa_hdr->ar_pro = arph->ar_pro;
    newa_hdr->ar_hln = arph->ar_hln;
    newa_hdr->ar_pln = arph->ar_pln;
    newa_hdr->ar_op = htons(ARP_REPLY);
    memcpy(newa_hdr->ar_sha,sr->if_list->addr,6);
    newa_hdr->ar_sip = arph->ar_tip;
    newa_hdr->ar_tip = arph->ar_sip;
    // newa_hdr->ar_tha = arph->ar_sha;
    memcpy(newa_hdr->ar_tha,arph->ar_sha,6);

    Debug("\nPacket to send:\n");
    Debug("Ethernet Header:\n");
    printEthernetHeader(newe_hdr);
    printf("Arp Header:\n");
    printArpHeader(newa_hdr);


    //then send
    // int sr_send_packet(struct sr_instance* sr /* borrowed */,
    //                      uint8_t* buf /* borrowed */ ,
    //                      unsigned int len,
    //                      const char* iface /* borrowed */)
    sr_send_packet(sr, buf,len, interface);
    printf("said yes!\n");

}

uint16_t calculate_check_sum(size_t length, uint16_t* vdata) {
    return my_checksum(length, vdata);
}

void respondToIcmpEcho(struct sr_instance* sr, uint8_t* packet,
       unsigned int len, char* interface, struct sr_ethernet_hdr* e_hdr,
       struct ip* ip_hdr, struct icmp_hdr* icmp_hdr) {

    Debug("Responding to ICMP echo request");

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
    newip_hdr->ip_sum = calculate_check_sum(10, (uint16_t*)newip_hdr);
/*
    // Change Icmp Header
    struct icmp_hdr *newi_hdr = (struct icmp_hdr*) (buf +
            sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    newi_hdr->icmp_type = 0;
    newi_hdr->icmp_code = 0;
    newi_hdr->icmp_sum = 0;
    newi_hdr->icmp_ident = icmp_hdr->icmp_ident;
    newi_hdr->icmp_seqnum = icmp_hdr->icmp_seqnum;

    //Recalculate Check Sum
    newi_hdr->icmp_sum = calculate_check_sum(sizeof(struct icmp_hdr),
            (uint16_t*)newi_hdr);

    // Put in data
    int header_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmp_hdr);
    int data_len = len - header_len;
    uint8_t *data = buf + header_len;
    memcpy(data, packet + header_len, data_len);
*/
    sr_send_packet(sr, buf,len, interface);
    printf("sent ping reply!\n");
}

bool iAmDestination(struct in_addr* ip_dest,struct sr_instance* sr) {
    char* fromsr = prettyprintIPHelper(sr->if_list->ip);
    char * frompacket =inet_ntoa(*ip_dest);
    bool answer = (strncmp(fromsr, frompacket, 15) == 0);
    free(fromsr);
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
        struct sr_ethernet_hdr* e_hdr, struct ip *ip_hdr) {
/*
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
    newip_hdr->ip_sum = calculate_check_sum(sizeof(struct ip), (uint16_t*)newip_hdr);

    // Change Icmp Header
    struct icmp_hdr *newi_hdr = (struct icmp_hdr*) (buf +
            sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    newi_hdr->icmp_type = 3;
    newi_hdr->icmp_code = 3;
    newi_hdr->icmp_sum = 0;
    newi_hdr->icmp_ident = 0;
    newi_hdr->icmp_seqnum = 0;

    //Recalculate Check Sum
    newi_hdr->icmp_sum = calculate_check_sum(sizeof(struct icmp_hdr), (uint16_t*)newi_hdr);

    uint8_t *data = buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + 
        sizeof(struct icmp_hdr);
    memcpy(data, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip) + 8);


    sr_send_packet(sr, buf, len, interface);
*/
    Debug("SendIcmpError not implemented\n");
}

void route(struct sr_instance* sr, uint8_t* packet, unsigned int len,
        char* interface, struct sr_ethernet_hdr* e_hdr, struct ip* ip_hdr) {
    Debug("route not implemented\n");
}
