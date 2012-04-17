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

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

void prettyprintIP(uint32_t ipaddr);
void sendYes(struct sr_ethernet_hdr* ehdr, struct sr_arphdr* arph, struct sr_instance* sr, char*);
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

    printf("*** -> Received packet of length %d \n",len);
    if (e_hdr->ether_type == htons(ETHERTYPE_ARP)) {
        struct sr_arphdr*       a_hdr = 0;
        a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
        printf("\tARP:");
        prettyprintIP(a_hdr->ar_tip);
        printf("\n");

        //send ARP Reply "YES!"
        sendYes(e_hdr,a_hdr,sr,interface);
    }
    else if (e_hdr->ether_type == htons(ETHERTYPE_IP)) {
        printf("\tIP\n");
    }
    else if (e_hdr->ether_type == htons(IPPROTO_ICMP)) {
        printf("\tICMP\n");
    }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: pretty print ipaddr
 * Scope: Local
 *
 *---------------------------------------------------------------------*/
void prettyprintIP(uint32_t ipaddr){
    // char output[15];
    unsigned char octet[4] = {0,0,0,0};
    for (int i=0;i<4;i++){
        octet[i]=(ipaddr >> (i*8) ) & 0xFF;
    }
    // sprintf(output,"%d.%d.%d.%d", octet[3],octet[2],octet[1],octet[0]);
    printf("%d.%d.%d.%d", octet[3],octet[2],octet[1],octet[0]);
    // return output;
}

void sendYes(struct sr_ethernet_hdr* ehdr, struct sr_arphdr* arph, struct sr_instance* sr,char* interface){
    //ethohdr + aprhrd
    struct sr_ethernet_hdr newe_hdr;
    struct sr_arphdr newa_hdr;

    //     uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination ethernet address */
    // uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source ethernet address */
    // uint16_t ether_type;                     /* packet type ID */

    // newe_hdr.ether_dhost = ehdr->ether_shost;
    memcpy(newe_hdr.ether_dhost,ehdr->ether_shost,6);
    // newa_hdr.ether_shost = ehdr->ether_dhost;
    memcpy(newe_hdr.ether_shost,sr->if_list->addr,6);
    newe_hdr.ether_type = ehdr->ether_type;

    newa_hdr.ar_hrd = arph->ar_hrd;
    newa_hdr.ar_pro = arph->ar_pro;
    newa_hdr.ar_hln = arph->ar_hln;
    newa_hdr.ar_pln = arph->ar_pln;
    newa_hdr.ar_op = ARP_REPLY;
    memcpy(newa_hdr.ar_sha,sr->if_list->addr,6);
    newa_hdr.ar_sip = arph->ar_tip;
    newa_hdr.ar_tip = arph->ar_sip;
    // newa_hdr.ar_tha = arph->ar_sha;
    memcpy(newa_hdr.ar_tha,arph->ar_sha,6);

    //then send
    // int sr_send_packet(struct sr_instance* sr /* borrowed */,
    //                      uint8_t* buf /* borrowed */ ,
    //                      unsigned int len,
    //                      const char* iface /* borrowed */)
    unsigned int len = sizeof(struct sr_ethernet_hdr)+ sizeof(struct sr_arphdr);
    uint8_t buf[len];
    memcpy(&buf, &newe_hdr, sizeof(struct sr_ethernet_hdr));
    memcpy(&buf + sizeof(struct sr_ethernet_hdr), &newa_hdr, sizeof(struct sr_arphdr));
    sr_send_packet(sr, buf,len, interface);
    printf("said yes!\n");

}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
