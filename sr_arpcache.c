#include <string.h>
#include <stdlib.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"

struct arppair {
    uint32_t ip;
    uint8_t mac[ETHER_ADDR_LEN];
    //time_t expire;
    struct arppair *next;
};

struct arppair *cache;

void init_arpcache(void) {
    cache = NULL;
    // for now statically add arpcache
//    uint8_t mac1[] = { 0x00, 0x89, 0xb2, 0x0a, 0x1a, 0x48 };
//    addarp("171.67.242.68", mac1);
//    uint8_t mac2[] = { 0x00, 0x98, 0x76, 0xd8, 0x0c, 0x59 };
//    addarp("171.67.242.70", mac2);
}

void addarp(uint32_t ip, uint8_t mac[6]) {
    struct arppair *newarp = malloc(sizeof(struct arppair));
    newarp->ip = ip;
    memcpy(newarp->mac, mac, 6);
    newarp->next = cache;
    cache = newarp;
}

const uint8_t * getarp(uint32_t ip) {
    struct arppair *arpptr = cache;
    while(arpptr != NULL) {
        if(memcmp(&(arpptr->ip), &ip, sizeof(uint32_t)) == 0) {
            return arpptr->mac;
        }
        arpptr = arpptr->next;
    }
    return NULL;
} 

void delete_arpcache(void) {
    struct arppair *nextptr = cache;
    while(cache != NULL) {
        nextptr = cache->next;
        free(cache);
        cache = nextptr;
    }
}
