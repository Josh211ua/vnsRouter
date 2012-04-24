#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

void init_arpcache(void);

void addarp(char ip[15], uint8_t mac[6]);

const uint8_t * getarp(char ip[15]);

void delete_arpcache(void);

#endif
