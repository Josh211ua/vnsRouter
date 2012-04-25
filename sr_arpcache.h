#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

void init_arpcache(void);

void addarp(uint32_t ip, uint8_t mac[6]);

const uint8_t * getarp(uint32_t ip);

void delete_arpcache(void);

#endif
