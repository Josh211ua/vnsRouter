#ifndef SR_ICMP_PROTO_H
#define SR_ICMP_PROTO_H

struct icmp_hdr
{
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint16_t icmp_ident;
    uint16_t icmp_seqnum;
} __attribute__ ((packed)) ;

#endif
