/*-----------------------------------------------------------------------------
 * file:  sr_rlt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002  
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>



#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rlt.h"
#include "sr_router.h"

uint8_t parseShortFromString(char* src, uint len);
uint16_t parseLongFromString(char* src, uint len);
void printRuleTable(struct sr_instance* sr);

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rlt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  srcIP[32];
    char  srcPort[32];
    char  dstIP[32];
    char  dstPort[32];
    char  ipProto[32];
    //struct in_addr dest_addr;
    //struct in_addr gw_addr;
    //struct in_addr mask_addr;
    
    struct flowTableEntry *nfte = NULL; 
    struct flowTableEntry *fte = NULL; 
    
    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }
    
    fp = fopen(filename,"r");
    
    while( fgets(line,BUFSIZ,fp) != 0)
    {
        fte = malloc(sizeof(struct flowTableEntry));
        fte->srcIPw = false;
        fte->srcPortw = false;
        fte->dstIPw = false;
        fte->dstPortw = false;
        fte->ipProtow = false;
        fte->isImmortal = true;
        
        sscanf(line,"%s %s %s %s %s",srcIP,srcPort,dstIP,dstPort,ipProto);
        if (strncmp(srcIP, "*", 1) == 0) {
            fte->srcIPw = true;
        }
        else
        {
            strncpy(fte->srcIP, srcIP, 15);
        }
        
        if (strncmp(srcPort, "*", 1) == 0) {
            fte->srcPortw = true;
        }
        else
        {
            int srcPortint = parseLongFromString(srcPort, strlen(srcPort));
            fte->srcPort = srcPortint; 
        }
        
        if (strncmp(dstIP, "*", 1) == 0) {
            fte->dstIPw = true;
        }
        else
        {
            strncpy(fte->dstIP, dstIP, 15);
        }

        if (strncmp(dstPort, "*", 1) == 0) {
            fte->dstPortw = true;
        }
        else
        {
            int dstPint = parseLongFromString(dstPort, strlen(dstPort));
            fte->dstPort = dstPint;
        }
        
        if (strncmp(ipProto, "*", 1) == 0) {
            fte->ipProtow = true;
        }
        else
        {
            int ipProtint = parseShortFromString(ipProto, strlen(ipProto));
            fte->ipProtocol = ipProtint;
            
        }
        
       // parseShortFromString
        // parseLongFromString
        
       // takes char* and Uint length, call strlen 237 srrouter.c
        
        fte->next = nfte;
        nfte = fte; 
        
    }
    
    sr->flowTable = fte; 
    return 0; 
    /* -- while -- *//* -- success -- */
} /* -- sr_load_rt -- */

void printRuleTable(struct sr_instance* sr) {
    struct flowTableEntry* rule = sr->flowTable;
    while(rule != NULL) {
        Debug("Src:%s:%u\n", rule->srcIP, rule->srcPort);
        Debug("Dst:%s:%u\n", rule->dstIP, rule->dstPort);
        Debug("Proto:%u\n", rule->ipProtocol);
        rule = rule->next;
    }
}
uint8_t parseShortFromString(char* src, uint len){
    uint8_t total = 0;
    for(int i = 0; i < len; i++){
        total *= 10;
        total += src[i] - '0';
    }
    return total;
}

uint16_t parseLongFromString(char* src, uint len){
    uint16_t total = 0;
    for(int i = 0; i < len; i++){
        total *= 10;
        total += src[i] - '0';
    }
    return total;
}


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/





