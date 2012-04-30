#ifndef SR_RLT_H
#define SR_RLT_H

#include "sr_router.h"

int sr_load_rlt(struct sr_instance* sr,const char* filename);

void printRuleTable(struct sr_instance* sr);

#endif
