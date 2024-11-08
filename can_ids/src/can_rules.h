#ifndef CAN_RULES_H
#define CAN_RULES_H

#include "cansec_rules.h"

CANRule ruleTable[] = {
    { ALERT, false, 256, false, RECEIVE, {{UpLimit,"1-3|100"},{DownLimit,"0-0|150"},{Message,"Rule 1 : Alert on ID 100"},{Contains, "86"},{Length,"8"}},5},
    { ALERT, false, 255, false, RECEIVE, {{Message,"Delimiter Received\r\n"}},1},
    //{ DROP, false, 272, false, TRANSMIT, {{UpLimit,"1024"},{DownLimit,"-1024"},{Length,"8"},{Format,"FFFF0000FF00FF00"}},4},
    //{ BLOCK, false, 384, false, BIDIRECTIONAL, {{UpLimit,"512"},{DownLimit,"0"},{Message,"Alert 0x180"},{Length,"8"}},4},
};

int ruleCount = 2;

#endif // CAN_RULES_H
