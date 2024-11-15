/*
 * cansec_rules.h
 *
 *  Created on: Jul 8, 2024
 *      Author: bastien
 */

#ifndef SRC_CANSEC_RULES_H_
#define SRC_CANSEC_RULES_H_

#include "PmodCAN.h"
#include "xil_cache.h"
#include "xparameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RULE_LENGTH 256
#define MAX_LINE_LENGTH 1024
#define MAX_RULES 100

#define DELIMITER "-|"

typedef enum{
    ALERT,
    BLOCK,
    DROP,
    LOG,
    PASS,
    REWRITE
} Action;

typedef enum{
    RECEIVE,
    TRANSMIT,
    BIDIRECTIONAL
} Direction;

typedef enum{
    UpLimit,
    DownLimit,
    Format,
    Length,
    Message,
    Contains
} OptionType;

typedef struct{
    OptionType type;
    char* value;
} CANSecOption;

typedef struct{
    Action action;
    bool extended;
    long unsigned int id;
    bool isRequest;
    Direction dir;
    CANSecOption options[10];
    int num_options;
}CANRule;

// Struct for CAN Frame, its timestmp and its direction to check for security
typedef struct {
    long unsigned int timestp;
    Direction dir;
    CAN_Message msg;
} CANSecExtFrame;

// Error struct to store matching rule line
typedef struct {
    char matchingRules[MAX_RULES];
    int count;
} Error;

// Function to compare HTTP frame ID with Snort-like rule
bool applyRule(CANSecExtFrame frame, CANRule rule);

Error checkWithRules(CANSecExtFrame frame);

void splitRuleValue(char* value, char* delimiter, int64_t* options);

#endif /* SRC_CANSEC_RULES_H_ */
