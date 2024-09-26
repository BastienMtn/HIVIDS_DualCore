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

enum Action{
    ALERT,
    BLOCK,
    DROP,
    LOG,
    PASS,
    REWRITE
};

enum Direction{
    RECEIVE,
    TRANSMIT,
    BIDIRECTIONAL
};

enum OptionType{
    UpLimit,
    DownLimit,
    Format,
    Length,
    Message,
    Contains
};

typedef struct{
    enum OptionType type;
    char* value;
}CANSecOption;

typedef struct{
    enum Action action;
    bool extended;
    long unsigned int id;
    bool isRequest;
    enum Direction dir;
    CANSecOption options[10];
    int num_options;
}CANRule;

// Struct for CAN Frame, its timestmp and its direction to check for security
typedef struct CANSecExtFrame {
    long unsigned int timestp;
    enum Direction dir;
    CAN_Message msg;
} CANSecExtFrame;

// Error struct to store matching rule lines
struct Error {
    char **matchingRules;
    int count;
};

// Function to compare HTTP frame ID with Snort-like rule
bool applyRule(CANSecExtFrame frame, CANRule rule);

struct Error checkWithRules(CANSecExtFrame frame);

void splitRuleValue(char* value, char* delimiter, int64_t* options);

#endif /* SRC_CANSEC_RULES_H_ */
