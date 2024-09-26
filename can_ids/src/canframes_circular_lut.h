/*
 * canframes_circular_lut.h
 *
 *  Created on: Mar 20, 2024
 *      Author: bastien
 */

#ifndef SRC_CANFRAMES_CIRCULAR_LUT_H_
#define SRC_CANFRAMES_CIRCULAR_LUT_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PmodCAN.h"

#define TABLE_SIZE 2000

// Structure to represent an entry in the lookup table
typedef struct {
    long unsigned int key;
    CAN_Message value;
} TableEntry;

// Structure to represent the lookup table
typedef struct {
    TableEntry entries[TABLE_SIZE];
    int head; // Index of the oldest entry in the table
    int size; // Current number of entries in the table
} CAN_Circ_LookupTable;

void can_circ_lut_init(CAN_Circ_LookupTable *table);
void can_circ_lut_add(CAN_Circ_LookupTable *table, const long unsigned int *key, const CAN_Message *value);
CAN_Message can_circ_lut_getValue(CAN_Circ_LookupTable *table, const long unsigned int key);
int can_circ_lut_getValuesBelowLimit(CAN_Circ_LookupTable *table, const long unsigned int *limit, CAN_Message *results);
int can_circ_lut_getValuesBetweenLimits(CAN_Circ_LookupTable *table, const long unsigned int limit1, const long unsigned int limit2, CAN_Message *results);

#endif /* SRC_CANFRAMES_CIRCULAR_LUT_H_ */