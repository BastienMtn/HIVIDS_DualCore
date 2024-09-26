/*
 * canframes_circular_lut.c
 *
 *  Created on: Mar 20, 2024
 *      Author: bastien
 */

#include "canframes_circular_lut.h"

// Function to initialize the lookup table
void can_circ_lut_init(CAN_Circ_LookupTable *table) {
    table->head = 0;
    table->size = 0;
}

// Function to add an entry to the lookup table
void can_circ_lut_add(CAN_Circ_LookupTable *table, const long unsigned int *key, const CAN_Message *msg) {
    int index = (table->head + table->size) % TABLE_SIZE;
    table->entries[index].key = *key;
    
    table->entries[index].value.id =  msg->id;
    table->entries[index].value.eid = msg->eid;
    table->entries[index].value.ide = msg->ide;
    table->entries[index].value.rtr = msg->rtr;
    table->entries[index].value.srr = msg->srr;
    table->entries[index].value.dlc = msg->dlc;

    for(int i=0; i<table->entries[index].value.dlc; i++){
        table->entries[index].value.data[i] = msg->data[i];
    }

    // table->entries[index].value = *value;
    /*
    memcpy(&table->entries[index].key, key, sizeof(long int));
    memcpy(&table->entries[index].value, value, sizeof(struct CAN_Message));
    */


    if (table->size < TABLE_SIZE) {
        table->size++;
    } else {
        // If the table is full, update the head to point to the next oldest entry
        table->head = (table->head + 1) % TABLE_SIZE;
    }
}

// Function to retrieve a value from the lookup table based on a key
CAN_Message can_circ_lut_getValue(CAN_Circ_LookupTable *table, const long unsigned int key) {
    for (int i = 0; i < table->size; i++) {
        int index = (table->head + i) % TABLE_SIZE;
        if (table->entries[index].key == key) {
            return table->entries[index].value;
        }
    }
    return ; // Key not found
}

// Function to retrieve values from the lookup table with keys inferior to the limit value
int can_circ_lut_getValuesBelowLimit(CAN_Circ_LookupTable *table, const long unsigned int *limit, CAN_Message *results) {
    int count = 0;
    for (int i = 0; i < table->size; i++) {
        int index = (table->head + i) % TABLE_SIZE;
        if (table->entries[index].key < *limit) {
            results[count]=table->entries[index].value;
            count++;
        }
    }
    return count;
}

// Function to retrieve values from the lookup table with keys inferior to the limit value
int can_circ_lut_getValuesBetweenLimits(CAN_Circ_LookupTable *table, const long unsigned int limit1, const long unsigned int limit2, CAN_Message *results) {
    int count = 0;
    for (int i = 0; i < table->size; i++) {
        int index = (table->head + i) % TABLE_SIZE;
        if (table->entries[index].key < limit2 && table->entries[index].key > limit1) {
            results[count]=table->entries[index].value;
            count++;
        }
    }
    return count;
}

// Useless here, should be removed when possible
int can_circ_lut_main() {
    CAN_Circ_LookupTable table;
    can_circ_lut_init(&table);

    return 0;
}