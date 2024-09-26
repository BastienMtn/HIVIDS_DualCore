/*
 * ddr_commons.h
 *
 *  Created on: Sep 20, 2024
 *      Author: bastien
 */

#ifndef SRC_DDR_COMMONS_H_
#define SRC_DDR_COMMONS_H_

#include <stdatomic.h>
#include "PmodCAN.h"

#define BUFFER_SIZE 20

typedef struct
{
   u32 timestp;
   CAN_Message msg;
} CAN_Entry;

typedef struct
{
   CAN_Entry buffer[BUFFER_SIZE];
   uint32_t head;
   uint32_t tail;
   atomic_flag lock;
} SharedBuffer;

extern volatile bool ddr_time_req __attribute__((section(".rx_shared")));
extern volatile u32 ddr_time __attribute__((section(".rx_shared")));
extern volatile int count __attribute__((section(".rx_shared")));
extern SharedBuffer shared_buffer __attribute__((section(".rx_shared")));

int consume_data(SharedBuffer *buf, CAN_Entry *data);

#endif /* SRC_DDR_COMMONS_H_ */
