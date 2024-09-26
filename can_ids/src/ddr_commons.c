/*
 * ddr_commons.c
 *
 *  Created on: Sep 20, 2024
 *      Author: bastien
 */

#include "ddr_commons.h"

volatile bool ddr_time_req __attribute__((section(".rx_shared")));
volatile u32 ddr_time __attribute__((section(".rx_shared")));
volatile int count __attribute__((section(".rx_shared")));

SharedBuffer shared_buffer __attribute__((section(".rx_shared"))) = {
    .head = 0,
    .tail = 0,
    .lock = ATOMIC_FLAG_INIT};

// Consume data
int consume_data(SharedBuffer *buf, CAN_Entry *data)
{
   uint32_t tail = atomic_load_explicit(&buf->tail, memory_order_relaxed);

   if (tail == atomic_load_explicit(&buf->head, memory_order_acquire))
   {
      // Buffer is empty
      return -1;
   }

   *data = buf->buffer[tail];
   atomic_store_explicit(&buf->tail, (tail + 1) % BUFFER_SIZE, memory_order_release);

   return 0;
}
