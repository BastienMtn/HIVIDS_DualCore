/******************************************************************************
 *
 * Copyright (C) 2009 - 2014 Xilinx, Inc.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Use of the Software is limited solely to applications:
 * (a) running on a Xilinx device, or
 * (b) that interact with a Xilinx device through a bus or interconnect.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
 * OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Except as contained in this notice, the name of the Xilinx shall not be used
 * in advertising or otherwise to promote the sale, use or other dealings in
 * this Software without prior written authorization from Xilinx.
 *
 ******************************************************************************/

/*
 * This application configures UART 16550 to baud rate 9600.
 * PS7 UART (Zynq) is not initialized by this application, since
 * bootrom/bsp configures it to baud rate 115200
 *
 * ------------------------------------------------
 * | UART TYPE   BAUD RATE                        |
 * ------------------------------------------------
 *   uartns550   9600
 *   uartlite    Configurable only in HW design
 *   ps7_uart    115200 (configured by bootrom/bsp)
 */

/***************************** Include Files *********************************/

#include <stdio.h>
#include <sleep.h>
#include <stdatomic.h>
#include "xil_io.h"
#include "xil_mmu.h"
#include "xil_printf.h"
#include "xpseudo_asm.h"
#include "xil_exception.h"
#include "FreeRTOS.h"
#include "task.h"

/*
#include "xil_cache.h"
#include "xparameters.h"
*/

// Includes for CANBus
#include "PmodCAN.h"

/************************** Constant Definitions *****************************/

#define CPU_CLOCK_HZ (650000000) // Replace with your actual CPU clock frequency
#define TICK_RATE_HZ (configTICK_RATE_HZ)
#define BUFFER_SIZE 20
#define SD_DEVICE_ID XPAR_XSDPS_0_DEVICE_ID
#define PYNQZ2
/**************************** Type Definitions *******************************/

typedef struct
{
	u32 timestp;
	CAN_Message msg;
} CAN_Entry;

typedef struct
{
	CAN_Entry buffer[BUFFER_SIZE];
	_Atomic uint32_t head;
	_Atomic uint32_t tail;
	atomic_flag lock;
} SharedBuffer;

/***************** Macros (Inline Functions) Definitions *********************/

/************************** Function Prototypes ******************************/

int produce_data(SharedBuffer *buf, CAN_Entry *data);
void DemoInitialize();
void DemoRun();
void DemoCleanup();
void EnableCaches();
void DisableCaches();
u8 isInPrivilegedMode(void);
void enable_pmu_and_counters();
void resetCycleCounter(void);
void disable_pmu_and_counters();
unsigned int read_cycle_counter();
u32 getHighPrecisionTimestamp(void);
static void mainTask(void *pvParameters);

/************************** Variable Definitions *****************************/

extern u32 MMUTable;

volatile bool ddr_time_req __attribute__((section(".rx_shared")));
volatile u32 ddr_time __attribute__((section(".rx_shared")));
volatile int count __attribute__((section(".rx_shared")));

SharedBuffer shared_buffer __attribute__((section(".rx_shared"))) = {
	.head = 0,
	.tail = 0,
	.lock = ATOMIC_FLAG_INIT};

PmodCAN myDevice;

static TaskHandle_t xMainTask;

/********************************** Code *************************************/

int main()
{
	xil_printf("CPU1: init_platform\n\r");

	// Disable cache on OCM
	//  S=b1 TEX=b100 AP=b11, Domain=b1111, C=b0, B=b0
	Xil_SetTlbAttributes(0xFFFF0000, 0x14de2);

	xil_printf("Privilege mode : %s \r\n", isInPrivilegedMode()? "True":"False");

	enable_pmu_and_counters();

	xil_printf("Privilege mode : %s \r\n", isInPrivilegedMode()? "True":"False");

	atomic_store(&count, 0);
	xil_printf("Count = %d \r\n", count);

	xTaskCreate(mainTask,
	      				(const char *)"main",
	      				configMINIMAL_STACK_SIZE * 8,
	      				NULL,
	      				tskIDLE_PRIORITY + 1,
	      				&xMainTask);

	   /* Start the tasks and timer running. */
	   	vTaskStartScheduler();

	   	/* If all is well, the scheduler will now be running, and the following line
	   	will never be reached.  If the following line does execute, then there was
	   	insufficient FreeRTOS heap memory available for the idle and/or timer tasks
	   	to be created.  See the memory management section on the FreeRTOS web site
	   	for more details. */
	   	for (;;)
	   		;

	return 0;
}

static void mainTask(void *pvParameters){
	DemoInitialize();

	DemoRun();

	DemoCleanup();
}

// Produce data
int produce_data(SharedBuffer *buf, CAN_Entry *data)
{
	static int missed_frames = 0;
	uint32_t head = atomic_load_explicit(&buf->head, memory_order_relaxed);
	uint32_t next_head = (head + 1) % BUFFER_SIZE;

	if (next_head == atomic_load_explicit(&buf->tail, memory_order_acquire))
	{
		// Buffer is full
		missed_frames++;
		xil_printf("DDR BUFFER IS FULL : %d missed frames \r\n", missed_frames);
		return -1;
	}

	buf->buffer[head] = *data;
	atomic_store_explicit(&buf->head, next_head, memory_order_release);

	return 0;
}

void DemoInitialize()
{
	EnableCaches();
	CAN_begin(&myDevice, XPAR_PMODCAN_0_AXI_LITE_GPIO_BASEADDR,
			  XPAR_PMODCAN_0_AXI_LITE_SPI_BASEADDR);
	CAN_Configure(&myDevice, CAN_ModeNormalOperation);
}

void DemoRun()
{
	CAN_Message RxMessage;
	CAN_RxBuffer target;
	u8 status;
	u8 rx_int_mask;

	xil_printf("Welcome to the PmodCAN IP Core Receive Demo\r\n");

	while (1)
	{
		do
		{
			status = CAN_ReadStatus(&myDevice);
			// xil_printf("Waiting to receive\r\n");
			if(atomic_load(&ddr_time_req) == 1){
				u32 slave_time = getHighPrecisionTimestamp();
				//xil_printf("Slave time is %d \r\n", slave_time);
				atomic_store(&ddr_time, slave_time);
				atomic_store(&ddr_time_req,0);
			}
		} while ((status & CAN_STATUS_RX0IF_MASK) == 0 && (status & CAN_STATUS_RX1IF_MASK) == 0);

		u32 timestp = getHighPrecisionTimestamp();

		switch (status & 0x03)
		{
		case 0b01:
		case 0b11:
			// xil_printf("fetching message from receive buffer 0\r\n");
			target = CAN_Rx0;
			rx_int_mask = CAN_CANINTF_RX0IF_MASK;
			break;
		case 0b10:
			// xil_printf("fetching message from receive buffer 1\r\n");
			target = CAN_Rx1;
			rx_int_mask = CAN_CANINTF_RX1IF_MASK;
			break;
		default:
			// xil_printf("Error, message not received\r\n");
			continue;
		}

		CAN_ReceiveMessage(&myDevice, &RxMessage, target);

		CAN_Entry data = {
			.timestp = timestp,
			.msg = RxMessage,
		};

		produce_data(&shared_buffer, &data);

		CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, rx_int_mask, 0);

		if (RxMessage.id == 0x0 || RxMessage.id == 0x200 || RxMessage.id == 0x400 || RxMessage.id == 0x600 || RxMessage.id == 0x7ff)
		{
			// xil_printf("Waiting to send\r\n");
			do
			{
				status = CAN_ReadStatus(&myDevice);
			} while ((status & CAN_STATUS_TX0REQ_MASK) != 0); // Wait for buffer 0 to be clear

			CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX0IF_MASK, 0);

			// xil_printf("requesting to transmit message through transmit buffer 0 \r\n");

			u32 delay = getHighPrecisionTimestamp() - timestp;
			//xil_printf("Delay = %d", delay);

			for (int i = 0; i < 8; i++)
			{
				if (i < 4)
				{
					RxMessage.data[i] = delay >> i * 8;
				}
				else
				{
					RxMessage.data[i] = 0;
				}
			}

			CAN_SendMessage(&myDevice, RxMessage, CAN_Tx0);

			CAN_ModifyReg(&myDevice, CAN_CANINTF_REG_ADDR, CAN_CANINTF_TX0IF_MASK, 0);

			do
			{
				status = CAN_ReadStatus(&myDevice);
				// xil_printf("Waiting to complete transmission\r\n");
			} while ((status & CAN_STATUS_TX0IF_MASK) != 0); // Wait for message to transmit successfully
			// xil_printf("Message sent\n");
		}

		// xil_printf("received ");
		// DemoPrintMessage(RxMessage);
		count++;
		// xil_printf("Count = %d", count);

		// sleep(1);
	}
}

void DemoCleanup()
{
	CAN_end(&myDevice);
	DisableCaches();
}

// Hook function that is called on each tick interrupt
void vApplicationTickHook(void)
{
	resetCycleCounter();
	//xil_printf("Cycles = %d \r\n", read_cycle_counter());
}

u8 isInPrivilegedMode(void)
{
#ifdef PYNQZU
    uint32_t control;
    __asm volatile ("MRS %0, CONTROL" : "=r" (control)); // Read the CONTROL register
    return (control & 0x1) == 0;  // Check the nPRIV bit (Bit 0)
#endif
#ifdef PYNQZ2
    uint32_t mode;
        __asm volatile (
            "MRS %0, CPSR" // Read the CPSR register into the output variable
            : "=r" (mode)  // Output operand: store result in `mode`
            :              // No input operands
            :              // No clobbered registers
        );
        if((mode & 0x1F)!=0x10){
        	return 1; // Mask out the mode bits (bits 0-4)
        }else{
        	return 0;
        }
#endif
}


// Enable the PMU and cycle counter on the running core (core 1)
void enable_pmu_and_counters() {
	/*
    // Enable user mode access to the performance counters on this core
    asm volatile ("MRC p15, 0, r0, c9, c14, 0");
    asm volatile ("ORR r0, r0, #1");
    asm volatile ("MCR p15, 0, r0, c9, c14, 0");

    // Enable the PMU and reset all counters on this core
    asm volatile ("MRC p15, 0, r0, c9, c12, 0");
    asm volatile ("ORR r0, r0, #5"); // Enable cycle counter and event counters
    asm volatile ("MCR p15, 0, r0, c9, c12, 0");

    // Reset the cycle counter on this core
    asm volatile ("MCR p15, 0, r0, c9, c12, 2");

    // Enable the cycle counter on this core
    asm volatile ("MCR p15, 0, r0, c9, c12, 1");
    */
#ifdef PYNQZU
	// Enable user access to the performance counter (Control Register)
	__asm volatile ("MCR p15, 0, %0, c9, c14, 0" : : "r"(1));

	// Reset the cycle counter (Cycle Counter Register)
	__asm volatile ("MCR p15, 0, %0, c9, c12, 0" : : "r"(2));

	// Enable all counters including the cycle counter (Control Register)
	__asm volatile ("MCR p15, 0, %0, c9, c12, 1" : : "r"(1 << 31));
#endif
#ifdef PYNQZ2
	// Set PMUSERENR (User Enable Register) to allow user access to PMU
	    __asm volatile (
	        "MRC p15, 0, r0, c9, c14, 0\n" // Read PMUSERENR register into r0
	        "ORR r0, r0, #1\n"             // Set the EN bit (bit 0) to enable user access
	        "MCR p15, 0, r0, c9, c14, 0\n" // Write back to PMUSERENR register
	        :
	        :
	        : "r0"
	    );
	    // Enable PMU counters, reset the cycle counter, and enable the cycle counter specifically
	        __asm volatile (
	            "MRC p15, 0, r0, c9, c12, 0\n" // Read PMCR (Performance Monitor Control Register) into r0
	            "ORR r0, r0, #1\n"             // Set bit 0 to enable all counters
	            "MCR p15, 0, r0, c9, c12, 0\n" // Write back to PMCR
	            "MOV r0, #0x8000000f\n"        // Set bits for enabling cycle counter reset and enable
	            "MCR p15, 0, r0, c9, c12, 1\n" // Write to PMCNTENSET to enable the cycle counter
	            :
	            :
	            : "r0"
	        );
#endif
}

// Function to reset the cycle counter on Cortex-A9
void resetCycleCounter(void) {
#ifdef PYNQZ2
    __asm volatile (
            "MCR p15, 0, r0, c9, c12, 2\n" // Write 0 to PMCR to reset all counters
            "MOV r0, #0x00000007\n"        // Reset and enable the cycle counter and event counters
            "MCR p15, 0, r0, c9, c12, 0\n" // Write to PMCR to reset and enable
            :
            :
            : "r0"
        );
#endif
#ifdef PYNQZU
    // Reset the cycle counter to zero on each tick
    __asm volatile ("MCR p15, 0, %0, c9, c12, 0" : : "r"(2)); // Reset cycle counter
#endif
}

// Disable the PMU counters on this core (optional)
void disable_pmu_and_counters() {
#ifdef PYNQZU
    // Disable all counters on the running core
    asm volatile ("MRC p15, 0, r0, c9, c12, 0");
    asm volatile ("BIC r0, r0, #1"); // Disable cycle counter
    asm volatile ("MCR p15, 0, r0, c9, c12, 0");
#endif
}

// Read the cycle counter on the running core
unsigned int read_cycle_counter() {
    unsigned int cycle_count;
#ifdef PYNQZU
    asm volatile ("MRC p15, 0, %0, c9, c13, 0" : "=r" (cycle_count));
#endif
#ifdef PYNQZ2
    __asm volatile (
           "MRC p15, 0, %0, c9, c13, 0\n" // Read CCNT (Cycle Counter Register) into the output variable
           : "=r" (cycle_count)            // Output register
       );
#endif
    return cycle_count;
}

u32 getHighPrecisionTimestamp(void)
{
    u32 ticks = xTaskGetTickCount();           // Get the number of FreeRTOS ticks
    //xil_printf("ticks : %d \r\n",ticks);
    u64 cycles = read_cycle_counter();            // Get the number of cycles since the last tick

    u32 tickDurationUs = 1000000 / TICK_RATE_HZ; // Tick duration in microseconds
    u32 timestampUs = (ticks * tickDurationUs) + ((cycles * 1000000) / CPU_CLOCK_HZ);
    //u32 timestampUs = (cycles * 1000000) / CPU_CLOCK_HZ;
    return timestampUs;
}


void EnableCaches()
{
#ifdef __MICROBLAZE__
#ifdef XPAR_MICROBLAZE_USE_ICACHE
	Xil_ICacheEnable();
#endif
#ifdef XPAR_MICROBLAZE_USE_DCACHE
	Xil_DCacheEnable();
#endif
#endif
}

void DisableCaches()
{
#ifdef __MICROBLAZE__
#ifdef XPAR_MICROBLAZE_USE_DCACHE
	Xil_DCacheDisable();
#endif
#ifdef XPAR_MICROBLAZE_USE_ICACHE
	Xil_ICacheDisable();
#endif
#endif
}
