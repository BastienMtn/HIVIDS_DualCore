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
#include "semphr.h"
#include "task.h"

// Includes for sd card
#include "xparameters.h"
#include "xsdps.h"
#include "ff.h"
#include "xil_cache.h"
#include "xplatform_info.h"

// Includes for CANBus
#include "PmodCAN.h"
// #include "ddr_commons.h"

// Includes for IDS
#include "can_security.h"

#include "lwipopts.h"

/************************** Constant Definitions *****************************/
#define ARM1_STARTADR 0xFFFFFFF0
#define ARM1_BASEADDR 0x1FE01000
#define SD_WRITE_BUF_SIZE 1000
// #define FORMAT_SD_CARD

/**************************** Type Definitions *******************************/

/***************** Macros (Inline Functions) Definitions *********************/

#define sev() __asm__("sev")

/************************** Function Prototypes ******************************/

int sd_init();
int file_init(FIL *fil, char *FileName);
int file_save(FIL *fil);
int file_close(FIL *fil);
int SDPrintMessage(char *sdBuffer, CAN_Message message, u32 timestp, int dir);
static void saveTask(void *pvParameters);

/************************** Variable Definitions *****************************/

static TaskHandle_t xCanSaveTask, xCanSaveTask2;
static SemaphoreHandle_t DDRSem, SDSem;

static FATFS fatfs;
static FIL fil; /* File object */
/*
 * To test logical drive 0, FileName should be "0:/<File name>" or
 * "<file_name>". For logical drive 1, FileName should be "1:/<file_name>"
 */
static char FileName[32] = "logs_fpga_fuzz_5.json";
static char *SD_File;

#ifdef __ICCARM__
#pragma data_alignment = 32
u8 DestinationAddress[10 * 1024];
#pragma data_alignment = 32
u8 SourceAddress[10 * 1024];
#else
u8 DestinationAddress[10 * 1024] __attribute__((aligned(32)));
u8 SourceAddress[10 * 1024] __attribute__((aligned(32)));
#endif

char sdBuffer1[512 * SD_WRITE_BUF_SIZE], sdBuffer2[512 * SD_WRITE_BUF_SIZE];

PmodCAN myDevice;

u32 local_time = 0;

/********************************** Code *************************************/

int main()
{
   // Disable cache on OCM
   //  S=b1 TEX=b100 AP=b11, Domain=b1111, C=b0, B=b0
   Xil_SetTlbAttributes(0xFFFF0000, 0x14de2);

   atomic_store(&ddr_time_req, 0);
   atomic_store(&ddr_time, 0);

   xil_printf("ARM0: writing startaddress for ARM1\n\r");
   Xil_Out32(ARM1_STARTADR, ARM1_BASEADDR);
   dmb(); // waits until write has finished

   xil_printf("ARM0: sending the SEV to wake up ARM1\n\r");
   sev();

   DDRSem = xSemaphoreCreateMutex();
   if (DDRSem == NULL)
   {
      /* There was insufficient FreeRTOS heap available for the semaphore to
      be created successfully. */
      xil_printf("Error initializing DDRSem\r\n");
   }

   SDSem = xSemaphoreCreateMutex();
   if (SDSem == NULL)
   {
      /* There was insufficient FreeRTOS heap available for the semaphore to
         be created successfully. */
      xil_printf("Error initializing SDSem\r\n");
   }

   int status = sd_init();
   if (status != XST_SUCCESS)
   {
      xil_printf("SD Card init failed \r\n");
      return -1;
   }

   status = file_init(&fil, FileName);

   sys_thread_new("cansec_thrd", (void (*)(void *))can_security_init, 0,
				   TCPIP_THREAD_STACKSIZE*2,
				   DEFAULT_THREAD_PRIO);

   //can_security_init();

   xTaskCreate(saveTask,
               (const char *)"SD1",
               configMINIMAL_STACK_SIZE * 8,
               NULL,
               tskIDLE_PRIORITY + 1,
               &xCanSaveTask);

   xTaskCreate(saveTask,
               (const char *)"SD2",
               configMINIMAL_STACK_SIZE * 8,
               NULL,
               tskIDLE_PRIORITY + 1,
               &xCanSaveTask2);

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

// Task to receive messages from DDR and saving them to SD card
static void saveTask(void *pvParameters)
{
   const char *taskName = pcTaskGetName(NULL);
   xil_printf("SaveTask %s launched\r\n", taskName);
   char *sdBuffer;
   if (strcmp(taskName, "SD1"))
   {
      sdBuffer = sdBuffer1;
   }
   else
   {
      sdBuffer = sdBuffer2;
   }
   CAN_Entry data;
   CANSecExtFrame frame;
   frame.dir = RECEIVE;
   int total_frames = 0;
   xSemaphoreTake(DDRSem, portMAX_DELAY);
   xil_printf("%s Took DDRSem\r\n", taskName);
   while (1)
   {
      if (consume_data(&shared_buffer, &data) == 0)
      {
         // xil_printf("frame received...");
         frame.timestp = data.timestp;
         frame.msg = data.msg;
         can_security_store(frame);
         SDPrintMessage(sdBuffer, data.msg, data.timestp, 0);
         // xil_printf("Frame printed \r\n");
         total_frames++;
         if (total_frames % SD_WRITE_BUF_SIZE == 0)
         {
            xSemaphoreGive(DDRSem);
            unsigned int NumBytesWritten;
            xSemaphoreTake(SDSem, portMAX_DELAY);
            f_write(&fil, sdBuffer, strlen(sdBuffer), &NumBytesWritten);
            file_save(&fil);
            xSemaphoreGive(SDSem);
            sdBuffer[0] = '\0';
            xil_printf("Task : %s / Total frames = %d \r\n", taskName, total_frames);
            xSemaphoreTake(DDRSem, portMAX_DELAY);
         }
         /*
         if(total_frames == 2000){
          xil_printf("received 2000 frames\r\n");
          file_close(&fil);
         }
         */
      }
      // xil_printf("Count = %d \r\n", count);
   }
}

int sd_init()
{
   FRESULT Res;

   /*
    * To test logical drive 0, Path should be "0:/"
    * For logical drive 1, Path should be "1:/"
    */
   TCHAR *Path = "0:/";

   /*
    * Register volume work area, initialize device
    */
   Res = f_mount(&fatfs, Path, 0);

   if (Res != FR_OK)
   {
      return XST_FAILURE;
   }
   xil_printf("SD Volume mounted\r\n");

#ifdef FORMAT_SD_CARD
   BYTE work[FF_MAX_SS];
   /*
    * Path - Path to logical driver, 0 - FDISK format.
    * 0 - Cluster size is automatically determined based on Vol size.
    */
   Res = f_mkfs(Path, FM_FAT32, 0, work, sizeof work);
   if (Res != FR_OK)
   {
      return XST_FAILURE;
   }
   xil_printf("SD Volume Formatted\r\n");
#endif
   return XST_SUCCESS;
}

int file_init(FIL *fil, char *FileName)
{
   FRESULT Res;
   /*
    * Open file with required permissions.
    * Here - Creating new file with read/write permissions. .
    * To open file with write permissions, file system should not
    * be in Read Only mode.
    */
   SD_File = (char *)FileName;

   Res = f_open(fil, SD_File, FA_OPEN_APPEND | FA_WRITE | FA_READ);
   if (Res)
   {
      xil_printf("f_open failed with Res = %d \r\n", Res);
      return XST_FAILURE;
   }

   xil_printf("Log file %s ready to write...\r\n", FileName);

   return XST_SUCCESS;
}

int file_save(FIL *fil)
{
   FRESULT Res;
   /*
    * Synchronize file.
    */
   Res = f_sync(fil);
   ;
   if (Res)
   {
      xil_printf("f_sync failed with Res = %d \r\n", Res);
      return XST_FAILURE;
   }
   // xil_printf("File saved \r\n");
   return XST_SUCCESS;
}

int file_close(FIL *fil)
{
   FRESULT Res;
   /*
    * Close file.
    */
   Res = f_close(fil);
   if (Res)
   {
      return XST_FAILURE;
   }
   xil_printf("File closed\r\n");
   return XST_SUCCESS;
}

// Save data to SD CARD
int SDPrintMessage(char *sdBuffer, CAN_Message message, u32 timestp, int dir)
{
   //   FRESULT Res;
   //   UINT NumBytesWritten;
   /*
    * Write data to file.
    */
   static char text[512] = "", strapp[256];
   snprintf(strapp, 256, "{\r\n    \"timestamp\": %ld,\r\n    \"direction\": %s,\r\n    \"can_id\": \"0x%03X\",\r\n    \"extended_id\": \"0x%05lX\",\r\n    \"ide\": %u,\r\n    \"rtr\": %u,\r\n    \"dlc\": %u,\r\n    \"data\": [", timestp, dir == 0 ? "\"received\"" : "\"sent\"",
            message.id, message.eid, message.ide, message.rtr, message.dlc);
   strcat(text, strapp);
   for (int i = 0; i < message.dlc; i++)
   {
      if (i < (message.dlc - 1))
      {
         snprintf(strapp, 10, "\"0x%02X\", ", message.data[i]);
      }
      else
      {
         snprintf(strapp, 10, "\"0x%02X\"", message.data[i]);
      }
      strcat(text, strapp);
   }
   snprintf(strapp, 16, "]\r\n},\r\n");
   strcat(text, strapp);
   // Res = f_write(fil, (const void *)text, strlen(text), &NumBytesWritten);
   strcat(sdBuffer, text);
   text[0] = '\0';
   //   if (Res)
   //   {
   //      return XST_FAILURE;
   //   }

   // xil_printf("Write done\r\n");

   return XST_SUCCESS;
}
