/*
 * can_security.c
 *
 *  Created on: Mar 5, 2024
 *      Author: bastien
 */

#include "can_security.h"

// Includes for lwip
#include "FreeRTOSConfig.h"
#include "lwip/sockets.h"
#include "lwipopts.h"
#include "lwip/sys.h"

#include "netif/xadapter.h"
#include "platform_config.h"

#if LWIP_IPV6 == 1
#include "lwip/ip.h"
#else
#if LWIP_DHCP == 1
#include "lwip/dhcp.h"
#endif
#endif

#define LWIP_DEBUG
#define MAX_CONNECTIONS 8
int new_sd[MAX_CONNECTIONS];
int connection_index;

u16_t echo_port = 7;

static struct netif server_netif;

static TaskHandle_t xCanSecTask;
// Global variable to store most recent sent frames
CAN_Circ_LookupTable rx_lut1, rx_lut2;
static bool writeRXLut1 = true;
static SemaphoreHandle_t rx_lut_write;
// Global variable to store most recent transmitted frames
CAN_Circ_LookupTable tx_lut;
// Global floats containing the bandwidths, and the sending latency for IDs 0,512,1024,1536,2048
float rx_bndw[HISTORY_SIZE], tx_bndw[HISTORY_SIZE], tx_latency[5];
static struct Bandwidths bndwth;
static float rx_bd_mean = 0.0, rx_bd_sd = 0.0, rx_bd_var = 0.0;
// Rates for each CAN ID
RateLUT rates[TABLE_SIZE];
RateLUT mean_rates_kmown_IDs[12];
RateLUT sd_rates_known_IDs[12];
RateLUT rates_hist_known_IDs[12][HISTORY_SIZE];
// Int to refresh the latency every 5 seconds only
int latency_refresh_count;
// Mutexes to protect the LUTs containing the sent and received frames
// sys_mutex_t rx_lut_mut;
// sys_mutex_t tx_lut_mut;

static void secTask(void *pvParameters)
{
    while (1)
    {
        xTaskNotifyWait(0,0,NULL,portMAX_DELAY);
        // ----- BANDWIDTH MEASUREMENT PART -----
        bndwth = bandwidth_measurement();
        // We have to adapt the value if we want to have the right print output because xil_printf does not support floats
        int rx_whole, rx_thousandths, tx_whole, tx_thousandths;
        rx_whole = bndwth.rx_bndwth;
        rx_thousandths = (bndwth.rx_bndwth - rx_whole) * 1000;
        tx_whole = bndwth.tx_bndwth;
        tx_thousandths = (bndwth.tx_bndwth - tx_whole) * 1000;
        xil_printf("Bandwidths : RX = %d.%3d / TX = %d.%3d \r\n", rx_whole, rx_thousandths, tx_whole, tx_thousandths);
        int mean_whole, mean_thousandths, sd_whole, sd_thousandths, var_whole, var_thousandths;
        mean_whole = rx_bd_mean;
        mean_thousandths = (rx_bd_mean - mean_whole) * 1000;
        sd_whole = rx_bd_sd;
        sd_thousandths = (rx_bd_sd - sd_whole) * 1000;
        var_whole = rx_bd_var;
        var_thousandths = (rx_bd_var - var_whole) * 1000;
        xil_printf("Rx bandwidth mean = %d.%3d / SD = %d.%3d / VAR = %d.%3d \r\n", mean_whole, mean_thousandths, sd_whole, sd_thousandths, var_whole, var_thousandths);

        // ----- RATE MEASUREMENT PART -----
        int rate_size = can_rate_msrmnt();

        // ----- LATENCY MEASUREMENT PART -----
        // TODO Find a replacement for this or delete it
        /*
        latency_refresh_count++;
        if (latency_refresh_count == 10)
        {
            latency_send_measurement();
            for (int i = 0; i < 5; i++)
            {
                xil_printf("TX Latency %d = %d \r\n", i, tx_latency[i]);
            }
            latency_refresh_count = 0;
        }
        */

        // ----- ATTACK DETECTION PART -----
        if (DOS_detection())
        {
            xil_printf("----------------------A DOS attack has been detected--------------------------- \r\n");
        }
    }
}

static void vTimerCbMetricsRefresh(TimerHandle_t timer)
{
    //xil_printf("Notifying metrics refresh \r\n");
    xTaskNotify(xCanSecTask,0,eNoAction);
}

long unsigned int cansec_gettime()
{
    atomic_store(&ddr_time_req, 1);
    while (atomic_load(&ddr_time_req) == 1)
    {
    };
    u32 local_time = atomic_load(&ddr_time);
    // xil_printf("Local time is %ld\r\n", local_time);
    return local_time;
}

void can_security_store(CANSecExtFrame frame)
{
    // TODO: Add info on whether the frame has passed, been dropped, blocked, etc ??
    checkWithRules(frame);
    if (frame.dir == RECEIVE)
    {
        xSemaphoreTake(rx_lut_write, portMAX_DELAY);
        if (writeRXLut1)
        {
            can_circ_lut_add(&rx_lut1, &(frame.timestp), &(frame.msg));
            // xil_printf("Time : %d | Adding to rx lut | New rx_lut size : %d | Id = %x \r\n", frame.timestp, rx_lut1.size, frame.msg.id);
            writeRXLut1 = false;
            can_circ_lut_add(&rx_lut2, &(frame.timestp), &(frame.msg));
            // xil_printf("Time : %d | Adding to rx lut | New rx_lut size : %d | Id = %x \r\n", frame.timestp, rx_lut2.size, frame.msg.id);
        }
        else
        {
            can_circ_lut_add(&rx_lut2, &(frame.timestp), &(frame.msg));
            // xil_printf("Time : %d | Adding to rx lut | New rx_lut size : %d | Id = %x\r\n", frame.timestp, rx_lut2.size, frame.msg.id);
            writeRXLut1 = true;
            can_circ_lut_add(&rx_lut1, &(frame.timestp), &(frame.msg));
            // xil_printf("Time : %d | Adding to rx lut | New rx_lut size : %d | Id = %x \r\n", frame.timestp, rx_lut1.size, frame.msg.id);
        }

        /*CAN_Message msg =  can_circ_lut_getValue(&rx_lut, frame.timestp);
        can_print_message(msg);*/
        xSemaphoreGive(rx_lut_write);
    }
    else
    {
        // sys_mutex_lock(&tx_lut_mut);
        can_circ_lut_add(&tx_lut, &(frame.timestp), &(frame.msg));
        // sys_mutex_unlock(&tx_lut_mut);
        xil_printf("Time : %d | Adding to tx lut | New tx_lut size : %d \r\n", frame.timestp, tx_lut.size);
        /*CAN_Message msg =  can_circ_lut_getValue(&tx_lut, frame.timestp);
        can_print_message(msg);*/
    }
}

// TODO: DOS Detection
// Mean, standard deviation
bool DOS_detection()
{
    /*if(bndwth.rx_bndwth > rx_bd_mean*5){
        return true;
    }*/
    if (bndwth.rx_bndwth > rx_bd_mean + 3 * rx_bd_sd)
    {
        return true;
    }
    return false;
}

// TODO: Data consistency check
// If a node sends a speed of 100kmh, check with the other nodes if its realistic (for example different wheels)
// Also work for oss/iss, app and rpm, etc

// TODO: Period deviation measurement for each known ID

// TODO: Node Isolation mechanism ?

// TODO: Spoof detection??

// TODO: Flood detection (needs a way to store the rates of the knowm IDs)
bool flood_detection()
{
    bool resp = false;
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (rates[i].value > 1)
        {
            xil_printf("----------------------Flooding detected on ID %x--------------------------- \r\n", rates[i].key);
            resp = true;
        }
    }
    return resp;
}

// ! The bandwidth only takes the real data part of the frame into account, since the rest depends on stuff bits etc !
struct Bandwidths bandwidth_measurement()
{
    int count = 0, total_datalength = 0;
    static int index = 0;
    static bool isFull = false;
    static CAN_Message data[TABLE_SIZE];
    int my_time = cansec_gettime();
    // data = malloc(TABLE_SIZE*sizeof(CAN_Message));
    if (writeRXLut1)
    {
        count = can_circ_lut_getValuesBetweenLimits(&rx_lut2, (my_time - CANSEC_BNDW_SAMPLE_SIZE * 1000), my_time, data);
    }
    else
    {
        count = can_circ_lut_getValuesBetweenLimits(&rx_lut1, (my_time - CANSEC_BNDW_SAMPLE_SIZE * 1000), my_time, data);
    }
    for (int i = 0; i < count; i++)
    {
        // xil_printf("Frame in rx lut n%d has ID %X and size %d \r\n",i,data[i].id,data[i].dlc);
        total_datalength += data[i].dlc;
    };
    // xil_printf("RX TOTAL DATALENGTH = %d \r\n", total_datalength);
    rx_bndw[index] = (float)total_datalength * 1000 / CANSEC_BNDW_SAMPLE_SIZE;

    total_datalength = 0;
    // sys_mutex_lock(&tx_lut_mut);
    count = can_circ_lut_getValuesBetweenLimits(&tx_lut, (my_time - CANSEC_BNDW_SAMPLE_SIZE * 1000), my_time, data);
    // sys_mutex_unlock(&tx_lut_mut);
    for (int i = 0; i < count; i++)
    {
        // xil_printf("Frame in tx lut n%d has ID %X and size %d \r\n",i,data[i].id,data[i].dlc);
        total_datalength += data[i].dlc;
    };
    // xil_printf("TX TOTAL DATALENGTH = %d \r\n", total_datalength);
    tx_bndw[index] = (float)total_datalength * 1000 / CANSEC_BNDW_SAMPLE_SIZE;
    struct Bandwidths resp;
    resp.rx_bndwth = rx_bndw[index];
    resp.tx_bndwth = tx_bndw[index];

    if (isFull)
    {
        rx_bd_mean = calculateMEAN(rx_bndw, HISTORY_SIZE);
        rx_bd_var = calculateVAR(rx_bndw, HISTORY_SIZE);
        rx_bd_sd = calculateSD(rx_bndw, HISTORY_SIZE);
    }
    else
    {
        rx_bd_mean = calculateMEAN(rx_bndw, index);
        rx_bd_var = calculateVAR(rx_bndw, index);
        rx_bd_sd = calculateSD(rx_bndw, index);
    }
    if (isFull == false && index == (HISTORY_SIZE - 1))
        isFull = true;
    index = (index + 1) % HISTORY_SIZE;
    return resp;
}

// Latency measurement function, a bit useless for now as the timing isnt precise enough to measure the latency in ms or ns
/*
void latency_send_measurement()
{
    CAN_Message msg;
    msg.id = 0;
    msg.dlc = 6;
    msg.eid = 0x15a;
    msg.rtr = 0;
    msg.ide = 0;
    msg.data[0] = 0x01;
    msg.data[1] = 0x02;
    msg.data[2] = 0x04;
    msg.data[3] = 0x08;
    msg.data[4] = 0x10;
    msg.data[5] = 0x20;
    msg.data[6] = 0x40;
    msg.data[7] = 0x80;

    long unsigned int t_init = cansec_gettime();
    can_send_message(msg);
    tx_latency[0] = cansec_gettime() - t_init;

    msg.id = 512;
    t_init = cansec_gettime();
    can_send_message(msg);
    tx_latency[1] = cansec_gettime() - t_init;

    msg.id = 1024;
    t_init = cansec_gettime();
    can_send_message(msg);
    tx_latency[2] = cansec_gettime() - t_init;

    msg.id = 1536;
    t_init = cansec_gettime();
    can_send_message(msg);
    tx_latency[3] = cansec_gettime() - t_init;

    msg.id = 2047;
    t_init = cansec_gettime();
    can_send_message(msg);
    tx_latency[4] = cansec_gettime() - t_init;
}
*/

// Rate measurement par ID
int can_rate_msrmnt()
{
    static CAN_Message data[TABLE_SIZE];
    static bool isFull = false;
    static int head = 0;
    int count = 0;
    int my_time = cansec_gettime();
    if (writeRXLut1)
    {
        count = can_circ_lut_getValuesBetweenLimits(&rx_lut2, my_time - CANSEC_RATE_SAMPLE_SIZE * 1000, my_time, data);
    }
    else
    {
        count = can_circ_lut_getValuesBetweenLimits(&rx_lut1, my_time - CANSEC_RATE_SAMPLE_SIZE * 1000, my_time, data);
    }
    int index = 0;
    bool found = false;
    for (int i = 0; i < TABLE_SIZE; i++)
    {
        rates[i].value = 0;
        rates[i].key = 0;
    }
    for (int i = 0; i < count; i++)
    {
        for (int j = 0; j < index; j++)
        {
            if (data[i].ide == 0)
            {
                if (rates[j].key == data[i].id)
                {
                    rates[j].value++;
                    found = true;
                    break;
                }
            }
            else
            {
                if (rates[j].key == (data[i].id << 18) + data[i].eid)
                {
                    rates[j].value++;
                    found = true;
                    break;
                }
            }
        }
        if (found == false)
        {
            if (data[i].ide == 0)
            {
                rates[index].key = (long unsigned int)(data[i].id);
            }
            else
            {
                rates[index].key = (data[i].id << 18) + data[i].eid;
            }
            // rates[index].key = (data[i].eid == 0 ? data[i].id : (data[i].id << 18) + data[i].eid);
            rates[index].value = 1;
            index++;
        }
        found = false;
    };
    int sample_size = isFull ? HISTORY_SIZE : head;
    int mean_whole, mean_thousandths, sd_whole, sd_thousandths; // variables pour recuperer partie entiere et millième
    float hist[HISTORY_SIZE];
    for (int i = 0; i < index; i++)
    {
        switch (rates[i].key)
        {
        case 0x110:
            rates_hist_known_IDs[1][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[1][j].value;
            }
            mean_rates_kmown_IDs[1].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[1].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[1].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[1].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[1].value;
            sd_thousandths = (sd_rates_known_IDs[1].value - sd_whole) * 1000;
            xil_printf("Rate ID 110 = %d /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[1].value, mean_whole, mean_thousandths,sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[1].value + 3 * sd_rates_known_IDs[1].value)
            {
                xil_printf("----------------------Flooding detected on ID 110 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[1].value - 3 * sd_rates_known_IDs[1].value)
            {
                xil_printf("----------------------Suspend detected on ID 110 --------------------------- \r\n");
            }
            break;
        case 0x120:
            rates_hist_known_IDs[2][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[2][j].value;
            }
            mean_rates_kmown_IDs[2].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[2].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[2].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[2].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[2].value;
            sd_thousandths = (sd_rates_known_IDs[2].value - sd_whole) * 1000;
            xil_printf("Rate ID 120 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[2].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[2].value + 3 * sd_rates_known_IDs[2].value)
            {
                xil_printf("----------------------Flooding detected on ID 120 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[2].value - 3 * sd_rates_known_IDs[2].value)
            {
                xil_printf("----------------------Suspend detected on ID 120 --------------------------- \r\n");
            }
            break;
        case 0x180:
            rates_hist_known_IDs[3][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[3][j].value;
            }
            mean_rates_kmown_IDs[3].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[3].value = calculateSD(hist, sample_size);

            mean_whole = mean_rates_kmown_IDs[3].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[3].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[3].value;
            sd_thousandths = (sd_rates_known_IDs[3].value - sd_whole) * 1000;
            xil_printf("Rate ID 180 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n", (int)rates[3].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[3].value + 3 * sd_rates_known_IDs[3].value)
            {
                xil_printf("----------------------Flooding detected on ID 180 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[3].value - 3 * sd_rates_known_IDs[3].value)
            {
                xil_printf("----------------------Suspend detected on ID 180 --------------------------- \r\n");
            }
            break;
        case 0x1a0:
            rates_hist_known_IDs[4][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[4][j].value;
            }
            mean_rates_kmown_IDs[4].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[4].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[4].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[4].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[4].value;
            sd_thousandths = (sd_rates_known_IDs[4].value - sd_whole) * 1000;
            xil_printf("Rate ID 1A0 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[4].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[4].value + 3 * sd_rates_known_IDs[4].value)
            {
                xil_printf("----------------------Flooding detected on ID 1a0 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[4].value - 3 * sd_rates_known_IDs[4].value)
            {
                xil_printf("----------------------Suspend detected on ID 1a0 --------------------------- \r\n");
            }
            break;
        case 0x1c0:
            rates_hist_known_IDs[5][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[5][j].value;
            }
            mean_rates_kmown_IDs[5].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[5].value = calculateSD(hist, sample_size);

            mean_whole = mean_rates_kmown_IDs[5].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[5].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[5].value;
            sd_thousandths = (sd_rates_known_IDs[5].value - sd_whole) * 1000;
            xil_printf("Rate ID 1C0 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n", (int)rates[5].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[5].value + 3 * sd_rates_known_IDs[5].value)
            {
                xil_printf("----------------------Flooding detected on ID 1c0 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[5].value - 3 * sd_rates_known_IDs[5].value)
            {
                xil_printf("----------------------Suspend detected on ID 1c0 --------------------------- \r\n");
            }
            break;
        case 0x280:
            rates_hist_known_IDs[6][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[6][j].value;
            }
            mean_rates_kmown_IDs[6].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[6].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[6].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[6].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[6].value;
            sd_thousandths = (sd_rates_known_IDs[6].value - sd_whole) * 1000;
            xil_printf("Rate ID 280 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[6].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[6].value + 3 * sd_rates_known_IDs[6].value)
            {
                xil_printf("----------------------Flooding detected on ID 280 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[6].value - 3 * sd_rates_known_IDs[6].value)
            {
                xil_printf("----------------------Suspend detected on ID 280 --------------------------- \r\n");
            }
            break;
        case 0x2e0:
            rates_hist_known_IDs[7][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[7][j].value;
            }
            mean_rates_kmown_IDs[7].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[7].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[7].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[7].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[7].value;
            sd_thousandths = (sd_rates_known_IDs[7].value - sd_whole) * 1000;
            xil_printf("Rate ID 2E0 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[7].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[7].value + 3 * sd_rates_known_IDs[7].value)
            {
                xil_printf("----------------------Flooding detected on ID 2e0 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[7].value - 3 * sd_rates_known_IDs[7].value)
            {
                xil_printf("----------------------Suspend detected on ID 2e0 --------------------------- \r\n");
            }
            break;
        case 0x300:
            rates_hist_known_IDs[8][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[8][j].value;
            }
            mean_rates_kmown_IDs[8].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[8].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[8].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[8].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[8].value;
            sd_thousandths = (sd_rates_known_IDs[8].value - sd_whole) * 1000;
            xil_printf("Rate ID 300 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[8].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[8].value + 3 * sd_rates_known_IDs[8].value)
            {
                xil_printf("----------------------Flooding detected on ID 300 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[8].value - 3 * sd_rates_known_IDs[8].value)
            {
                xil_printf("----------------------Suspend detected on ID 300 --------------------------- \r\n");
            }
            break;
        case 0x318:
            rates_hist_known_IDs[9][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[9][j].value;
            }
            mean_rates_kmown_IDs[9].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[9].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[9].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[9].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[9].value;
            sd_thousandths = (sd_rates_known_IDs[9].value - sd_whole) * 1000;
            xil_printf("Rate ID 318 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[9].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[9].value + 3 * sd_rates_known_IDs[9].value)
            {
                xil_printf("----------------------Flooding detected on ID 318 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[9].value - 3 * sd_rates_known_IDs[9].value)
            {
                xil_printf("----------------------Suspend detected on ID 318 --------------------------- \r\n");
            }
            break;
        case 0x3e0:
            rates_hist_known_IDs[10][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[10][j].value;
            }
            mean_rates_kmown_IDs[10].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[10].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[10].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[10].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[10].value;
            sd_thousandths = (sd_rates_known_IDs[10].value - sd_whole) * 1000;
            xil_printf("Rate ID 3E0 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[10].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[10].value + 3 * sd_rates_known_IDs[10].value)
            {
                xil_printf("----------------------Flooding detected on ID 3e0 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[10].value - 3 * sd_rates_known_IDs[10].value)
            {
                xil_printf("----------------------Suspend detected on ID 3e0 --------------------------- \r\n");
            }
            break;
        case 0x5c0:
            rates_hist_known_IDs[11][head].value = rates[i].value;
            for (int j = 0; j < sample_size; j++)
            {
                hist[j] = rates_hist_known_IDs[11][j].value;
            }
            mean_rates_kmown_IDs[11].value = calculateMEAN(hist, sample_size);
            sd_rates_known_IDs[11].value = calculateSD(hist, sample_size);

            /*
            mean_whole = mean_rates_kmown_IDs[11].value;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[11].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd_rates_known_IDs[11].value;
            sd_thousandths = (sd_rates_known_IDs[11].value - sd_whole) * 1000;
            xil_printf("Rate ID 5C0 = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n",(int)rates[11].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
            */

            if ((head != 0 || isFull) && rates[i].value > mean_rates_kmown_IDs[11].value + 3 * sd_rates_known_IDs[11].value)
            {
                xil_printf("----------------------Flooding detected on ID 5c0 --------------------------- \r\n");
            }
            else if ((head != 0 || isFull) && rates[i].value < mean_rates_kmown_IDs[11].value - 3 * sd_rates_known_IDs[11].value)
            {
                xil_printf("----------------------Suspend detected on ID 5c0 --------------------------- \r\n");
            }
            break;
        default:
            break;
        }
    }

    if (isFull == false && head == (HISTORY_SIZE - 1))
        isFull = true;
    head = (head + 1) % HISTORY_SIZE;
    return index;
}

// TODO: Implement timestamp check ?
// If we want to be able to detect spoofing, we must be able to detect 10-15ns derivation.
// To do this, we need to add an hw timer in vivado to get the precise timestamps
// Implementation details are yet to be found
void timestamp_check() {};


void print_ip(char *msg, ip_addr_t *ip)
{
	xil_printf(msg);
	xil_printf("%d.%d.%d.%d\n\r", ip4_addr1(ip), ip4_addr2(ip),
			   ip4_addr3(ip), ip4_addr4(ip));
}

void print_ip_settings(ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw)
{

	print_ip("Board IP: ", ip);
	print_ip("Netmask : ", mask);
	print_ip("Gateway : ", gw);
}

void print_echo_app_header()
{
	xil_printf("%20s %6d %s\r\n", "echo server",
			   echo_port,
			   "$ telnet <board_ip> 7");
}

/* thread spawned for each connection */
void process_echo_request(void *p)
{
	int sd = *(int *)p;
	int RECV_BUF_SIZE = 2048;
	char recv_buf[RECV_BUF_SIZE];
	int n, nwrote;

	for(int i=0; i<100; i++){
		lwip_write(sd,"BONJOUR",(size_t)7);
	}

	while (1)
	{
		/* read a max of RECV_BUF_SIZE bytes from socket */
		if ((n = read(sd, recv_buf, RECV_BUF_SIZE)) < 0)
		{
			xil_printf("%s: error reading from socket %d, closing socket\r\n", __FUNCTION__, sd);
			break;
		}

		/* break if the recved message = "quit" */
		if (!strncmp(recv_buf, "quit", 4))
			break;

		/* break if client closed connection */
		if (n <= 0)
			break;

		/* handle request */
		if ((nwrote = write(sd, recv_buf, n)) < 0)
		{
			xil_printf("%s: ERROR responding to client echo request. received = %d, written = %d\r\n",
					   __FUNCTION__, n, nwrote);
			xil_printf("Closing socket %d\r\n", sd);
			break;
		}
	}

	/* close connection */
	close(sd);
	vTaskDelete(NULL);
}

void echo_application_thread()
{
	int sock;
	int size;
#if LWIP_IPV6 == 0
	struct sockaddr_in address, remote;

	memset(&address, 0, sizeof(address));

	if ((sock = lwip_socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;
	else xil_printf("Successfully created Dgram sock\r\n");

	if(lwip_write(sock, "Bonjour", (size_t)7)!=7) xil_printf("Error sending bonjour");
	else xil_printf("Successfully sent bonjour\r\n");

	address.sin_family = AF_INET;
	address.sin_port = htons(echo_port);
	address.sin_addr.s_addr = INADDR_ANY;
#else
	struct sockaddr_in6 address, remote;

	memset(&address, 0, sizeof(address));

	address.sin6_len = sizeof(address);
	address.sin6_family = AF_INET6;
	address.sin6_port = htons(echo_port);

	memset(&(address.sin6_addr), 0, sizeof(address.sin6_addr));

	if ((sock = lwip_socket(AF_INET6, SOCK_STREAM, 0)) < 0)
		return;
#endif

	if (lwip_bind(sock, (struct sockaddr *)&address, sizeof(address)) < 0)
		return;

	lwip_listen(sock, 0);

	size = sizeof(remote);

	while (1)
	{
		if ((new_sd[connection_index] = lwip_accept(sock, (struct sockaddr *)&remote, (socklen_t *)&size)) > 0)
		{
			sys_thread_new("echos", process_echo_request,
						   (void *)&(new_sd[connection_index]),
						   TCPIP_THREAD_STACKSIZE,
						   DEFAULT_THREAD_PRIO);
			if (++connection_index >= MAX_CONNECTIONS)
			{
				break;
			}
		}
	}
	xil_printf("Maximum number of connections reached, No further connections will be accepted\r\n");
	vTaskSuspend(NULL);
}



void network_thread(void *p)
{
	struct netif *netif;
	/* the mac address of the board. this should be unique per board */
	unsigned char mac_ethernet_address[] = {0x00, 0x0a, 0x35, 0x00, 0x01, 0x02};
#if LWIP_IPV6 == 0
	ip_addr_t ipaddr, netmask, gw;
#if LWIP_DHCP == 1
	int mscnt = 0;
#endif
#endif

	netif = &server_netif;

	xil_printf("\r\n\r\n");
	xil_printf("-----lwIP Socket Mode Echo server Demo Application ------\r\n");

#if LWIP_IPV6 == 0
#if LWIP_DHCP == 0
	/* initialize IP addresses to be used */
	IP4_ADDR(&ipaddr, 192, 168, 1, 10);
	IP4_ADDR(&netmask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 192, 168, 1, 1);
#endif

	/* print out IP settings of the board */

#if LWIP_DHCP == 0
	print_ip_settings(&ipaddr, &netmask, &gw);
	/* print all application headers */
#endif

#if LWIP_DHCP == 1
	ipaddr.addr = 0;
	gw.addr = 0;
	netmask.addr = 0;
#endif
#endif

#if LWIP_IPV6 == 0
	/* Add network interface to the netif_list, and set it as default */
	if (!xemac_add(netif, &ipaddr, &netmask, &gw, mac_ethernet_address, PLATFORM_EMAC_BASEADDR))
	{
		xil_printf("Error adding N/W interface\r\n");
		return;
	}
#else
	/* Add network interface to the netif_list, and set it as default */
	if (!xemac_add(netif, NULL, NULL, NULL, mac_ethernet_address, PLATFORM_EMAC_BASEADDR))
	{
		xil_printf("Error adding N/W interface\r\n");
		return;
	}

	netif->ip6_autoconfig_enabled = 1;

	netif_create_ip6_linklocal_address(netif, 1);
	netif_ip6_addr_set_state(netif, 0, IP6_ADDR_VALID);

	print_ip6("\n\rBoard IPv6 address ", &netif->ip6_addr[0].u_addr.ip6);
#endif

	netif_set_default(netif);

	/* specify that the network if is up */
	netif_set_up(netif);

	/* start packet receive thread - required for lwIP operation */
	sys_thread_new("xemacif_input_thread", (void (*)(void *))xemacif_input_thread, netif,
				   TCPIP_THREAD_STACKSIZE,
				   DEFAULT_THREAD_PRIO);

#if LWIP_IPV6 == 0
#if LWIP_DHCP == 1
	dhcp_start(netif);
	while (1)
	{
		vTaskDelay(DHCP_FINE_TIMER_MSECS / portTICK_RATE_MS);
		dhcp_fine_tmr();
		mscnt += DHCP_FINE_TIMER_MSECS;
		if (mscnt >= DHCP_COARSE_TIMER_SECS * 1000)
		{
			dhcp_coarse_tmr();
			mscnt = 0;
		}
	}
#else
	xil_printf("\r\n");
	xil_printf("%20s %6s %s\r\n", "Server", "Port", "Connect With..");
	xil_printf("%20s %6s %s\r\n", "--------------------", "------", "--------------------");

	print_echo_app_header();
	xil_printf("\r\n");
	sys_thread_new("echod", echo_application_thread, 0,
				   TCPIP_THREAD_STACKSIZE,
				   DEFAULT_THREAD_PRIO);
	vTaskDelete(NULL);
#endif
#else
	print_echo_app_header();
	xil_printf("\r\n");
	sys_thread_new("echod", echo_application_thread, 0,
				   THREAD_STACKSIZE,
				   DEFAULT_THREAD_PRIO);
	vTaskDelete(NULL);
#endif
	return;
}




// Function to init all the security functions of the CANBus
int can_security_init()
{
    // Initialize the receive and transmit buffers
    rx_lut_write = xSemaphoreCreateMutex();
    if (rx_lut_write == NULL)
    {
        /* There was insufficient FreeRTOS heap available for the semaphore to
        be created successfully. */
        xil_printf("Error initializing rx_lut_write\r\n");
    }
    can_circ_lut_init(&rx_lut1);
    can_circ_lut_init(&rx_lut2);
    can_circ_lut_init(&tx_lut);

    for (int i = 0; i < HISTORY_SIZE; i++)
    {
        rx_bndw[i] = 0.0;
        tx_bndw[i] = 0.0;
    }
    latency_refresh_count = 0;
    mean_rates_kmown_IDs[0].key = 0x100;
    mean_rates_kmown_IDs[1].key = 0x110;
    mean_rates_kmown_IDs[2].key = 0x120;
    mean_rates_kmown_IDs[3].key = 0x180;
    mean_rates_kmown_IDs[4].key = 0x1a0;
    mean_rates_kmown_IDs[5].key = 0x1c0;
    mean_rates_kmown_IDs[6].key = 0x280;
    mean_rates_kmown_IDs[7].key = 0x2e0;
    mean_rates_kmown_IDs[8].key = 0x300;
    mean_rates_kmown_IDs[9].key = 0x318;
    mean_rates_kmown_IDs[10].key = 0x3e0;
    mean_rates_kmown_IDs[11].key = 0x5c0;
    for (int i = 0; i < 12; i++)
    {
        mean_rates_kmown_IDs[i].value = 0.0;
    }

    xTaskCreate(secTask, (const char *)"CANSecTask",
                configMINIMAL_STACK_SIZE * 8,
                NULL,
                tskIDLE_PRIORITY+1,
                &xCanSecTask);

    // Initialize the software timer
    TimerHandle_t timerHndlMetricsRefresh;
    timerHndlMetricsRefresh = xTimerCreate("timer1Sec", pdMS_TO_TICKS(CANSEC_REFRESH_RATE), pdTRUE, (void *)0, vTimerCbMetricsRefresh); /* callback */
    if (timerHndlMetricsRefresh == NULL)
    {
        xil_printf("!!! Error while creating timer !!!\r\n");
    }
    if (xTimerStart(timerHndlMetricsRefresh, 0) == pdFAIL)
    {
        xil_printf("Timer has not started \r\n");
    }

    //tcpip_init(createSocket, NULL);
    lwip_init();
    sys_thread_new("NW_THRD", network_thread, NULL,
    				   TCPIP_THREAD_STACKSIZE,
    				   DEFAULT_THREAD_PRIO);

    return EXIT_SUCCESS;
}
