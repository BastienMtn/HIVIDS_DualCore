/*
 * can_security.c
 *
 *  Created on: Mar 5, 2024
 *      Author: bastien
 */

#include "can_security.h"

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
RateAttackLUT rates_attack[12];
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

char* get_attack_name(enum AttackScenario a)
{
    switch (a)
    {
        case NONE:
            return "None\0";
        case FLOODING:
            return "Flooding\0";
        case SUSPEND:
            return "Suspend\0";
        default:
            return "\0";
    }
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
    return bndwth.rx_bndwth > rx_bd_mean + 3 * rx_bd_sd;
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
    CAN_Circ_LookupTable* rx_lut = &rx_lut1;
    if (writeRXLut1)
    {
        rx_lut = &rx_lut2;
    }
    count = can_circ_lut_getValuesBetweenLimits(&rx_lut2, (my_time - CANSEC_BNDW_SAMPLE_SIZE * 1000), my_time, data);
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

    int size = index;
    if (isFull)
    {
        size = HISTORY_SIZE;
    }
    rx_bd_mean = calculateMEAN(rx_bndw, size);
    rx_bd_var = calculateVAR(rx_bndw, size);
    rx_bd_sd = calculateSD(rx_bndw, size);

    if (!isFull && index == (HISTORY_SIZE - 1))
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
    // we wouldnt want it the other way around?
    CAN_Circ_LookupTable* rx_lut = &rx_lut1;
    if (writeRXLut1)
    {
        rx_lut = &rx_lut2;
    }
    count = can_circ_lut_getValuesBetweenLimits(&rx_lut2, my_time - CANSEC_RATE_SAMPLE_SIZE * 1000, my_time, data);
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
            if ((data[i].ide == 0 && rates[j].key == data[i].id) || // Normal ID check
                (data[i].ide != 0 && (rates[j].key == (data[i].id << 18) + data[i].eid))) // Extended ID check
            {
                rates[j].value++;
                found = true;
                break;
            }
        }
        if (found)
        {
            found = false;
            continue;
        }
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
    };
    int sample_size = isFull ? HISTORY_SIZE : head;
    int mean_whole, mean_thousandths, sd_whole, sd_thousandths; // variables pour recuperer partie entiere et millième
    float mean, sd;
    float hist[HISTORY_SIZE];
    int id_idx = -1;
    char* id[4];
    for (int i = 0; i < index; i++)
    {
        bool show_rates = false;
        switch (rates[i].key)
        {
        case 0x110:
            id_idx = 1;
            id = "110\0";
            break;
        case 0x120:
            id_idx = 2;
            id = "120\0";
            break;
        case 0x180:
            id_idx = 3;
            id = "180\0";
            show_rates = true;
            break;
        case 0x1a0:
            id_idx = 4;
            id = "1a0\0";
            break;
        case 0x1c0:
            id_idx = 5;
            id = "1c0\0";
            show_rates = true;
            break;
        case 0x280:
            id_idx = 6;
            id = "280\0";
            break;
        case 0x2e0:
            id_idx = 7;
            id = "2e0\0";
            break;
        case 0x300:
            id_idx = 8;
            id = "300\0";
            break;
        case 0x318:
            id_idx = 9;
            id = "318\0";
            break;
        case 0x3e0:
            id_idx = 10;
            id = "3e0\0";
            break;
        case 0x5c0:
            id_idx = 4;
            id = "5c0\0";
            break;
        default:
            id_idx = -1;
            break;
        }

        if (id_idx <= 0) {
            continue;
        }

        rates_hist_known_IDs[id_idx][head].value = rates[i].value;
        for (int j = 0; j < sample_size; j++)
        {
            hist[j] = rates_hist_known_IDs[id_idx][j].value;
        }
        mean = calculateMEAN(hist, sample_size);
        sd = calculateSD(hist, sample_size);

        if (show_rates){
            mean_whole = mean;                             // recup partie entière
            mean_thousandths = (mean_rates_kmown_IDs[id_idx].value - mean_whole) * 1000; // recup apres la virgule
            sd_whole = sd;
            sd_thousandths = (sd_rates_known_IDs[id_idx].value - sd_whole) * 1000;
            xil_printf("Rate ID %s = %d  /  Mean = %d.%03d  /  SD = %d.%03d \r\n", id, (int)rates[id_idx].value, mean_whole, mean_thousandths, sd_whole, sd_thousandths);
        }

        bool has_data = (head != 0 || isFull);
        if (rates_attack[id_idx].attack == NONE) {
            if (has_data && rates[i].value > mean + 3 * sd)
            {
                rates_attack[id_idx].attack = FLOODING;
                rates_attack[id_idx].mean = mean_rates_kmown_IDs[id_idx].value;
                rates_attack[id_idx].sd = sd_rates_known_IDs[id_idx].value;
                xil_printf("----------------------Flooding detected on ID %s --------------------------- \r\n", id);
            }
            else if (has_data && rates[i].value < mean - 3 * sd)
            {
                rates_attack[id_idx].attack = SUSPEND;
                rates_attack[id_idx].mean = mean_rates_kmown_IDs[id_idx].value;
                rates_attack[id_idx].sd = sd_rates_known_IDs[id_idx].value;
                xil_printf("----------------------Suspend detected on ID %s --------------------------- \r\n", id);
            }
            mean_rates_kmown_IDs[id_idx].value = mean;
            sd_rates_known_IDs[id_idx].value = sd;
            return;
        }
        // Would be here if there is an attack on the ID
        if (has_data && (rates[i].value < (rates_attack[id_idx].mean + 3 * rates_attack[id_idx].sd))
             && (rates[i].value > (rates_attack[id_idx].mean - 3 * rates_attack[id_idx].sd)))
        {
            mean_rates_kmown_IDs[id_idx].value = rates_attack[id_idx].mean;
            sd_rates_known_IDs[id_idx].value = rates_attack[id_idx].sd;
            xil_printf("----------------------%s stopped on ID %s --------------------------- \r\n", get_attack_name(rates_attack[id_idx].attack), id);
            rates_attack[id_idx].attack = NONE;
        }else { // Continue the update of the mean and sd even?
            mean_rates_kmown_IDs[id_idx].value = mean;
            sd_rates_known_IDs[id_idx].value = sd;
        }
    }

    if (!isFull && head == (HISTORY_SIZE - 1))
        isFull = true;
    head = (head + 1) % HISTORY_SIZE;
    return index;
}

// TODO: Implement timestamp check ?
// If we want to be able to detect spoofing, we must be able to detect 10-15ns derivation.
// To do this, we need to add an hw timer in vivado to get the precise timestamps
// Implementation details are yet to be found
void timestamp_check() {};

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

    return EXIT_SUCCESS;
}
