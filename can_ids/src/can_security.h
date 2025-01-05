/*
 * can_security.h
 *
 *  Created on: Mar 5, 2024
 *      Author: bastien
 */

#ifndef SRC_CAN_SECURITY_H_
#define SRC_CAN_SECURITY_H_

#include "FreeRTOS.h"
#include "PmodCAN.h"
#include "xil_cache.h"
#include "xparameters.h"
#include "canframes_circular_lut.h"
#include "timers.h"
#include "semphr.h"
#include "formulas.h"
#include "ddr_commons.h"
#include "cansec_rules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

// Sample size of the bandwidth measurements, in milliseconds
#define CANSEC_BNDW_SAMPLE_SIZE 5000
// Sample size of the rates measurements, in milliseconds
#define CANSEC_RATE_SAMPLE_SIZE 1000
// Refresh rate of the CANBus metrics, in ms
#define CANSEC_REFRESH_RATE 1000

#define HISTORY_SIZE 60

typedef enum{
    NONE,
    FLOODING,
    SUSPEND
}AttackScenario;

struct Bandwidths{
    float rx_bndwth;
    float tx_bndwth;
};

typedef struct {
    long unsigned int key;
    float value;
} RateLUT;

typedef struct {
    AttackScenario attack;
    float mean;
    float sd;
} RateAttackLUT;

long unsigned int cansec_gettime();

void can_security_store(CANSecExtFrame frame);

struct Bandwidths bandwidth_measurement();

void latency_send_measurement();

int can_rate_msrmnt();

void timestamp_check();

bool DOS_detection(struct Bandwidths bndwth);

int can_security_init();

#endif /* SRC_CAN_SECURITY_H_ */
