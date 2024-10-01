# HIVIDS_DualCore

## General Description
This project is an Hybrid In-Vehicle Intrusion Detection System, based on statistical analysis and user-defined rules.
It analyzes CANBus traffic and tries to detect differents attacks scenarios such as : DOS, Flooding, Replay, Suspend, Fuzzing attacks.

## How to use
This version uses a dual core setup of the Pynq Z2 or ZU FPGA. Therefore, a few steps need to be checked to make it work.

Prerequisites : This application is made for Cortex A9 cores, with a Coretx A53 version that has not beem tested yet. It is mandatory to have an FPGA equiped with this processors to ensure good timestamping of frames using the processors' cycles counters.
Also, this applicatoin needs to run on a Vivado Desing including a Pmod CAN Controller, connecting via SPI interface. The PmodCAN component needs to be plugged to the Pmod Connector on the board, respecting the configuration from Vivado (Pmod A or B). Configuration on Vivado can be a bit tricky because you need to make the connection pins by pins according to documentation. A tutorial to detail this step will be made later on.
If you are using Pynq ZU, and you need the Raspberry Pi header connector, make sure to use Pmod B connector as Pmod A shares pins with the said Raspberry connector.

Design steps :
First, a new domain has to be created in Vitis to be able to put different applications on both cores. This can be done by following this tutorial :
https://www.hackster.io/whitney-knitter/dual-arm-hello-world-on-zynq-using-vitis-9fc8b7

Second, you have to create two applications, one on each domain, ensuring that can_ids part runs on *Core 0* because it is the only core able to access the SD Card for logging.
Then, Core 1 needs to be setup to use the Pmod connector.

Third, you need to ensure the correct configuration of linker scripts (they are both in this repository, but if you modify them make sure the shared memory region is common to both cores, and also make sur Core 0 has enough memory space to operate).

### Core 0 Config
You need to add the following libraries to the BSP file :
- xiltimer : with paranmeter en_interval_timer set as true
- xilffs : with parameter use_lfn = 3 (or anything different than 0 should work)
Additionnally, you need to change freeRTOS' total heap size to set it as 131072 (in kernel_behavior)
### Core 1
You need to add the -DUSEAMP 1 flag in the compiler settings to ensure it knows its running in AMP mode (see tutorial given earlier).
