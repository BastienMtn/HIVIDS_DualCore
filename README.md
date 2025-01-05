# HIVIDS_DualCore

## General Description
This project is a Hybrid In-Vehicle Intrusion Detection System, based on statistical analysis and user-defined rules.
It analyzes CANBus traffic and tries to detect different attacks scenarios such as : DOS, Flooding, Replay, Suspend, Fuzzing attacks.

## How to use
This version uses a dual-core setup of the Pynq Z2 or ZU FPGA. A simpler version (not containing the most recent tweaks) [was developed here](https://github.com/BastienMtn/HIVIDS). Therefore, a few steps need to be checked to make it work.

Prerequisites : This application is made for Cortex A9 cores, with a Cortex A53 version that has not been tested yet. It is mandatory to have an FPGA equipped with these processors to ensure good timestamping of frames using the processors' cycles counters.
Also, this application needs to run on a Vivado Design including a Pmod CAN Controller, connecting via SPI interface. The PmodCAN component needs to be plugged to the Pmod Connector on the board, respecting the configuration from Vivado (Pmod A or B). Configuration on Vivado can be a bit tricky because you need to make the connection pins by pins according to documentation. A tutorial to detail this step will be made later on.
If you are using Pynq ZU, and you need the Raspberry Pi header connector, make sure to use Pmod B connector as Pmod A shares pins with the said Raspberry connector.

Design steps :
First, a new domain has to be created in Vitis to be able to put different applications on both cores. This can be done by following this tutorial :
https://www.hackster.io/whitney-knitter/dual-arm-hello-world-on-zynq-using-vitis-9fc8b7

Second, you have to create two applications, one on each domain, ensuring that can_ids part runs on *Core 0* because it is the only core able to access the SD Card for logging.
Then, Core 1 needs to be setup to use the Pmod connector.

Third, you need to ensure the correct configuration of linker scripts (they are both in this repository, but if you modify them make sure the shared memory region is common to both cores, and also make sur Core 0 has enough memory space to operate).

### Core 0 Config
You need to add the following libraries to the BSP file :
- xiltimer : with parameter en_interval_timer set as true
- xilffs : with parameter use_lfn = 3 (or anything different from 0 should work)
Additionally, you need to change freeRTOS' total heap size to set it as 131072 (in kernel_behavior)

### Core 1
You need to add the -DUSEAMP 1 flag in the compiler settings to ensure it knows its running in AMP mode (see tutorial given earlier).

## User defined rules

User-defined rules can be created with a Snort-like syntax and added to the project in `src/can_rules.h`.
The syntax and the generation of valid rules can be done with [this tool](https://github.com/BastienMtn/HIVIDS_RuleParser).

## Results
This project successfully detects DOS, Flooding, Fuzzing and Suspend attacks with a high proportion and minimal loss of frames on synthetic data.

[A simulator that generate synthetic CAN load](https://github.com/BastienMtn/CAN_Simulator) has been developed in parallel of the IDS and demonstrate the capability of this project to correctly identify and report attacks.

[A simulator that uses CarlaSim](https://github.com/BBArikL/carlasim-can-bridge) to generate more "realistic" data in CAN and Ethernet was also developed alongside this project.
This project also tends to be a more generic simulation base for different attacks in modern vehicles.
It also provides an interactive response to the injected attacks and to provide context to possible attack vectors.

## Additional Work
This project, although working and providing excellent detection, can be improved in future works:
- Latency measurement: Calculate the mean and standard deviation of the latency between CAN frames. This data can be used to identify a different attacks that are happening on the bus.
- Node isolation mechanism: Verify if data coming from a node 
- Period deviation: Verify period deviation of what is expected from each ECU. This can help to determine what ECU is being suspended or being flooded.
- Timestamp check: Detect spoofing when CAN frames have more than 10-15ns derivation. A hw timer in vivado could get the precise timestamps. Implementation details are yet to be found
- Spoof detection: Verify if conflicting CAN messages are being transmitted and raise an alert on outlying messages, based on data retrieved from similar ECUs.
- Alert reporting: Report alerts to the operator either through ethernet (See `lwipAlert` branch) or other means.
- Data consistency check: Check with the different data fields if it is consistent (speed of wheels, torque request and throttle position, etc.).