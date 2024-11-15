/*
 * cansec_rules.c
 *
 *  Created on: Jul 8, 2024
 *      Author: bastien
 */

#include "cansec_rules.h"
#include "can_rules.h"

// Function to apply the rule to the Can Frame
bool applyRule(CANSecExtFrame frame, CANRule rule)
{
    //xil_printf("Applying rule\r\n");
    bool pass = false;
    char errMessage[128] = "Default message\r\n";

    int64_t sum;
    int64_t options[3];
    int startbyte;
    int endbyte;

    for (int i = 0; i < rule.num_options; i++)
    {
        //xil_printf("Analysing option\r\n");
        sum = 0;
        switch (rule.options[i].type)
        {
        case UpLimit:
            splitRuleValue(rule.options[i].value, DELIMITER, options); 
            startbyte = (int) options[0];
            endbyte = (int) options[1];
            
            for (int j = startbyte; j <= endbyte; j++)
            {
                sum += frame.msg.data[j] << j*8;              
            }
            pass = (sum <= options[2]);                       
            break;
        case DownLimit:
            splitRuleValue(rule.options[i].value, DELIMITER, options); 
            startbyte = (int) options[0];
            endbyte = (int) options[1];
            
            for (int j = startbyte; j <= endbyte; j++)
            {
                sum += frame.msg.data[j] << j*8;              
            }
            pass = (sum >= options[2]);                       
            break;
        case Format:
            pass = (frame.msg.data[0] & strtol(rule.options[i].value, NULL, 16));
            break;
        case Length:
            pass = (frame.msg.dlc == atoi(rule.options[i].value));
            break;
        case Contains:
        {
            int value = atoi(rule.options[i].value);
            for (int j = 0; j < frame.msg.dlc; j++)
            {
                pass = (frame.msg.data[j] != value);
                if (!pass)
                {
                    break;
                }
            }
            break;
        }
        case Message:
            strcpy(errMessage, rule.options[i].value);
            break;
        default:
            break;
        }

        if (!pass)
        {
            xil_printf("Error on ID = %x / Message : %s\r\n",frame.msg.id, errMessage);
            return false;
        }
    }

    return true;
}

// Function to check HTTP frame against rule table and store matching lines
struct Error checkWithRules(CANSecExtFrame frame)
{
    //xil_printf("Checking with rules\r\n");
    // Initialize error struct
    static struct Error error;
    error.count = 0;

    // Check if rule table is initialized
    if (ruleTable == NULL)
    {
        xil_printf("Error: Rule table not initialized.\r\n");
        return error;
    }

    // Compare the HTTP frame ID with each rule in the lookup table
    for (int i = 0; i < ruleCount; i++)
    {
        //xil_printf("Comparing with rules\r\n");
        long unsigned int frame_id = frame.msg.id;
        if(ruleTable[i].extended){
            frame_id = frame.msg.id << 18 + frame.msg.eid;
        }
        bool same_direction = (ruleTable[i].dir == BIDIRECTIONAL);
        if(!same_direction){
            same_direction = (ruleTable[i].dir == frame.dir);
        }
        if ((frame_id == ruleTable[i].id) && ((frame.msg.ide == 1) == ruleTable[i].extended) && (same_direction) && ((frame.msg.rtr == 1) == ruleTable[i].isRequest))
        {
            if (!applyRule(frame, ruleTable[i]))
            {
                // Store the matching rule line
                error.matchingRules[i]='1';
                error.count++;
            }else{
                error.matchingRules[i]='0';
            }
        }else{
            error.matchingRules[i]='0';
        }
    }

    return error;
}

int secrules_test_main()
{
    // PART OF THE CODE HERE IS AN EXAMPLE OF AN OLD MAIN, TO BE DELETED
    /*
        // Simulated HTTP frame
        struct HTTPFrame frame = {1234, 5, {1, 2, 3, 4, 5, 6, 7, 8}};

        // Check HTTP frame against rule table and store matching lines
        struct Error error = checkWithRules(frame);
        if (error.count == 0) {
            printf("No matching rule found for the HTTP frame ID.\n");
        } else if (error.count < 0) {
            printf("Error processing HTTP frame.\n");
        } else {
            printf("Matching Rule Lines:\n");
            for (int i = 0; i < error.count; i++) {
                printf("%s\n", error.matchingRules[i]);
                free(error.matchingRules[i]);
            }
        }

        // Free memory allocated for matching rule lines
        if (error.matchingRules != NULL) {
            free(error.matchingRules);
        }

        // Free memory allocated for the rule table
        for (int i = 0; ruleTable[i] != NULL; i++) {
            free(ruleTable[i]);
        }
        free(ruleTable);
    */
    return 0;
}

void splitRuleValue(char* value, char* delimiter, int64_t* options) {
    char* save = value;
    char* token = strtok_r(value, delimiter, &save);
    for (int j=0 ; j<3 ; j++){
        options[j] = atoi (token);
        token = (strtok_r(NULL, delimiter, &save));  
    }
}
