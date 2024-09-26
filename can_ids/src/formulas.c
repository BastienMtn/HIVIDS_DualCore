/*
 * formulas.c
 *
 *  Created on: May 30, 2024
 *      Author: bastien
 */
#include "formulas.h"

float calculateMEAN(float data[], int size){
    float sum = 0.0;
    int i;
    for (i = 0; i < size; ++i) {
        sum += data[i];
    }
    return sum / size;
}

// Function to calculate standard deviation
float calculateSD(float data[], int size) {
    // Calculate the standard deviation (square root of variance)
    float variance = calculateVAR(data, size);
    // If variance is zero, standard deviation is also zero
    if (variance == 0.0f) {
        return 0.0f;
    }
    float standard_deviation = 0.0f;
    float x = variance;
    float guess = x / 2.0f;
    float epsilon = 0.00001f; // Define the accuracy of the approximation

    // Using Newton's method to approximate the square root
    while (1) {
        float new_guess = 0.5f * (guess + x / guess);
        if (guess - new_guess < epsilon && guess - new_guess > -epsilon) {
            standard_deviation = new_guess;
            break;
        }
        guess = new_guess;
    }

    return standard_deviation;
}

// Function to calculate variance
float calculateVAR(float data[], int size) {
    if (size <= 1) {
        return 0.0f;
    }

    float sum = 0.0f;
    float sum_of_squares = 0.0f;

    // Calculate the sum and sum of squares of the data
    for (int i = 0; i < size; i++) {
        sum += data[i];
        sum_of_squares += data[i] * data[i];
    }

    // Calculate the variance
    float variance = (sum_of_squares - (sum * sum) / size) / (size - 1);

    return variance;
}