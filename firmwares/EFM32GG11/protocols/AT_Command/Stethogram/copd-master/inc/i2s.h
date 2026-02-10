/*
 * i2s.h
 *
 *  Created on: 2020/4/19
 *      Author: Ryan
 */

#include "em_chip.h"
#include "em_cmu.h"
#include "em_emu.h"
#include "em_gpio.h"
#include "em_ldma.h"
#include "em_usart.h"

#ifndef _COPD_INC_I2S_H_
#define _COPD_INC_I2S_H_

/*	not use	*/
#define MIC_ENABLE_PORT gpioPortA
#define MIC_ENABLE_PIN 5

/* I2S_PORT */
#define I2S_PORT gpioPortA
#define I2S_TX_PIN 0
#define I2S_RX_PIN 1
#define I2S_CLK_PIN 2
#define I2S_CS_PIN 3

/* I2S_1_PORT */
#define I2S_1_PORT gpioPortD
#define I2S_1_TX_PIN 0
#define I2S_1_RX_PIN 1
#define I2S_1_CLK_PIN 2
#define I2S_1_CS_PIN 3

// Sample frequency in Hz
// 8kHz * 512 / 120 = 34133 Hz
#define SAMPLE_FREQUENCY 34133

// Buffers to hold microphone input
#define BUFFER_SIZE_I2S 10

void MICMODE_InitMIC(uint32_t sampleFrequency);

void MICMODE_InitLDMA(void);
void initCMU(void);
void Return_Left_buffer(int16_t *);
void Return_Right_buffer(int16_t *);
#endif //	_COPD_INC_I2S_H_
uint32_t Swap_Endian(uint32_t num);