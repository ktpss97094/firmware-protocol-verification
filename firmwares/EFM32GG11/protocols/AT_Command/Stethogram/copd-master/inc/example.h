/*
 * example.h
 *
 * Author: EPL Ryan
 * here try all peripheral example
 */

#ifndef EXAMPLE_H_
#define EXAMPLE_H_
#include "em_acmp.h"
#include "em_adc.h"
#include "em_cmu.h"
#include "em_gpio.h"
#include "em_ldma.h"
#include "em_letimer.h"
#include "em_prs.h"
#include "led.h"

#define TEST_INPUT_PORT (gpioPortC) // TX0 = PC4 pin
#define TEST_INPUT_PIN (4)          // TX0 = PC4 pin

/* example2 adc_scan_diff_interrupt	*/
#define adcFreq 16000000
#define NUM_INPUTS 2

/* example1 acmp_interrupt */
void initGPIO_acmp_interrupt(void);
void initACMP_acmp_interrupt(void);

/* example2 adc_scan_diff_interrupt	*/
void initADC_adc_scan_diff(void);

/* example3 adc_scan_interrupt	*/
void initADC_adc_scan(void);

/* example4 */
#define letimerDesired 1000 // Desired letimer interrupt frequency (in Hz)

/* example 5 */
/* DMA channel used for the examples */
#define LDMA_CHANNEL 0
#define LDMA_CH_MASK 1 << LDMA_CHANNEL
/* Memory to memory transfer buffer size */
#define BUFFER_SIZE 4

/* Number of iterations of A and B. */
#define NUM_ITERATIONS 5
/* Constant for loop transfer */
/* NUM_SETS - 1 (for first iteration) */
#define LOOP_COUNT NUM_ITERATIONS - 1 // total NUM_ITERATIONS
#define maxBufferSize 0x8000          // 0x30000 = 192kB		0x40000 = 256kB 0x70000 = 448kB

void initLdma_ldma_linked_list_looped(void);
void fillBuffer(void);

/* example 6 */
/* 2D buffer size and constants for 2D copy */
#define BUFFER_2D_WIDTH 10
#define BUFFER_2D_HEIGHT 8
#define TRANSFER_WIDTH 3
#define TRANSFER_HEIGHT 4
#define SRC_ROW_INDEX 1
#define SRC_COL_INDEX 0
#define DST_ROW_INDEX 1
#define DST_COL_INDEX 2
void initLdma_ldma_2d_copy(void);

/* example 7 */
#define GPIO_PRS_CHANNEL 1
/* DMA channel used for the examples */
#define DMA_CHANNEL 0
#define DMA_CH_MASK 1 << DMA_CHANNEL
#define TRANSFER_SIZE 1 - 1 // 1 word
#define DMA_CHANNEL_TIMER 1
#define DMA_CH_MASK_TIMER 1 << DMA_CHANNEL_TIMER
#define DMA_CHANNEL_BUFFER 2
#define DMA_CH_MASK_BUFFER 1 << DMA_CHANNEL_BUFFER
#define TESTBUFFERSIZE 2048
#define TEST_BUFFER_TRANSFER_SIZE TESTBUFFERSIZE - 1
void initLdma_ldma_control_gpio(void);
void initGPIO_ldma_control_gpio(void);

void initPRS_acmp(void);

#endif
