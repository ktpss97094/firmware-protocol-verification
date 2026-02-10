/*
 * function.h
 *
 * Author: EPL Ryan
 */

#ifndef FUNCTION_H_
#define FUNCTION_H_

#include "em_cmu.h"
#include "em_cryotimer.h"
#include "em_gpio.h"
#include "em_letimer.h"
#include "em_timer.h"
#include "em_usart.h"

#include "Adc.h"
#include "CCS811.h"
#include "HDC2080.h"
#include "LSM9DS1.h"
#include "em_rtc.h"
#include "gpiointerrupt.h"
#include "i2s.h"
#include "led.h"
#include "sdio.h"
/*
 * WTIMER USE
 * Desired frequency in Hz
 */
#define OUT_FREQ 145                   // Min: 145 Hz, Max: 9.5 MHz with default settings
#define TIMER1_PRESCALE timerPrescale1 // Default prescale value

/*
 * LETIMER USE
 */
#define OUT_FREQ_LETIMER 1                                // Desired frequency in Hz
#define DUTY_CYCLE 100                                    // Duty cycle percentage
#define LETIMER0_FREQ CMU_ClockFreqGet(cmuClock_LETIMER1) // LETIMER1 frequency
// Desired letimer interrupt frequency (in Hz)
#define letimerDesired 1000

/*
 * cyro use
 */
#define CRYOTIMER_PRESCALE cryotimerPresc_1
#define CRYOTIMER_PERIOD cryotimerPeriod_512 // 500Hz

/*
 * WTIMER use
 */
// Desired frequency in Hz
#define OUT_FREQ_WTIMER 2

// Default prescale value
#define WTIMER3_PRESCALE timerPrescale1

#define micSAMPLINGRATE2K (2000)

#define SYMBOL_MARKER(name) __asm__ volatile(".global " #name "\n" #name ":")

void init_LED(void);
void init_MIC(void);
void init_ADC0(void);
void init_sensor(void);
void init_peripheral(void);
void init_gpio_interrupt(void);
void initSDIO(void);

void init_CRYOTIMER(void);
void init_TIMER0(void);
void init_WTIMER1(void);
void init_WTIMER3(void);
void init_USART(void);
double humidity_caculation(uint16_t rawdata);
double calculate_temperature(uint16_t temp_raw_data);
void intLSM9DS1(uint8_t pin);

// log-related
void init_log(void);
void print_log(char *message, int len);

// SD Card
void init_SD_Card(void);

#endif
