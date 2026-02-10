/*
 * Adc.h
 *
 *  Created on: 2018/02
 *      Author: RyanYeh
 *  modified by alexhsu on 2020/03/13
 */

#ifndef INC_ADC_H_
#define INC_ADC_H_

#include "em_adc.h"
#include "em_cmu.h"
#include "math.h"
#include "stdlib.h"

#define ADC_IDX_BATTERY (0)
#define ADC_CHANNEL_COUNT (2)
#define ADC_IDX_NTC (1)
#define BAT_MEAS_TIME (1)

typedef struct DrvAdcVoltSt {
    uint16_t wVolt;
    uint16_t wAdc;
    uint16_t wBatLevel;
} DrvAdcVoltType;

extern void AdcStart(void);
extern void init_Adc(void);
extern short GetBatLevel(void);
extern short GetBatVolt(void);
extern uint16_t AdcBatGetCode(void);
extern uint16_t AdcNtcGetCode(void);

#endif /* INC_ADC_H_ */
