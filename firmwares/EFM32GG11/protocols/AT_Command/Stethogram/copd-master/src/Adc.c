/*
 * Adc.c
 *
 *  Created on: 2018/02
 *      Author: RyanYeh
 *  modified by alexhsu on 2020/03/13
 */
#include "Adc.h"
#include <stdio.h>

uint32_t nAdcCode[ADC_CHANNEL_COUNT];
uint32_t nAdcCodeCnt;
uint32_t temp_code;

uint16_t wAdcNtc;

void ADC0_IRQHandler(void) {
    int code;
    ADC_IntClear(ADC0, ADC_IntGet(ADC0));
    code = ADC_DataScanGet(ADC0);

    /*
    switch(nAdcCodeCnt)
    {
      case ADC_IDX_NTC:

          temp_code = code;
          wAdcNtc = code;
          break;
    }
    */
    temp_code = code;
    wAdcNtc = code;
    // printf("code= %d\n",code);
    nAdcCodeCnt = (nAdcCodeCnt + 1) % ADC_CHANNEL_COUNT;
}

/**
 * @brief init_Adc
 *
 * Initialize ADC
 *
 * @return NULL
 */
void init_Adc(void) {
    // printf("run init_Adc() \n");
    CMU_ClockEnable(cmuClock_ADC0, true);

    ADC_Init_TypeDef ADC0_init = ADC_INIT_DEFAULT;

    ADC0_init.ovsRateSel = adcOvsRateSel128;
    ADC0_init.warmUpMode = adcWarmupNormal;
    ADC0_init.timebase = ADC_TimebaseCalc(4000000);
    ADC0_init.prescale = ADC_PrescaleCalc(100000, 4000000);
    ADC0_init.tailgate = 0;
    ADC0_init.em2ClockConfig = adcEm2Disabled;
    ADC_Init(ADC0, &ADC0_init);

    ADC_InitScan_TypeDef scanInit = ADC_INITSCAN_DEFAULT;

    scanInit.reference = adcRef5V;
    scanInit.resolution = adcResOVS;
    scanInit.fifoOverwrite = true;

    // COPD's tempsensor
    // PA4 adcPosSelAPORT1XCH4 temp sensor
    // PA4 adcPosSelAPORT2YCH4 temp sensor (active)
    ADC_ScanSingleEndedInputAdd(&scanInit, adcScanInputGroup0, adcPosSelAPORT2YCH4);

    ADC_InitScan(ADC0, &scanInit);

    ADC_IntEnable(ADC0, ADC_IEN_SCAN);
    NVIC_EnableIRQ(ADC0_IRQn);

    nAdcCodeCnt = 0;
    while (nAdcCodeCnt < ADC_CHANNEL_COUNT) {
        nAdcCode[nAdcCodeCnt] = 0;
        nAdcCodeCnt++;
    }
    nAdcCodeCnt = 0;
    wAdcNtc = 0;
}

/**
 * @brief AdcStart
 *
 * Start ADC measurement
 *
 * @return NULL
 */
void AdcStart(void) { ADC_Start(ADC0, adcStartScan); }

uint16_t AdcNtcGetCode() { return wAdcNtc; }

/**************************************************************************/ /**
                                                                              * @brief ADC0
                                                                              *interrupt handler.
                                                                              *Simply clears
                                                                              *interrupt flag.
                                                                              *****************************************************************************/
