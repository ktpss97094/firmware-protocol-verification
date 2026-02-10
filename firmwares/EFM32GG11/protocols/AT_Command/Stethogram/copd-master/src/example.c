#include "example.h"

/*	ex5	*/
/* Descriptor linked list for LDMA transfer */
LDMA_Descriptor_t descLink[3];
/* Buffuint8_t dstBuffer[BUFFER_SIZE];er for memory to memory transfer */
uint32_t srcBuffer[1] = {0xabcdefab};
uint32_t dstBuffer[2] = {0};
uint32_t srcBuffer_ex7_test[TESTBUFFERSIZE];
uint32_t dstBuffer_ex7_test[TESTBUFFERSIZE];
LDMA_Descriptor_t descLink_test;
uint32_t look_addr = 0;
uint32_t wtimer3_address = 0;

uint8_t srcA[BUFFER_SIZE] = "AAaa";
uint8_t srcB[BUFFER_SIZE] = "BBbb";
uint8_t srcC[BUFFER_SIZE] = "DDdd";

// uint8_t maxBuffer[maxBufferSize] = {0};

/* Descriptor linked list for LDMA transfer */
LDMA_Descriptor_t descLink_2d_copy[2];

/* Buffer for 2D copy transfer */
uint16_t src2d[BUFFER_2D_HEIGHT][BUFFER_2D_WIDTH];
uint16_t dst2d[BUFFER_2D_HEIGHT][BUFFER_2D_WIDTH];

/*
**********************************
**********************************
                ex1 acmp_interrupt example
                If PC4 receives HIGH, it will trigger ACMP INTERRUPT
                We use PC5 as the pin for external signal to PC4
**********************************
**********************************
*/
void initGPIO_acmp_interrupt(void) {
    // Enable clock
    CMU_ClockEnable(cmuClock_GPIO, true);

    // Configure PC4  and LED 2
    GPIO_PinModeSet(TEST_INPUT_PORT, TEST_INPUT_PIN, gpioModeInputPullFilter, 0);
    GPIO_PinModeSet(LED_2_Port, LED_2_Pin, gpioModePushPull, 1);

    // Configure PC5 RX0 for input signal */
    GPIO_PinModeSet(gpioPortC, 5, gpioModePushPull, 1);

    // Configure PB3 TX2 output (Exp Header 9)
    GPIO_PinModeSet(gpioPortB, 3, gpioModePushPull, 0);
}

/**************************************************************************/ /**
                                                                              * @brief ACMP
                                                                              *initialization
                                                                              *****************************************************************************/
void initACMP_acmp_interrupt(void) {
    // Enable clock
    CMU_ClockEnable(cmuClock_ACMP0, true);

    // Set ACMP initialization to the default
    ACMP_Init_TypeDef acmp0_init = ACMP_INIT_DEFAULT;

    // We want to delay enable until after everything is set up
    acmp0_init.enable = false;

    // ACMP interrupts when voltage on pos channel drops below neg channel
    acmp0_init.interruptOnFallingEdge = true;

    // Set VB to default configuration of 1.25V
    ACMP_VBConfig_TypeDef vb_config = ACMP_VBCONFIG_DEFAULT;

    // Init and set ACMP channel
    ACMP_Init(ACMP0, &acmp0_init);

    // Set PB3 TX2 to output
    ACMP_GPIOSetup(ACMP0, 7, true, true);
    // Configure the GPIO pins such that if PB9(acmpInputAPORT2XCH25) is high, the output is logic
    // high Configure the GPIO pins such that if PC4(acmpInputAPORT0XCH4 is high, the output is
    // logic high
    ACMP_ChannelSet(ACMP0, acmpInputVBDIV, acmpInputAPORT0XCH4); // neg is VBDIV pos is pin

    ACMP_VBSetup(ACMP0, &vb_config);

    ACMP_Enable(ACMP0);

    // Wait for warmup
    while (!(ACMP0->STATUS & _ACMP_STATUS_ACMPACT_MASK))
        ;

    // Clear pending ACMP interrupts
    //  NVIC_ClearPendingIRQ(ACMP0_IRQn);
    //  ACMP_IntClear(ACMP0, ACMP_IFC_EDGE);

    //  // Enable ACMP interrupts
    //  NVIC_EnableIRQ(ACMP0_IRQn);
    //  ACMP_IntEnable(ACMP0, ACMP_IEN_EDGE);
}

/*
**********************************
**********************************
                ex2 adc_scan_diff_interrupt example	not work yet ><

**********************************
**********************************
*/
void initADC_adc_scan_diff(void) {
    // Enable ADC0 clock
    CMU_ClockEnable(cmuClock_ADC0, true);

    // Declare init structs
    ADC_Init_TypeDef init = ADC_INIT_DEFAULT;
    ADC_InitScan_TypeDef initScan = ADC_INITSCAN_DEFAULT;

    // Modify init structs
    init.prescale = ADC_PrescaleCalc(adcFreq, 0);
    init.timebase = ADC_TimebaseCalc(0);

    initScan.diff = true;              // differential ended
    initScan.reference = adcRef2V5;    // internal 2.5V reference
    initScan.resolution = adcRes12Bit; // 12-bit resolution
    initScan.acqTime = adcAcqTime4;    // set acquisition time to meet minimum requirements
    initScan.fifoOverwrite = true;     // FIFO overflow overwrites old data

    // Select ADC input. See README for corresponding EXP header pin.
    // Add VDD to scan for demonstration purposes
    //  ADC_ScanDifferentialInputAdd(&initScan, adcScanInputGroup0, adcPosSelAPORT4XCH9,
    //  adcScanNegInput1);	//PE9
    ADC_ScanDifferentialInputAdd(&initScan, adcScanInputGroup0, adcPosSelAPORT0YCH0,
                                 adcScanNegInput1); // PD0 I2S_DO1
    ADC_ScanDifferentialInputAdd(&initScan, adcScanInputGroup1, adcPosSelAVDD,
                                 adcScanNegInputDefault);

    // Set scan data valid level (DVL) to 2
    ADC0->SCANCTRLX |= (NUM_INPUTS - 1) << _ADC_SCANCTRLX_DVL_SHIFT;

    // Clear ADC scan fifo
    ADC0->SCANFIFOCLEAR = ADC_SCANFIFOCLEAR_SCANFIFOCLEAR;

    // Initialize ADC and Scan
    ADC_Init(ADC0, &init);
    ADC_InitScan(ADC0, &initScan);

    // Enable Scan interrupts
    ADC_IntEnable(ADC0, ADC_IEN_SCAN);

    // Enable ADC interrupts
    NVIC_ClearPendingIRQ(ADC0_IRQn);
    NVIC_EnableIRQ(ADC0_IRQn);
}

/*
**********************************
**********************************
                ex3 adc_scan_interrupt
**********************************
**********************************
*/
void initADC_adc_scan(void) {
    // Enable ADC0 clock
    CMU_ClockEnable(cmuClock_ADC0, true);

    // Declare init structs
    ADC_Init_TypeDef init = ADC_INIT_DEFAULT;
    ADC_InitScan_TypeDef initScan = ADC_INITSCAN_DEFAULT;

    // Modify init structs
    init.prescale = ADC_PrescaleCalc(adcFreq, 0);
    init.timebase = ADC_TimebaseCalc(0);

    initScan.diff = 0;                 // single ended
    initScan.reference = adcRef2V5;    // internal 2.5V reference
    initScan.resolution = adcRes12Bit; // 12-bit resolution
    initScan.acqTime = adcAcqTime4;    // set acquisition time to meet minimum requirement
    initScan.fifoOverwrite = true;     // FIFO overflow overwrites old data

    // Select ADC input. See README for corresponding EXP header pin.
    // Add VDD to scan for demonstration purposes
    ADC_ScanSingleEndedInputAdd(&initScan, adcScanInputGroup0, adcPosSelAPORT0XCH0); // PD0 I2S_DO1
    ADC_ScanSingleEndedInputAdd(&initScan, adcScanInputGroup1, adcPosSelAVDD);

    // Set scan data valid level (DVL) to 2
    ADC0->SCANCTRLX |= (NUM_INPUTS - 1) << _ADC_SCANCTRLX_DVL_SHIFT;

    // Clear ADC Scan fifo
    ADC0->SCANFIFOCLEAR = ADC_SCANFIFOCLEAR_SCANFIFOCLEAR;

    // Initialize ADC and Scan
    ADC_Init(ADC0, &init);
    ADC_InitScan(ADC0, &initScan);

    // Enable Scan interrupts
    ADC_IntEnable(ADC0, ADC_IEN_SCAN);

    // Enable ADC interrupts
    NVIC_ClearPendingIRQ(ADC0_IRQn);
    NVIC_EnableIRQ(ADC0_IRQn);
}

/*
        ex4 adc_scan_letimer_interrupt
*/

void initLETIMER_adc_scan_letimer_interrupt(void) {
    LETIMER_Init_TypeDef letimerInit = LETIMER_INIT_DEFAULT;

    // Enable clock to the LE modules interface
    CMU_ClockEnable(cmuClock_HFLE, true);

    // Select LFXO for the LETIMER
    CMU_ClockSelectSet(cmuClock_LFA, cmuSelect_LFXO);
    CMU_ClockEnable(cmuClock_LETIMER0, true);

    // Reload COMP0 on underflow, idle output, and run in repeat mode
    letimerInit.comp0Top = true;
    letimerInit.ufoa0 = letimerUFOANone;
    letimerInit.repMode = letimerRepeatFree;

    // Need REP0 != 0 to pulse on underflow
    LETIMER_RepeatSet(LETIMER0, 0, 1);

    // calculate the topValue
    uint32_t topValue = CMU_ClockFreqGet(cmuClock_LETIMER0) / letimerDesired;

    // Compare on wake-up interval count
    LETIMER_CompareSet(LETIMER0, 0, topValue);

    // Initialize and enable LETIMER
    LETIMER_Init(LETIMER0, &letimerInit);

    // Enable LETIMER0 interrupts for COMP0
    LETIMER_IntEnable(LETIMER0, LETIMER_IEN_COMP0);

    // Enable LETIMER interrupts
    NVIC_ClearPendingIRQ(LETIMER0_IRQn);
    NVIC_EnableIRQ(LETIMER0_IRQn);
}

/*
        ex5 ldma_linked_list_looped
*/
void initLdma_ldma_linked_list_looped(void) {
    uint32_t i;

    /* Initialize buffers for memory transfer */
    for (i = 0; i < BUFFER_SIZE; i++) {
        dstBuffer[i] = 0;
    }

    LDMA_Init_t init = LDMA_INIT_DEFAULT;
    LDMA_Init(&init);

    /* Use looped peripheral transfer configuration macro */
    LDMA_TransferCfg_t periTransferTx = LDMA_TRANSFER_CFG_MEMORY_LOOP(LOOP_COUNT);

    /* LINK descriptor macros for looping, SINGLE descriptor macro for single transfer */
    descLink[0] =
        (LDMA_Descriptor_t)LDMA_DESCRIPTOR_LINKREL_M2M_BYTE(&srcA, &dstBuffer, BUFFER_SIZE, 1);
    descLink[1] =
        (LDMA_Descriptor_t)LDMA_DESCRIPTOR_LINKREL_M2M_BYTE(&srcB, &dstBuffer, BUFFER_SIZE, -1);
    descLink[2] =
        (LDMA_Descriptor_t)LDMA_DESCRIPTOR_SINGLE_M2M_BYTE(&srcC, &dstBuffer, BUFFER_SIZE);

    /* Enable looping */
    descLink[1].xfer.decLoopCnt = 1;

    /* Enable interrupts */
    descLink[0].xfer.doneIfs = true;
    descLink[1].xfer.doneIfs = true;
    descLink[2].xfer.doneIfs = true;

    /* Disable automatic triggers */
    descLink[0].xfer.structReq = false;
    descLink[1].xfer.structReq = false;
    descLink[2].xfer.structReq = false;

    LDMA_StartTransfer(LDMA_CHANNEL, (void *)&periTransferTx, (void *)&descLink);

    /* Request first transfer */
    LDMA->SWREQ |= LDMA_CH_MASK;
}

/*
        ex6 ldma_2d_copy
*/
void initLdma_ldma_2d_copy(void) {
    uint32_t x, y;

    /* Initialize buffers for 2D copy */
    for (x = 0; x < BUFFER_2D_HEIGHT; x++) {
        for (y = 0; y < BUFFER_2D_WIDTH; y++) {
            src2d[x][y] = x * BUFFER_2D_WIDTH + y;
            dst2d[x][y] = 0;
        }
    }

    LDMA_Init_t init = LDMA_INIT_DEFAULT;
    LDMA_Init(&init);

    /* Use looped me1ory transfer configuration macro */
    LDMA_TransferCfg_t memTransfer = LDMA_TRANSFER_CFG_MEMORY_LOOP(9 - 2);

    descLink_2d_copy[0] =
        (LDMA_Descriptor_t)LDMA_DESCRIPTOR_LINKREL_M2M_HALF(&src2d[0][0], &dst2d[0][0],
                                                            10, // xfercnt
                                                            1); // linkjump
    descLink_2d_copy[1] = (LDMA_Descriptor_t)LDMA_DESCRIPTOR_LINKREL_M2M_HALF(0, 0, 10, 0);

    /* Use relative addressing for source & destination, enable looping */
    descLink_2d_copy[1].xfer.srcAddrMode = ldmaCtrlSrcAddrModeRel;
    descLink_2d_copy[1].xfer.dstAddrMode = ldmaCtrlDstAddrModeRel;
    descLink_2d_copy[1].xfer.decLoopCnt = 1;

    /* Stop after looping */
    descLink_2d_copy[1].xfer.link = 0;

    LDMA_StartTransfer(LDMA_CHANNEL, (void *)&memTransfer, (void *)&descLink_2d_copy);
}

/*
 * ex7 ldma_control_gpio
 */
void initLdma_ldma_control_gpio(void) {
    /* init transfer buffer */
    uint32_t i;
    for (i = 0; i < TESTBUFFERSIZE; i++) {
        srcBuffer_ex7_test[i] = i;
        dstBuffer_ex7_test[i] = 0;
    }

    LDMA_Init_t init = LDMA_INIT_DEFAULT;
    LDMA_Init(&init);
    srcBuffer[0] = GPIO->P[gpioPortF].DOUT & (uint32_t)0xFFDF; // let PF5 == 0

    /* Writes directly to the LDMA channel registers */
    LDMA->CH[DMA_CHANNEL].CTRL = LDMA_CH_CTRL_SIZE_WORD | LDMA_CH_CTRL_REQMODE_ALL |
                                 LDMA_CH_CTRL_BLOCKSIZE_UNIT1 |
                                 (TRANSFER_SIZE) << _LDMA_CH_CTRL_XFERCNT_SHIFT;
    LDMA->CH[DMA_CHANNEL].SRC = (uint32_t)srcBuffer;
    LDMA->CH[DMA_CHANNEL].DST = (uint32_t)&GPIO->P[gpioPortF].DOUT;

    /* Writes TIMER CNT directly to the LDMA channel registers */
    LDMA->CH[DMA_CHANNEL_TIMER].CTRL = LDMA_CH_CTRL_SIZE_WORD | LDMA_CH_CTRL_REQMODE_ALL |
                                       LDMA_CH_CTRL_BLOCKSIZE_UNIT1 |
                                       (TRANSFER_SIZE) << _LDMA_CH_CTRL_XFERCNT_SHIFT;
    LDMA->CH[DMA_CHANNEL_TIMER].SRC = (uint32_t)0x4001AC24;
    LDMA->CH[DMA_CHANNEL_TIMER].DST = (uint32_t)&dstBuffer;

    /* Writes BUFFER directly to the LDMA channel registers */
    LDMA->CH[DMA_CHANNEL_BUFFER].CTRL = LDMA_CH_CTRL_SIZE_WORD | LDMA_CH_CTRL_REQMODE_ALL |
                                        LDMA_CH_CTRL_BLOCKSIZE_UNIT128 |
                                        (TEST_BUFFER_TRANSFER_SIZE) << _LDMA_CH_CTRL_XFERCNT_SHIFT;
    LDMA->CH[DMA_CHANNEL_BUFFER].SRC = (uint32_t)&srcBuffer_ex7_test;
    LDMA->CH[DMA_CHANNEL_BUFFER].DST = (uint32_t)&dstBuffer_ex7_test;
    wtimer3_address = (uint32_t)WTIMER3->CNT;

    descLink_test =
        (LDMA_Descriptor_t)LDMA_DESCRIPTOR_SINGLE_M2M_WORD((uint32_t)0x4001AC24, &dstBuffer[1], 1);
    look_addr = (((uint32_t)(&descLink_test.xfer) & (uint32_t)0xFFFFFFFC)) | (uint32_t)0x0001;
    LDMA->CH[DMA_CHANNEL_BUFFER].LINK =
        (((uint32_t)(&descLink_test.xfer) & (uint32_t)0xFFFFFFFC)) | (uint32_t)0x0002;

    /* Enable all interrupt and wait PRS on DMAREQ0 to start transfer */
    LDMA->CH[DMA_CHANNEL].REQSEL = ldmaPeripheralSignal_PRS_REQ0;
    LDMA->CH[DMA_CHANNEL_TIMER].REQSEL = ldmaPeripheralSignal_PRS_REQ0;
    LDMA->CH[DMA_CHANNEL_BUFFER].REQSEL = ldmaPeripheralSignal_PRS_REQ0;

    LDMA->IFC = DMA_CH_MASK | DMA_CH_MASK_TIMER | DMA_CH_MASK_BUFFER;
    LDMA->IEN = DMA_CH_MASK | DMA_CH_MASK_TIMER | DMA_CH_MASK_BUFFER;
    /* Enable all LDMA Channel */
    LDMA->CHEN = DMA_CH_MASK | DMA_CH_MASK_TIMER | DMA_CH_MASK_BUFFER;
}

void initGPIO_ldma_control_gpio(void) {
    /* Configure push button SW as input */
    GPIO_PinModeSet(gpioPortA, 5, gpioModeInputPullFilter, 1);
    /* Configure interrupt on push button PA5 for rising edge but not enabled - PRS sensing instead
     */
    GPIO_IntConfig(gpioPortA, 5, true, false, false);

    /* Select GPIO as PRS source and push button BTN1 as signal for PRS channel */
    CMU_ClockEnable(cmuClock_PRS, true);
    PRS_SourceSignalSet(GPIO_PRS_CHANNEL, PRS_CH_CTRL_SOURCESEL_GPIOL, 5, prsEdgePos);
    /* Select PRS channel for DMA request 0 */
    PRS->DMAREQ0 = PRS_DMAREQ0_PRSSEL_PRSCH1;
}
// void fillBuffer(void)
//{
//	uint32_t i = 0;
//	for(i = 0; i < maxBufferSize; i++){
//////	maxBuffer[i] = 0xfe;
//	}
//}

void initPRS_acmp(void) {
    // Enable PRS clock
    CMU_ClockEnable(cmuClock_PRS, true);

    PRS_SourceAsyncSignalSet(0, PRS_CH_CTRL_SOURCESEL_ACMP0, PRS_CH_CTRL_SIGSEL_ACMP0OUT);
}
