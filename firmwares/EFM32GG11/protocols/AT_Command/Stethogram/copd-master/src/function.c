#include "function.h"
/*For TinyML*/

/*For LTE port allocate*/
#define LTE_PWRON_PORT (gpioPortE)
#define LTE_PWRON_PIN (5)
#define LTE_PWRON() GPIO_PinInGet(LTE_PWRON_PORT, LTE_PWRON_PIN)
#define LTE_PWRON_OUTPUT() GPIO_PinModeSet(LTE_PWRON_PORT, LTE_PWRON_PIN, gpioModePushPull, 0)
#define LTE_PWRON_ON() GPIO_PinOutClear(LTE_PWRON_PORT, LTE_PWRON_PIN)
#define LTE_PWRON_OFF() GPIO_PinOutSet(LTE_PWRON_PORT, LTE_PWRON_PIN)
#define LTE_PWRON_INIT() LTE_PWRON_OUTPUT()

#define LTE_RSTB_PORT (gpioPortE)
#define LTE_RSTB_PIN (4)
#define LTE_RSTB() GPIO_PinInGet(LTE_RSTB_PORT, LTE_RSTB_PIN)
#define LTE_RSTB_OUTPUT() GPIO_PinModeSet(LTE_RSTB_PORT, LTE_RSTB_PIN, gpioModePushPull, 0)
#define LTE_RSTB_ON() GPIO_PinOutClear(LTE_RSTB_PORT, LTE_RSTB_PIN)
#define LTE_RSTB_OFF() GPIO_PinOutSet(LTE_RSTB_PORT, LTE_RSTB_PIN)
#define LTE_RSTB_INIT() LTE_RSTB_OUTPUT()

#define PWR_4V_EN_PORT (gpioPortF)
#define PWR_4V_EN_PIN (12)
#define PWR_4V_EN() GPIO_PinInGet(PWR_4V_EN_PORT, PWR_4V_EN_PIN)
#define PWR_4V_EN_OUTPUT() GPIO_PinModeSet(PWR_4V_EN_PORT, PWR_4V_EN_PIN, gpioModePushPull, 0)
#define PWR_4V_EN_ON() GPIO_PinOutSet(PWR_4V_EN_PORT, PWR_4V_EN_PIN)
#define PWR_4V_EN_OFF() GPIO_PinOutClear(PWR_4V_EN_PORT, PWR_4V_EN_PIN)

#define SAMPLE_FREQUENCY 34133

// parameter init
uint32_t nineaxis_counter = 0;
/*rx buffer init*/

void Delay(uint32_t dlyTicks);

void init_LED(void) {
    /* enable clock	*/
    CMU_ClockEnable(cmuClock_GPIO, true);

    /* ENABLE GPIO	*/
    GPIO_PinModeSet(gpioPortF, 2, gpioModePushPull, 1); // LED 1
    GPIO_PinModeSet(gpioPortF, 5, gpioModePushPull, 1); // LED 2
    GPIO_PinModeSet(gpioPortB, 6, gpioModePushPull, 1); // LED 3
}

void init_MIC(void) {
    initCMU();
    MICMODE_InitMIC(SAMPLE_FREQUENCY);
    MICMODE_InitLDMA();
}

void init_peripheral(void) {
    init_LED();
    init_CRYOTIMER();
    init_Adc();
    init_I2C();
}

void init_sensor(void) {
    HDC2080Init(); // Humidity sensor
    CCS811Init();  // VOC sensor
    LSM9DS1Init(); // 9-axis sensor
}

void initSDIO(void) {
    CMU_ClockEnable(cmuClock_GPIO, true);
    GPIO_PinModeSet(gpioPortA, 6, gpioModeInput, 0);              // SDIO_CD
    GPIO_PinModeSet(gpioPortE, 12, gpioModePushPullAlternate, 0); // SDIO_CMD
    GPIO_PinModeSet(gpioPortE, 13, gpioModePushPullAlternate, 1); // SDIO_CLK
    GPIO_PinModeSet(gpioPortE, 11, gpioModePushPullAlternate, 1); // SDIO_DAT0
    GPIO_PinModeSet(gpioPortE, 10, gpioModePushPullAlternate, 1); // SDIO_DAT1
    GPIO_PinModeSet(gpioPortE, 9, gpioModePushPullAlternate, 1);  // SDIO_DAT2
    GPIO_PinModeSet(gpioPortE, 8, gpioModePushPullAlternate, 1);  // SDIO_DAT3
}

void initLSM9DS1(uint8_t pin) // light up/down led 2
{
    nineaxis_counter++;
    // GPIO_PinOutToggle(LED_2_Port, LED_2_Pin);
}

void initKEY_SW(uint8_t pin) // light up/down led 3
{
    GPIO_PinOutToggle(LED_3_Port, LED_3_Pin);
}

void init_gpio_interrupt(void) {
    /* enable GPIO interrupt */
    GPIOINT_Init();
    /* KEY_SW	*/
    GPIO_PinModeSet(gpioPortA, 5, gpioModeInputPull, 1);
    GPIO_ExtIntConfig(gpioPortA, 5, 5, false, true, true);
    GPIOINT_CallbackRegister(5, initKEY_SW);
    GPIO_IntEnable(1 << 5); // GPIO->IEN interrupt enable register
    /* LSM9DS1	*/
    GPIO_PinModeSet(gpioPortA, 14, gpioModeInputPull, 1);
    GPIO_ExtIntConfig(gpioPortA, 14, 14, false, true, true);
    GPIOINT_CallbackRegister(14, initLSM9DS1);
    GPIO_IntEnable(1 << 14); // GPIO->IEN interrupt enable register
}

void init_CRYOTIMER(void) {
    // can work but no good
    // Enable cryotimer clock
    CMU_ClockEnable(cmuClock_CRYOTIMER, true);

    // Initialize cryotimer
    CRYOTIMER_Init_TypeDef init = CRYOTIMER_INIT_DEFAULT;
    init.osc = cryotimerOscULFRCO;   // Use the ULFRCO 1000hZ clock
    init.presc = CRYOTIMER_PRESCALE; // Set the prescaler divide 1
    init.period = CRYOTIMER_PERIOD;  // Set when wakeup events occur every 2 on 1 sec
    init.enable = true;              // Start the cryotimer after initialization is done
    CRYOTIMER_Init(&init);

    // Enable cryotimer interrupts
    CRYOTIMER_IntEnable(CRYOTIMER_IEN_PERIOD);
    NVIC_EnableIRQ(CRYOTIMER_IRQn);
    NVIC_SetPriority(CRYOTIMER_IRQn, 1);
}

void init_TIMER0(void) {
    // Enable clock for TIMER1 module
    CMU_ClockEnable(cmuClock_TIMER0, true);

    //  // Configure TIMER1 Compare/Capture for output compare
    //  // Use PWM mode, which sets output on overflow and clears on compare events
    //  TIMER_InitCC_TypeDef timerCCInit = TIMER_INITCC_DEFAULT;
    //  timerCCInit.mode = timerCCModePWM;
    //  TIMER_InitCC(TIMER1, 0, &timerCCInit);

    //  // Route TIMER1 CC0 to location 0 and enable CC0 route pin
    //  // TIM1_CC0 #0 is GPIO Pin PC13
    //  TIMER1->ROUTELOC0 |=  TIMER_ROUTELOC0_CC0LOC_LOC0;
    //  TIMER1->ROUTEPEN |= TIMER_ROUTEPEN_CC0PEN;

    // Set top value to overflow at the desired PWM_FREQ frequency
    TIMER_TopSet(TIMER0, CMU_ClockFreqGet(cmuClock_TIMER0) / micSAMPLINGRATE2K);

    // Initialize the timer
    TIMER_Init_TypeDef timerInit = TIMER_INIT_DEFAULT;
    TIMER_Init(TIMER0, &timerInit);

    // Enable TIMER1 compare event interrupts to update the duty cycle
    TIMER_IntEnable(TIMER0, TIMER_IEN_OF);
    NVIC_EnableIRQ(TIMER0_IRQn);
}

/**************************************************************************/ /**
                                                                              * @brief
                                                                              *    TIMER
                                                                              * initialization
                                                                              *****************************************************************************/
void init_WTIMER1(void) {
    // Enable clock for TIMER1 module
    CMU_ClockEnable(cmuClock_TIMER1, true);

    // Configure TIMER1 Compare/Capture for output compare
    TIMER_InitCC_TypeDef timerCCInit = TIMER_INITCC_DEFAULT;
    timerCCInit.mode = timerCCModeCompare;
    timerCCInit.cmoa = timerOutputActionToggle;
    TIMER_InitCC(TIMER1, 0, &timerCCInit);

    // Set route to Location 0 and enable
    // TIM1_CC0 #5 is PF2
    TIMER1->ROUTELOC0 |= TIMER_ROUTELOC0_CC0LOC_LOC5;
    TIMER1->ROUTEPEN |= TIMER_ROUTEPEN_CC0PEN;

    // Set Top value
    // Note each overflow event constitutes 1/2 the signal period
    uint32_t topValue =
        CMU_ClockFreqGet(cmuClock_HFPER) / (2 * OUT_FREQ * (1 << TIMER1_PRESCALE)) - 1;
    TIMER_TopSet(TIMER1, topValue);

    // Initialize and start timer with defined prescale
    TIMER_Init_TypeDef timerInit = TIMER_INIT_DEFAULT;
    timerInit.prescale = TIMER1_PRESCALE;
    TIMER_Init(TIMER1, &timerInit);
}

/**************************************************************************/ /**
                                                                              * @brief
                                                                              *    TIMER
                                                                              * initialization
                                                                              *****************************************************************************/
void init_WTIMER3(void) {
    // Enable clock for WTIMER0 module
    CMU_ClockEnable(cmuClock_WTIMER3, true);

    // Configure WTIMER0 Compare/Capture for output compare
    TIMER_InitCC_TypeDef wtimerCCInit = TIMER_INITCC_DEFAULT;
    wtimerCCInit.mode = timerCCModeCompare;
    wtimerCCInit.cmoa = timerOutputActionToggle;
    TIMER_InitCC(WTIMER3, 0, &wtimerCCInit);

    // Set route to Location 7 and enable
    // WTIM0_CC0 #7 is PB6
    WTIMER3->ROUTELOC0 |= TIMER_ROUTELOC0_CC0LOC_LOC6;
    WTIMER3->ROUTEPEN |= TIMER_ROUTEPEN_CC0PEN;

    // Set Top value
    // Note each overflow event constitutes 1/2 the signal period
    uint32_t topValue =
        CMU_ClockFreqGet(cmuClock_HFPER) / (2 * OUT_FREQ_WTIMER * (1 << WTIMER3_PRESCALE));
    TIMER_TopSet(WTIMER3, topValue);

    // Initialize and start wtimer with defined prescale
    TIMER_Init_TypeDef wtimerInit = TIMER_INIT_DEFAULT;
    wtimerInit.prescale = WTIMER3_PRESCALE;
    TIMER_Init(WTIMER3, &wtimerInit);
}

double humidity_caculation(uint16_t rawdata) {
    double data = rawdata;
    data = data / 65536;
    data = data * 100;
    return data;
}

double calculate_temperature(uint16_t temp_raw_data) {
    return (temp_raw_data / 65536.0) * 165 - 40;
}

// init usart0 and connect the LTE
// receive at command by ISR
void init_USART(void) {
    USART_InitAsync_TypeDef init = USART_INITASYNC_DEFAULT;
    init.baudrate = 115200;
    // Enable oscillator to GPIO and USART0 modules
    CMU_ClockEnable(cmuClock_GPIO, true);
    CMU_ClockEnable(cmuClock_USART0, true);

    // set pin modes for UART0 TX and RX pins
    // usart_tx sent messange to LTE_TX and usart0_rx receive message from LTE_RX
    GPIO_PinModeSet(gpioPortE, 6, gpioModeInput, 0);    // LTE_Rx (it's input for MCU)
    GPIO_PinModeSet(gpioPortE, 7, gpioModePushPull, 1); // LTE_Tx (it's output for MCU)

    // Enable NVIC USART sources
    NVIC_ClearPendingIRQ(USART0_RX_IRQn);
    NVIC_EnableIRQ(USART0_RX_IRQn);
    //  NVIC_ClearPendingIRQ(USART0_TX_IRQn);
    //  NVIC_EnableIRQ(USART0_TX_IRQn);

    // Initialize USART asynchronous mode and route pins
    USART_InitAsync(USART0, &init);
    USART0->ROUTELOC0 = USART_ROUTELOC0_RXLOC_LOC1 | USART_ROUTELOC0_TXLOC_LOC1;
    USART0->ROUTEPEN |= USART_ROUTEPEN_TXPEN | USART_ROUTEPEN_RXPEN;
}

void init_log(void) {
    USART_InitAsync_TypeDef init = USART_INITASYNC_DEFAULT;
    init.baudrate = 115200;
    // Enable oscillator to GPIO and USART0 modules
    CMU_ClockEnable(cmuClock_GPIO, true);
    CMU_ClockEnable(cmuClock_UART0, true);

    // set pin modes for UART0 TX and RX pins
    // PC4(TX), PC5(RX)
    GPIO_PinModeSet(gpioPortC, 5, gpioModeInput, 0);    // Rx
    GPIO_PinModeSet(gpioPortC, 4, gpioModePushPull, 1); // Tx

    // Initialize USART asynchronous mode and route pins
    USART_InitAsync(UART0, &init);
    UART0->ROUTELOC0 = USART_ROUTELOC0_RXLOC_LOC4 | USART_ROUTELOC0_TXLOC_LOC4;
    UART0->ROUTEPEN |= USART_ROUTEPEN_TXPEN | USART_ROUTEPEN_RXPEN;
}

// print log messages through UART0
void print_log(char message[], int len) {
    int i = 0;
    for (i = 0; i < len; i++) {
        USART_Tx(UART0, message[i]);
    }
}

// void init_SD_Card() {
// 	SDIO_Init(SDIO, 0, cmuClock_SDIO);
// 	GPIO_PinModeSet(gpioPortE, 13, gpioModePushPull, 0); //CLK
// 	GPIO_PinModeSet(gpioPortE, 12, gpioModePushPull, 1); //CMD
// 	GPIO_PinModeSet(gpioPortE, 11, gpioModePushPull, 0); //Data0
// 	GPIO_PinModeSet(gpioPortE, 10, gpioModePushPull, 0); //Data1
// 	GPIO_PinModeSet(gpioPortE, 9, gpioModePushPull, 0); //Data2
// 	GPIO_PinModeSet(gpioPortE, 8, gpioModePushPull, 0); //Data3
// 	SDIO->ROUTELOC0 |= SDIO_ROUTELOC0_DATLOC_LOC0 | SDIO_ROUTELOC0_CLKLOC_LOC0 |
// SDIO_ROUTELOC1_CMDLOC_LOC0;
// }
/*
void init_RTC(){
        static const RTC_Init_TypeDef rtcInit =
        {
                .enable   = false,
                .debugRun = false,
                .comp0Top = true
        };

        RTC_Init(&rtcInit);

        // Set compare value
        RTC_CompareSet(0, RTC_COMP_VALUE);
        RTC_IntEnable(RTC_IFS_COMP0);
        NVIC_EnableIRQ(RTC_IRQn);

}
*/
