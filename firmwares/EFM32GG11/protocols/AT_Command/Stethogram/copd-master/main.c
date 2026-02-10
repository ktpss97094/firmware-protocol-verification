/******************************************************************************
 * @file main.c
 * @brief empty example for COPD
 * @author Ryan ->Tiger
 * @version  0.1 -> 1.0
 ******************************************************************************/

#include "Adc.h"
#include "CCS811.h"
#include "HDC2080.h"
#include "LSM9DS1.h"
#include "at_cmd.h"
#include "em_chip.h"
#include "em_cmu.h"
#include "em_device.h"
#include "em_emu.h"
#include "em_gpio.h"
#include "em_usart.h"
#include "example.h"
#include "function.h"
#include "i2s.h"
#include "led.h"
#include "sdio.h"
#include "usart.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* for test */
#define BUFLEN 800
uint8_t testBuffer[1];

uint8_t bufferr2[512];
int sd_output = 0x00;
/*LTE Usart ISR*/
char bufferr[BUFLEN]; // receive rx data
uint32_t inpos = 0;
uint32_t outpos = 0;
bool receive = false;
int device_mode = 1;
uint32_t command_flag = 0;
/* All get data variable	*/
double temperature = 0.0;
uint16_t humidityBuffer[1];
uint16_t temperatureBuffer[1];
uint16_t vocBuffer[4];
uint8_t voc[2];
double humidity_data = 0.0;
uint8_t nine_axisBuffer[18];
uint16_t accBuffer[3];
uint16_t gyrBuffer[3];
unsigned int clock_get = 0;
unsigned int clock_get_2 = 0;
unsigned int clock_get_3 = 0;
unsigned int clock_get_4 = 0;
unsigned int timelength = 0;
/* All flag	*/
uint8_t ambient_flag = 0;
uint8_t mic_flag = 0;
uint8_t SYSMirror[1024];
/* i2s	*/
int16_t Mic_Left_Buffer[BUFFER_SIZE_I2S];
int16_t Mic_Right_Buffer[BUFFER_SIZE_I2S];
extern int leftBufferIndex;
char log_message_buf[200];
volatile uint32_t msTicks; /* counts 1ms timeTicks */
char Leftmic[20] = "Leftbuffer: ";
char Rightmic[20] = "Rightbuffer: ";
int sdbufferindex = 0;
uint32_t sdcardindex = 0;

char APIkey[20] = "1B3CLVMMUEMHW5A8";
char http_str[100] =
    "at+HTTPPARA=https://api.thingspeak.com/update?api_key=1B3CLVMMUEMHW5A8&field1=&field2= \r\n";
char cmd01[80] = "AT+CPIN?\r\n";
char micdatalte[2][4096];
int settime = 3;
int countdown = 30;
int micindex = 0;
int micdataindex = 0;
/******************************************************************************
 * @brief SysTick_Handler
 * Interrupt Service Routine for system tick counter
 *****************************************************************************/
void SysTick_Handler(void) { msTicks++; /* increment counter necessary in Delay()*/ }

/******************************************************************************
 * @brief Delays number of msTick Systicks (typically 1 ms)
 * @param dlyTicks Number of ticks to delay
 *****************************************************************************/
void Delay(uint32_t dlyTicks) {
    uint32_t curTicks;

    curTicks = msTicks;
    while ((msTicks - curTicks) < dlyTicks)
        ;
}

/******************************************************************************
 * @brief  Main function
 * Main is called from _program_start, see assembly startup file
 *****************************************************************************/

int main(void) {
    /* Initialize chip */
    CHIP_Init();

    /* Setup SysTick Timer for 1 msec interrupts  */
    if (SysTick_Config(CMU_ClockFreqGet(cmuClock_CORE) / 1000)) {
        while (1)
            ;
    }

    /* initial peripheral */
    init_peripheral();

    init_LTE();

    init_USART();

    LTE_SwitchToCmdMode();

    SYMBOL_MARKER("END_SYMBOLIC_EXECUTION");
}

void CRYOTIMER_IRQHandler(void) {
    uint32_t flags = CRYOTIMER_IntGet();
    CRYOTIMER_IntClear(flags);
    GPIO_PinOutToggle(LED_1_Port, LED_1_Pin);
    ambient_flag++;
}

void TIMER0_IRQHandler(void) {
    TIMER_IntClear(TIMER0, TIMER_IF_OF);
    mic_flag++; // no use
}

/* for mic	*/
void LDMA_IRQHandler(void) {
    // Clear all interrupt flags
    LDMA->IFC |= 0xFFFFFFFF;
    leftBufferIndex = 0;
}
void USART0_RX_IRQHandler(void) // receive one by one and print
{
    bufferr[0] = USART0->RXDATA;
    print_log(bufferr, 1);
}
