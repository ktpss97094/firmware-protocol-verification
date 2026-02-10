#include "at_cmd.h"
#include "em_cmu.h"
#include "em_gpio.h"
#include "em_usart.h"
#include <stdio.h>
#include <string.h>

/* Defines and Macros from function.c */
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

/* External dependencies */
extern void Delay(uint32_t dlyTicks);
extern char log_message_buf[200];

extern char APIkey[20];
extern char http_str[100];
extern char cmd01[80];
extern char micdatalte[2][4096];
extern int settime;
extern int countdown;
extern int micindex;
extern int micdataindex;

void init_LTE(void) {

    /* Initialize buffers to '0' as per original main.c logic */
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 4096; j++) {
            micdatalte[i][j] = '0';
        }
    }

    PWR_4V_EN_ON();
    LTE_PWRON_INIT();
    LTE_RSTB_INIT();
    LTE_PWRON_OFF();
    LTE_RSTB_OFF();

    PWR_4V_EN_OFF();
    PWR_4V_EN_ON();

    LTE_RSTB_ON();
    LTE_PWRON_ON();
}

void send_AT_Command(char command[]) {
    for (int i = 0; command[i] != '\0'; i++) {
        USART_Tx(USART0, command[i]);
    }
}

/* API Implementations */

void LTE_Send_Int(int value) {
    char cmd[80];
    snprintf(cmd, 80, "%d", value);
    send_AT_Command(cmd);
}

void LTE_Set_Function_Mode(int mode) {
    char cmd[80];
    snprintf(cmd, 80, "AT+CFUN=%d\r\n", mode);
    send_AT_Command(cmd);
    Delay(500);
}

void LTE_Check_Sim_Status(void) {
    send_AT_Command("AT+CPIN?\r\n");
    Delay(500);
}

void LTE_Set_Context(char *apn) {
    char cmd[80];
    snprintf(cmd, 80, "AT+CGDCONT=1,\"IP\",\"%s\"\r\n", apn);
    send_AT_Command(cmd);
    Delay(500);
}

void LTE_Activate_Context(void) {
    send_AT_Command("AT+CGACT=1,1\r\n");
    Delay(500);
}

void LTE_Clear_Context_8(void) {
    send_AT_Command("AT+CGDCONT=8\r\n");
    Delay(500);
}

void LTE_Auto_Select_Operator(void) {
    send_AT_Command("AT+COPS=0\r\n");
    Delay(500);
}

void LTE_Check_Connection_Status(void) {
    send_AT_Command("AT+CGACT?\r\n");
    Delay(500);
    send_AT_Command("AT+COPS?\r\n");
    Delay(500);
    send_AT_Command("AT+CGDCONT?\r\n");
    Delay(500);
}

void LTE_Configure_PSD(void) {
    send_AT_Command("AT+UPSD=0,100,1\r\n");
    Delay(500);
    send_AT_Command("AT+UPSDA=0,3\r\n");
    Delay(500);
    send_AT_Command("AT+UPSND=0,8\r\n");
    Delay(500);
}

void LTE_Create_Socket(int protocol) {
    char cmd[80];
    snprintf(cmd, 80, "AT+USOCR=%d\r\n", protocol);
    send_AT_Command(cmd);
    Delay(500);
}

void LTE_Connect_Socket(char *ip, int port) {
    char cmd[80];
    snprintf(cmd, 80, "AT+USOCO=0,\"%s\",%d\r\n", ip, port);
    send_AT_Command(cmd);
    Delay(500);
}

void LTE_Enter_Direct_Link(void) {
    send_AT_Command("AT+USODL=0\r\n");
    Delay(500);
}

void LTE_SwitchToCmdMode(void) {
    // send_AT_Command("+++\r\n");
    // Delay(500);

    /* Compliant version */
    Delay(1000);
    send_AT_Command("+++");
    Delay(1000);
}

void LTE_Send_Data_Block(char *data) {
    send_AT_Command(data);
    Delay(100);
}
