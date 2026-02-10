#ifndef AT_CMD_H_
#define AT_CMD_H_

#include <stdbool.h>
#include <stdint.h>

/**
 * @file at_cmd.h
 * @brief LTE Module AT Command Driver
 * @details This driver manages the specific AT commands for u-blox LTE modules.
 *          It encapsulates 3GPP and vendor-specific commands into C APIs.
 */

/* =========================================================================
 *  Initialization & Transport
 * ========================================================================= */

/**
 * @brief Initialize the LTE module hardware control pins.
 *        Configures Power and Reset pins for the modem.
 */
void init_LTE(void);

/**
 * @brief Send raw ASCII string to the module via USART.
 * @param command Null-terminated string command.
 */
void send_AT_Command(char command[]);

/* =========================================================================
 *  LTE / Network Control APIs
 *  (Specific to Cellular/LTE Modules)
 * ========================================================================= */

/**
 * @brief Send an integer value as a command string.
 * @param value The integer to send.
 */
void LTE_Send_Int(int value);

/**
 * @brief Set the module functionality (AT+CFUN).
 * @param mode 1: Full functionality, 0: Minimum functionality, 4: Airplane mode.
 */
void LTE_Set_Function_Mode(int mode);

/**
 * @brief Check SIM card status (AT+CPIN?).
 */
void LTE_Check_Sim_Status(void);

/**
 * @brief Set Packet Data Protocol (PDP) Context (AT+CGDCONT).
 * @param apn Access Point Name string (e.g., "internet").
 */
void LTE_Set_Context(char *apn);

/**
 * @brief Activate PDP Context (AT+CGACT).
 *        Enables data connection.
 */
void LTE_Activate_Context(void);

/**
 * @brief Clear PDP Context ID 8 (AT+CGDCONT=8).
 *        Specific fix for certain network barriers.
 */
void LTE_Clear_Context_8(void);

/**
 * @brief Automatically select network operator (AT+COPS=0).
 */
void LTE_Auto_Select_Operator(void);

/**
 * @brief Debug routine to check connection status.
 *        Queries CGACT, COPS, and CGDCONT.
 */
void LTE_Check_Connection_Status(void);

/**
 * @brief Configure Packet Switched Data (PSD) profiles.
 *        (u-blox specific: AT+UPSD, UPSDA, UPSND)
 */
void LTE_Configure_PSD(void);

/* =========================================================================
 *  Socket / Data Control APIs
 *  (u-blox specific TCP/IP stack)
 * ========================================================================= */

/**
 * @brief Create a socket (AT+USOCR).
 * @param protocol 6: TCP, 17: UDP.
 */
void LTE_Create_Socket(int protocol);

/**
 * @brief Connect socket to remote server (AT+USOCO).
 * @param ip Remote IP address string.
 * @param port Remote port number.
 */
void LTE_Connect_Socket(char *ip, int port);

/**
 * @brief Enter Direct Link mode for transparent data transmission (AT+USODL).
 */
void LTE_Enter_Direct_Link(void);

/**
 * @brief Send Escape Sequence (+++) to exit data mode.
 */
void LTE_SwitchToCmdMode(void);

/**
 * @brief Send a block of data to the module.
 * @param data Pointer to data buffer.
 */
void LTE_Send_Data_Block(char *data);

#endif /* AT_CMD_H_ */
