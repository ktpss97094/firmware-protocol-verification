/*
 * i2c.h
 *
 *  Created on: 2019?~8??6ωθωβ
 *      Author: Ryan
 *  modified by alexhsu on 2020/03/20
 */

#ifndef _BB_V0_INC_I2C_H_
#define _BB_V0_INC_I2C_H_

#include "em_gpio.h"
/*  For bluebox i2c1 define
#define I2C1_SCL_PJ14          (10)
#define I2C1_SDA_PJ15          (12)

#define I2C_MAX_BUFFER_SIZE   (64)

#define I2C_SCL_PORT          (gpioPortJ)
#define I2C_SDA_PORT          (gpioPortJ)
#define I2C_SCL_PIN           (14)
#define I2C_SDA_PIN           (15)
#define I2C_SCL_ROUTELOC      (I2C1_SCL_PJ14)
#define I2C_SDA_ROUTELOC      (I2C1_SDA_PJ15)
*/

/* For COPD i2c0 define */
#define I2C0_SCL_PC7 (2)
#define I2C0_SDA_PC6 (2)

#define I2C_MAX_BUFFER_SIZE (64)

#define I2C_SCL_PORT (gpioPortC)
#define I2C_SDA_PORT (gpioPortC)
#define I2C_SCL_PIN (7)
#define I2C_SDA_PIN (6)
#define I2C_SCL_ROUTELOC (I2C0_SCL_PC7)
#define I2C_SDA_ROUTELOC (I2C0_SDA_PC6)

/* i2c0 define end  */

#define FALSE (0)
#define TRUE (1)

typedef struct I2cCtrlST {
    uint8_t bAddr;
    uint8_t bSendBuf[I2C_MAX_BUFFER_SIZE];
    uint8_t bRecBuf[I2C_MAX_BUFFER_SIZE];
    uint8_t bSendLen;
    uint8_t bRecLen;
} I2cCtrlType;

extern int I2cRegRead(void);
extern int I2cWrite(void);
extern void init_I2C(void);
extern int I2cRead(void);

extern I2cCtrlType I2cData;

#endif /* _BB_V0_INC_I2C_H_ */
