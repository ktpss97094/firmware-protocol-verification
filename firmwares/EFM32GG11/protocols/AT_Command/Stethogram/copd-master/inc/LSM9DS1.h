#include "i2c.h"

// Register Map

#ifndef __LSM9DS1_Registers_H__
#define __LSM9DS1_Registers_H__

/////////////////////////////////////////
// LSM9DS1 Accel/Gyro (XL/G) Registers //
/////////////////////////////////////////
#define ACT_THS 0x04
#define ACT_DUR 0x05
#define INT_GEN_CFG_XL 0x06
#define INT_GEN_THS_X_XL 0x07
#define INT_GEN_THS_Y_XL 0x08
#define INT_GEN_THS_Z_XL 0x09
#define INT_GEN_DUR_XL 0x0A
#define REFERENCE_G 0x0B
#define INT1_CTRL 0x0C
#define INT2_CTRL 0x0D
#define WHO_AM_I_XG 0x0F
#define CTRL_REG1_G 0x10
#define CTRL_REG2_G 0x11
#define CTRL_REG3_G 0x12
#define ORIENT_CFG_G 0x13
#define INT_GEN_SRC_G 0x14
#define OUT_TEMP_L 0x15
#define OUT_TEMP_H 0x16
#define STATUS_REG_0 0x17
#define OUT_X_L_G 0x18
#define OUT_X_H_G 0x19
#define OUT_Y_L_G 0x1A
#define OUT_Y_H_G 0x1B
#define OUT_Z_L_G 0x1C
#define OUT_Z_H_G 0x1D
#define CTRL_REG4 0x1E
#define CTRL_REG5_XL 0x1F
#define CTRL_REG6_XL 0x20
#define CTRL_REG7_XL 0x21
#define CTRL_REG8 0x22
#define CTRL_REG9 0x23
#define CTRL_REG10 0x24
#define INT_GEN_SRC_XL 0x26
#define STATUS_REG_1 0x27
#define OUT_X_L_XL 0x28
#define OUT_X_H_XL 0x29
#define OUT_Y_L_XL 0x2A
#define OUT_Y_H_XL 0x2B
#define OUT_Z_L_XL 0x2C
#define OUT_Z_H_XL 0x2D
#define FIFO_CTRL 0x2E
#define FIFO_SRC 0x2F
#define INT_GEN_CFG_G 0x30
#define INT_GEN_THS_XH_G 0x31
#define INT_GEN_THS_XL_G 0x32
#define INT_GEN_THS_YH_G 0x33
#define INT_GEN_THS_YL_G 0x34
#define INT_GEN_THS_ZH_G 0x35
#define INT_GEN_THS_ZL_G 0x36
#define INT_GEN_DUR_G 0x37

///////////////////////////////
// LSM9DS1 Magneto Registers //
///////////////////////////////
#define OFFSET_X_REG_L_M 0x05
#define OFFSET_X_REG_H_M 0x06
#define OFFSET_Y_REG_L_M 0x07
#define OFFSET_Y_REG_H_M 0x08
#define OFFSET_Z_REG_L_M 0x09
#define OFFSET_Z_REG_H_M 0x0A
#define WHO_AM_I_M 0x0F
#define CTRL_REG1_M 0x20
#define CTRL_REG2_M 0x21
#define CTRL_REG3_M 0x22
#define CTRL_REG4_M 0x23
#define CTRL_REG5_M 0x24
#define STATUS_REG_M 0x27
#define OUT_X_L_M 0x28
#define OUT_X_H_M 0x29
#define OUT_Y_L_M 0x2A
#define OUT_Y_H_M 0x2B
#define OUT_Z_L_M 0x2C
#define OUT_Z_H_M 0x2D
#define INT_CFG_M 0x30
#define INT_SRC_M 0x30
#define INT_THS_L_M 0x32
#define INT_THS_H_M 0x33

////////////////////////////////
// LSM9DS1 WHO_AM_I Responses //
////////////////////////////////
#define WHO_AM_I_AG_RSP 0x68
#define WHO_AM_I_M_RSP 0x3D

/* Ryan define function	*/
#define _CTRL_REG1_G_ODR_G_SHIFT 5
#define _CTRL_REG1_G_ODR_G_MASK 0x000000E0UL
#define _CTRL_REG1_G_ODR_G_DEFAULT 0x00000000UL
#define _CTRL_REG1_G_ODR_G_PWDOWN 0x00000000UL
#define _CTRL_REG1_G_ODR_G_119ODR 0x00000003UL

#define _CTRL_REG1_G_FS_G_SHIFT 3
#define _CTRL_REG1_G_FS_G_MASK 0x00000018UL
#define _CTRL_REG1_G_FS_G_DEFAULT 0x00000000UL
#define _CTRL_REG1_G_FS_G_245DPS 0x00000000UL
#define _CTRL_REG1_G_FS_G_500DPS 0x00000001UL
#define _CTRL_REG1_G_FS_G_2000DPS 0x00000003UL

#define _CTRL_REG1_G_BW_G_SHIFT 0
#define _CTRL_REG1_G_BW_G_MASK 0x00000003UL
#define _CTRL_REG1_G_BW_G_DEFAULT 0x00000000UL

#define _CTRL_REG6_XL_ODR_XL_SHIFT 5
#define _CTRL_REG6_XL_ODR_XL_MASK 0x000000E0UL
#define _CTRL_REG6_XL_ODR_XL_DEFAULT 0x00000000UL
#define _CTRL_REG6_XL_ODR_XL_119ODR 0x00000003UL

#define _CTRL_REG6_XL_FS_XL_SHIFT 3
#define _CTRL_REG6_XL_FS_XL_MASK 0x00000018UL
#define _CTRL_REG6_XL_FS_XL_DEFAULT 0x00000000UL
#define _CTRL_REG6_XL_FS_XL_2G 0x00000000UL
#define _CTRL_REG6_XL_FS_XL_16G 0x00000001UL
#define _CTRL_REG6_XL_FS_XL_4G 0x00000002UL
#define _CTRL_REG6_XL_FS_XL_8G 0x00000003UL

#define _CTRL_REG6_XL_BW_G_SHIFT 0
#define _CTRL_REG6_XL_BW_G_MASK 0x00000003UL
#define _CTRL_REG6_XL_BW_G_DEFAULT 0x00000000UL
/* Set the output frequency to 119Hz. 500DPS  14Hz cutoff*/
#define CTRL_REG1_INIT                                                                             \
    (_CTRL_REG1_G_ODR_G_119ODR << _CTRL_REG1_G_ODR_G_SHIFT) |                                      \
        (_CTRL_REG1_G_FS_G_500DPS << _CTRL_REG1_G_FS_G_SHIFT) |                                    \
        (_CTRL_REG1_G_BW_G_DEFAULT << _CTRL_REG1_G_BW_G_SHIFT)
#define CTRL_REG6_INIT                                                                             \
    (_CTRL_REG6_XL_ODR_XL_119ODR << _CTRL_REG6_XL_ODR_XL_SHIFT) |                                  \
        (_CTRL_REG6_XL_FS_XL_4G << _CTRL_REG6_XL_FS_XL_SHIFT) |                                    \
        (_CTRL_REG6_XL_BW_G_DEFAULT << _CTRL_REG6_XL_BW_G_SHIFT)

// Slave address
#define LSM9DS1_ADDRESS 0xD5          // for write
#define LSM9DS1_Magnetic_ADDRESS 0x38 // for write

void initIntr(void);
void LSM9DS1Init(void);
// extern void ReadLSM9DS1Data(short * destination);
void ReadAccelData(uint16_t *destination);
void ReadGyroData(uint16_t *destination);
void ReadMagnData(uint16_t *destination);
void LSM9DS1ReadWhoAmI(uint8_t *destination);

bool LSM9DS1RegWrite(uint8_t reg, uint8_t bData);

#endif
