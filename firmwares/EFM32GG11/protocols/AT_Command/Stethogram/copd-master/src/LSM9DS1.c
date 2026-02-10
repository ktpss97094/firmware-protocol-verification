#include "LSM9DS1.h"

void ReadAccelData(uint16_t *destination) {

    I2cData.bAddr = LSM9DS1_ADDRESS;
    I2cData.bSendBuf[0] = OUT_X_L_XL;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 6;
    I2cRegRead();

    destination[0] = ((int16_t)I2cData.bRecBuf[1] << 8 |
                      I2cData.bRecBuf[0]); // Turn the MSB and LSB into a signed 16-bit value
    destination[1] = ((int16_t)I2cData.bRecBuf[3] << 8 | I2cData.bRecBuf[2]);
    destination[2] = ((int16_t)I2cData.bRecBuf[5] << 8 | I2cData.bRecBuf[4]);
}

void ReadGyroData(uint16_t *destination) {

    I2cData.bAddr = LSM9DS1_ADDRESS;
    I2cData.bSendBuf[0] = OUT_X_L_G;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 6;
    I2cRegRead();

    destination[0] = ((int16_t)I2cData.bRecBuf[1] << 8 |
                      I2cData.bRecBuf[0]); // Turn the MSB and LSB into a signed 16-bit value
    destination[1] = ((int16_t)I2cData.bRecBuf[3] << 8 | I2cData.bRecBuf[2]);
    destination[2] = ((int16_t)I2cData.bRecBuf[5] << 8 | I2cData.bRecBuf[4]);
}

bool LSM9DS1RegWrite(uint8_t reg, uint8_t bData) {
    I2cData.bAddr = LSM9DS1_ADDRESS;
    I2cData.bSendBuf[0] = reg;
    I2cData.bSendBuf[1] = bData;
    I2cData.bSendLen = 2;

    if (I2cWrite() == FALSE) {
        return FALSE;
    }
    return TRUE;
}

void initAccel(void) {
    //	CTRL_REG5_XL (0x1F) (Default value: 0x38)
    //	[DEC_1][DEC_0][Zen_XL][Yen_XL][Zen_XL][0][0][0]
    //	DEC[0:1] - Decimation of accel data on OUT REG and FIFO.
    //		00: None, 01: 2 samples, 10: 4 samples 11: 8 samples
    //	Zen_XL - Z-axis output enabled
    //	Yen_XL - Y-axis output enabled
    //	Xen_XL - X-axis output enabled

    LSM9DS1RegWrite(CTRL_REG5_XL, 0xF8);

    // CTRL_REG6_XL (0x20) (Default value: 0x00)
    // [ODR_XL2][ODR_XL1][ODR_XL0][FS1_XL][FS0_XL][BW_SCAL_ODR][BW_XL1][BW_XL0]
    // ODR_XL[2:0] - Output data rate & power mode selection
    // FS_XL[1:0] - Full-scale selection
    // BW_SCAL_ODR - Bandwidth selection
    // BW_XL[1:0] - Anti-aliasing filter bandwidth selection

    // To disable the accel, set the sampleRate bits to 0.
    LSM9DS1RegWrite(CTRL_REG6_XL, CTRL_REG6_INIT); // 0110 0000

    // CTRL_REG7_XL (0x21) (Default value: 0x00)
    // [HR][DCF1][DCF0][0][0][FDS][0][HPIS1]
    // HR - High resolution mode (0: disable, 1: enable)
    // DCF[1:0] - Digital filter cutoff frequency
    // FDS - Filtered data selection
    // HPIS1 - HPF enabled for interrupt function
    LSM9DS1RegWrite(CTRL_REG7_XL, 0x00);
}

void initGyro(void) {

    // CTRL_REG1_G (Default value: 0x00)
    // [ODR_G2][ODR_G1][ODR_G0][FS_G1][FS_G0][0][BW_G1][BW_G0]
    // ODR_G[2:0] - Output data rate selection
    // FS_G[1:0] - Gyroscope full-scale selection
    // BW_G[1:0] - Gyroscope bandwidth selection

    // To disable gyro, set sample rate bits to 0. We'll only set sample
    // rate if the gyro is enabled.

    LSM9DS1RegWrite(CTRL_REG1_G, CTRL_REG1_INIT);

    // CTRL_REG2_G (Default value: 0x00)
    // [0][0][0][0][INT_SEL1][INT_SEL0][OUT_SEL1][OUT_SEL0]
    // INT_SEL[1:0] - INT selection configuration
    // OUT_SEL[1:0] - Out selection configuration

    LSM9DS1RegWrite(CTRL_REG2_G, 0x00);

    // CTRL_REG3_G (Default value: 0x00)
    // [LP_mode][HP_EN][0][0][HPCF3_G][HPCF2_G][HPCF1_G][HPCF0_G]
    // LP_mode - Low-power mode enable (0: disabled, 1: enabled)
    // HP_EN - HPF enable (0:disabled, 1: enabled)
    // HPCF_G[3:0] - HPF cutoff frequency

    LSM9DS1RegWrite(CTRL_REG3_G, 0x00);

    // CTRL_REG4 (Default value: 0x38)
    // [0][0][Zen_G][Yen_G][Xen_G][0][LIR_XL1][4D_XL1]
    // Zen_G - Z-axis output enable (0:disable, 1:enable)
    // Yen_G - Y-axis output enable (0:disable, 1:enable)
    // Xen_G - X-axis output enable (0:disable, 1:enable)
    // LIR_XL1 - Latched interrupt (0:not latched, 1:latched)
    // 4D_XL1 - 4D option on interrupt (0:6D used, 1:4D used)

    LSM9DS1RegWrite(CTRL_REG4, 0x38);

    // ORIENT_CFG_G (Default value: 0x00)
    // [0][0][SignX_G][SignY_G][SignZ_G][Orient_2][Orient_1][Orient_0]
    // SignX_G - Pitch axis (X) angular rate sign (0: positive, 1: negative)
    // Orient [2:0] - Directional user orientation selection

    LSM9DS1RegWrite(ORIENT_CFG_G, 0x00);
}

void LSM9DS1ReadWhoAmI(uint8_t *destination) {
    I2cData.bAddr = LSM9DS1_ADDRESS;
    I2cData.bSendBuf[0] = WHO_AM_I_XG;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 1;
    I2cRegRead();
    // IF REGREAD SUCESSFUL , the the result will be 0x68
    destination[0] = I2cData.bRecBuf[0];
    destination[1] = I2cData.bRecBuf[1];
    destination[2] = I2cData.bRecBuf[0];
    destination[3] = I2cData.bRecBuf[1];
}
void initIntr(void) {
    /*	config Interrupt */
    // LSM9DS1RegWrite(INT_GEN_CFG_XL,0x82);
    // LSM9DS1RegWrite(CTRL_REG8,0x24);	// ACTIVITE LOW
    // LSM9DS1RegWrite(INT1_CTRL,0x41);

    /*	config Interrupt testing */
    LSM9DS1RegWrite(INT_GEN_CFG_XL, 0x82);
    LSM9DS1RegWrite(CTRL_REG8, 0x24); // ACTIVITE LOW
    LSM9DS1RegWrite(INT1_CTRL, 0x41);
}
void LSM9DS1Init(void) {
    initAccel();
    initGyro();
    initIntr();
}
