#include "CCS811.h"
#include "em_cmu.h"
#include "em_i2c.h"
#include "stdio.h"

void Read_eCO2_and_eTVOC_Data(uint16_t *destination) {

    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bSendBuf[0] = ALG_RESULT_DATA;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 8;
    I2cRegRead();

    destination[0] = ((int16_t)I2cData.bRecBuf[0] << 8 |
                      I2cData.bRecBuf[1]); // Turn the MSB and LSB into a signed 16-bit value
    destination[1] = ((int16_t)I2cData.bRecBuf[2] << 8 | I2cData.bRecBuf[3]);
    destination[2] = ((int16_t)I2cData.bRecBuf[4] << 8 |
                      I2cData.bRecBuf[5]); // Turn the MSB and LSB into a signed 16-bit value
    destination[3] = ((int16_t)I2cData.bRecBuf[6] << 8 | I2cData.bRecBuf[7]);
}

void Read_eCO2_and_eTVOC_Data2(uint16_t *destination) {

    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bSendBuf[0] = ALG_RESULT_DATA;
    I2cData.bSendLen = 1;
    I2cWrite();

    // read eCO2
    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bRecLen = 2;
    I2cRead();
    destination[0] = ((int16_t)I2cData.bRecBuf[0] << 8 |
                      I2cData.bRecBuf[1]); // Turn the MSB and LSB into a signed 16-bit value

    // read eTVOC
    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bRecLen = 2;
    I2cRead();
    destination[1] = ((int16_t)I2cData.bRecBuf[0] << 8 |
                      I2cData.bRecBuf[1]); // Turn the MSB and LSB into a signed 16-bit value
}

void CCS811ReadWhoAmI(uint8_t *destination) {

    I2cData.bAddr = CCS811_ADDRESS; // Datasheet: 0x5A 0X5B Vitalsign: 0xB4 0XB5
    I2cData.bSendBuf[0] = 0x20;
    I2cData.bSendLen = 0;
    I2cData.bRecLen = 1;
    I2cRead();
    //  if (I2cRead()) printf("CCS811 I2C Read Sucessful!\n");
    //  else printf("CCS811 I2C Read Failed!\n");

    destination[0] = I2cData.bRecBuf[0];
}

bool CCS811RegWrite(uint8_t reg, uint8_t bData) {
    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bSendBuf[0] = reg;
    I2cData.bSendBuf[1] = bData;
    I2cData.bSendLen = 2;

    if (I2cWrite() == FALSE) {
        return FALSE;
    }
    return TRUE;
}

void CCS811Init(void) {
    // need RegWrite to APP_START register but don't need write any data
    /*
    I2cData.bAddr = 0xB5;
    I2cData.bSendBuf[0] = APP_START_REG;
    I2cData.bSendLen = 1;
    if (I2cWrite()) printf("CCS811Init I2C WRITE Sucessful!\n");
    else printf("CCS811Init I2C WRITE Failed!\n");
    */
    I2cData.bAddr = CCS811_ADDRESS;
    I2cData.bSendBuf[0] = APP_START_REG;
    // I2cData.bSendBuf[1] = bData;
    I2cData.bSendLen = 2;

    // if (I2cWrite()) printf("CCS811Init I2C WRITE Sucessful!\n");
    // else printf("CCS811Init I2C WRITE Failed!\n");
    // end of APP_START

    // CCS811RegWrite(MEAS_MODE_REG, 0b00100000);
}
