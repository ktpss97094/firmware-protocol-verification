#include "HDC2080.h"

void ReadHumidityData(uint16_t *destination) {
    HDC2080RegWrite(MEASUREMENT_CONFIG, 0x01);

    I2cData.bAddr = HDC2080_ADDRESS;
    I2cData.bSendBuf[0] = HUMID_LOW;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 2;
    I2cRegRead();

    destination[0] = ((int16_t)I2cData.bRecBuf[1] << 8 |
                      I2cData.bRecBuf[0]); // Turn the MSB and LSB into a signed 16-bit value
}

void ReadTemperatureData(uint16_t *destination) {
    HDC2080RegWrite(MEASUREMENT_CONFIG, 0x01);

    I2cData.bAddr = HDC2080_ADDRESS;
    I2cData.bSendBuf[0] = TEMP_LOW;
    I2cData.bSendLen = 1;
    I2cData.bRecLen = 2;
    I2cRegRead();

    destination[0] = ((int16_t)I2cData.bRecBuf[1] << 8 |
                      I2cData.bRecBuf[0]); // Turn the MSB and LSB into a signed 16-bit value
}

bool HDC2080RegWrite(uint8_t reg, uint8_t bData) {
    I2cData.bAddr = HDC2080_ADDRESS;
    I2cData.bSendBuf[0] = reg;
    I2cData.bSendBuf[1] = bData;
    I2cData.bSendLen = 2;

    if (I2cWrite() == FALSE) {
        return FALSE;
    }
    return TRUE;
}

void HDC2080Init(void) {
    HDC2080RegWrite(CONFIG, 0x00);
    HDC2080RegWrite(MEASUREMENT_CONFIG, 0x00);
}
