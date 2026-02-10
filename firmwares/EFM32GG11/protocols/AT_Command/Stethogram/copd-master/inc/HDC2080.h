#include "i2c.h"

// Register Map

/* Common addresses definition for HDC2080 sensor. */
// By tinkeringtech
#define TEMP_LOW 0x00
#define TEMP_HIGH 0x01
#define HUMID_LOW 0x02
#define HUMID_HIGH 0x03
#define INTERRUPT_DRDY 0x04
#define TEMP_MAX 0x05
#define HUMID_MAX 0x06
#define INTERRUPT_CONFIG 0x07
#define TEMP_OFFSET_ADJUST 0x08
#define HUM_OFFSET_ADJUST 0x09
#define TEMP_THR_L 0x0A
#define TEMP_THR_H 0x0B
#define HUMID_THR_L 0x0C
#define HUMID_THR_H 0x0D
#define CONFIG 0x0E
#define MEASUREMENT_CONFIG 0x0F
#define MID_L 0xFC
#define MID_H 0xFD
#define DEVICE_ID_L 0xFE
#define DEVICE_ID_H 0xFF

// Seven-bit device address 1000000 for GND , address 1000001 for VDD
#define HDC2080_ADDRESS 0X80 // for Write

void HDC2080Init(void);
void ReadHumidityData(uint16_t *destination);
void ReadTemperatureData(uint16_t *destination);
bool HDC2080RegWrite(uint8_t reg, uint8_t bData);