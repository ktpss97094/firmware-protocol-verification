/**
 * @filename I2C.c
 *
 * I2c control
 *
 * @author RyanYeh <RyanYeh710124@gmail.com>
 * @note
 * @modified by alexhsu on 2020/03/20
 */

#include "i2c.h"
#include "em_cmu.h"
#include "em_i2c.h"

#define I2C_TRANSFER_TIMEOUT 300000

I2cCtrlType I2cData;

/**
 * @brief I2CInit
 *
 * Initialize I2C
 *
 * @return NULL
 */
void init_I2C(void) {
    /*  For bluebox i2c1 Init
      /// clock
      CMU_ClockEnable(cmuClock_I2C1, true);
      CMU_ClockEnable(cmuClock_GPIO, true);

      /// [I2C1 I/O setup]
      GPIO_PinModeSet(I2C_SCL_PORT, I2C_SCL_PIN, gpioModeWiredAnd, 1);
      GPIO_PinModeSet(I2C_SDA_PORT, I2C_SDA_PIN, gpioModeWiredAnd, 1);

      /// Set up SCL
      I2C1->ROUTEPEN = I2C1->ROUTEPEN | I2C_ROUTEPEN_SCLPEN;
      I2C1->ROUTELOC0 = (I2C1->ROUTELOC0 & (~_I2C_ROUTELOC0_SCLLOC_MASK))
                    | (I2C_SCL_ROUTELOC<<_I2C_ROUTELOC0_SCLLOC_SHIFT);

      /// Set up SDA
      I2C1->ROUTEPEN = I2C1->ROUTEPEN | I2C_ROUTEPEN_SDAPEN;
      I2C1->ROUTELOC0 = (I2C1->ROUTELOC0 & (~_I2C_ROUTELOC0_SDALOC_MASK))
                    | I2C_SDA_ROUTELOC;

      I2C_Init_TypeDef init = I2C_INIT_DEFAULT;

      init.enable = 1;
      init.master = 1;
      init.freq = I2C_FREQ_FAST_MAX;
      init.clhr = i2cClockHLRStandard;
      I2C_Init(I2C1, &init);
     */

    /* For COPD i2c0 Init */
    /// clock
    CMU_ClockEnable(cmuClock_I2C0, true);
    CMU_ClockEnable(cmuClock_GPIO, true);

    /// [I2C0 I/O setup]
    GPIO_PinModeSet(I2C_SCL_PORT, I2C_SCL_PIN, gpioModeWiredAnd, 1);
    GPIO_PinModeSet(I2C_SDA_PORT, I2C_SDA_PIN, gpioModeWiredAnd, 1);

    /// Set up SCL
    I2C0->ROUTEPEN = I2C0->ROUTEPEN | I2C_ROUTEPEN_SCLPEN;
    I2C0->ROUTELOC0 = (I2C0->ROUTELOC0 & (~_I2C_ROUTELOC0_SCLLOC_MASK)) |
                      (I2C_SCL_ROUTELOC << _I2C_ROUTELOC0_SCLLOC_SHIFT);

    /// Set up SDA
    I2C0->ROUTEPEN = I2C0->ROUTEPEN | I2C_ROUTEPEN_SDAPEN;
    I2C0->ROUTELOC0 = (I2C0->ROUTELOC0 & (~_I2C_ROUTELOC0_SDALOC_MASK)) | I2C_SDA_ROUTELOC;

    I2C_Init_TypeDef init = I2C_INIT_DEFAULT;

    init.enable = 1;
    init.master = 1;
    init.freq = I2C_FREQ_FAST_MAX;
    init.clhr = i2cClockHLRStandard;
    I2C_Init(I2C0, &init);
    /* i2c0 Init end */
}

/*******************************************************************************
 * @brief
 *   Perform I2C transfer
 *
 * @details
 *   This driver only supports master mode, single bus-master. It does not
 *   return until the transfer is complete, polling for completion.
 *
 * @param[in] i2c
 *   Pointer to the peripheral port
 *
 * @param[in] seq
 *   Pointer to sequence structure defining the I2C transfer to take place. The
 *   referenced structure must exist until the transfer has fully completed.
 ******************************************************************************/
I2C_TransferReturn_TypeDef DrvI2C_Transfer(I2C_TypeDef *i2c, I2C_TransferSeq_TypeDef *seq) {
    I2C_TransferReturn_TypeDef ret;
    uint32_t timeout = I2C_TRANSFER_TIMEOUT;

    /// Do a polled transfer
    ret = I2C_TransferInit(i2c, seq);
    while (ret == i2cTransferInProgress && timeout--) {
        ret = I2C_Transfer(i2c);
    }
    return ret;
}

/**
 * @brief I2cWrite
 *
 * I2C write command
 *
 * @return send data count
 */
int I2cWrite() {
    I2C_TransferSeq_TypeDef seq;
    I2C_TransferReturn_TypeDef ret;

    seq.addr = I2cData.bAddr;
    seq.flags = I2C_FLAG_WRITE;

    /// Select command to issue
    seq.buf[0].data = (uint8_t *)I2cData.bSendBuf;
    seq.buf[0].len = I2cData.bSendLen;
    /// Select location/length of data to be read
    seq.buf[1].data = (uint8_t *)I2cData.bRecBuf;
    seq.buf[1].len = I2cData.bRecLen;

    ret = DrvI2C_Transfer(I2C0, &seq);

    if (ret != i2cTransferDone) {
        return ((int)FALSE);
    }
    return ((int)TRUE);
}

/**
 * @brief I2cRegRead
 *
 * I2C registry read command
 *
 * @return read data count
 */
int I2cRegRead() {
    I2C_TransferSeq_TypeDef seq;
    I2C_TransferReturn_TypeDef ret;

    seq.addr = I2cData.bAddr;
    seq.flags = I2C_FLAG_WRITE_READ;
    /// Select command to issue
    seq.buf[0].data = (uint8_t *)I2cData.bSendBuf;
    seq.buf[0].len = I2cData.bSendLen;
    /// Select location/length of data to be read
    seq.buf[1].data = (uint8_t *)I2cData.bRecBuf;
    seq.buf[1].len = I2cData.bRecLen;

    ret = DrvI2C_Transfer(I2C0, &seq);

    if (ret != i2cTransferDone) {
        return ((int)FALSE);
    }
    return ((int)I2cData.bRecLen);
}

/**
 * @brief I2cRead
 *
 * I2C Read command
 *
 * @return true/false
 */
int I2cRead() {
    I2C_TransferSeq_TypeDef seq;
    I2C_TransferReturn_TypeDef ret;

    seq.addr = I2cData.bAddr;
    seq.flags = I2C_FLAG_READ;

    /// Select location/length of data to be read
    seq.buf[0].data = (uint8_t *)I2cData.bRecBuf;
    seq.buf[0].len = I2cData.bRecLen;

    ret = DrvI2C_Transfer(I2C0, &seq);

    if (ret != i2cTransferDone) {
        return false;
    }
    return true;
}
