#include "i2s.h"

/// Globally declared LDMA link descriptors
LDMA_Descriptor_t leftDesc;
LDMA_Descriptor_t rightDesc;

uint32_t leftBuffer[BUFFER_SIZE_I2S];
uint16_t leftBufferIndex = 0;
uint32_t rightBuffer[BUFFER_SIZE_I2S];
uint16_t rightBufferIndex = 0;

/// Single byte used to dispose of right microphone data
// uint8_t rightData;

/**************************************************************************/ /**
                                                                              * @brief Configure and
                                                                              *start stereo
                                                                              *microphone on USART3
                                                                              * @Note: we used
                                                                              *USART3 to avoid bus
                                                                              *or pin conflicts
                                                                              *****************************************************************************/
void MICMODE_InitMIC(uint32_t sampleFrequency) {

    CMU_ClockEnable(cmuClock_GPIO, true);

    // Enable clock for USART3
    CMU_ClockEnable(cmuClock_USART3, true);

    // Enable GPIO clock and I2S pins
    GPIO_PinModeSet(I2S_PORT, I2S_RX_PIN, gpioModeInputPullFilter, 0);
    GPIO_PinModeSet(I2S_PORT, I2S_TX_PIN, gpioModePushPull, 1);
    GPIO_PinModeSet(I2S_PORT, I2S_CLK_PIN, gpioModePushPull, 1);
    GPIO_PinModeSet(I2S_PORT, I2S_CS_PIN, gpioModePushPull, 1);

    // Initialize USART3 to receive data from microphones synchronously
    USART_InitI2s_TypeDef def = USART_INITI2S_DEFAULT;
    def.sync.databits = usartDatabits8;
    def.format = usartI2sFormatW32D32;
    def.sync.enable = usartDisable;
    def.sync.autoTx = true;
    def.justify = usartI2sJustifyLeft;
    def.delay = true;

    // Separate DMA requests for left and right channel data
    def.dmaSplit = true;

    // Set baud rate to achieve desired sample frequency
    def.sync.baudrate = sampleFrequency * 64;

    USART_InitI2s(USART3, &def);

    // Enable route to GPIO pins for I2S transfer on route #0
    USART3->ROUTEPEN =
        USART_ROUTEPEN_TXPEN | USART_ROUTEPEN_RXPEN | USART_ROUTEPEN_CSPEN | USART_ROUTEPEN_CLKPEN;

    USART3->ROUTELOC0 = USART_ROUTELOC0_TXLOC_LOC0 | USART_ROUTELOC0_RXLOC_LOC0 |
                        USART_ROUTELOC0_CSLOC_LOC0 | USART_ROUTELOC0_CLKLOC_LOC0;

    // Enable USART3
    USART_Enable(USART3, usartEnable);
}

/**************************************************************************/ /**
                                                                              * @brief Configure and
                                                                              *start DMA
                                                                              * @detail Starting DMA
                                                                              *transfers that
                                                                              *transfer the data
                                                                              *from the different
                                                                              * mic channels to
                                                                              *either buffers or
                                                                              *dummy variables. We
                                                                              *are only using the
                                                                              *left channel's data
                                                                              *to show what a buffer
                                                                              *of mic data looks
                                                                              *like so the DMA
                                                                              *transfer for the
                                                                              *right channel only
                                                                              *puts the right mic
                                                                              *data into a dummy
                                                                              *variable
                                                                              *****************************************************************************/
void MICMODE_InitLDMA(void) {
    // Default LDMA init
    LDMA_Init_t init = LDMA_INIT_DEFAULT;
    LDMA_Init(&init);

    // Configure LDMA for transfer from USART to memory (left channel)
    // LDMA will loop continuously
    LDMA_TransferCfg_t leftCfg = LDMA_TRANSFER_CFG_PERIPHERAL(ldmaPeripheralSignal_USART3_RXDATAV);

    // Globally store and configure link descriptors for left microphone transfer
    LDMA_Descriptor_t leftXfer = LDMA_DESCRIPTOR_LINKREL_P2M_BYTE(
        &USART3->RXDATA, (uint8_t *)leftBuffer, 4 * BUFFER_SIZE_I2S, 0);
    leftDesc = leftXfer;
    // trigger interrupt on left microphone transfer complete (buffer full)
    leftDesc.xfer.doneIfs = 1;
    leftDesc.xfer.ignoreSrec = 0;

    // Configure LDMA for transfer from USART to memory (right channel)
    // LDMA will loop continuously
    LDMA_TransferCfg_t rightCfg =
        LDMA_TRANSFER_CFG_PERIPHERAL(ldmaPeripheralSignal_USART3_RXDATAVRIGHT);

    // Set up right microphone descriptor
    LDMA_Descriptor_t rightXfer = LDMA_DESCRIPTOR_LINKREL_P2M_BYTE(
        &USART3->RXDATA, (uint8_t *)rightBuffer, 4 * BUFFER_SIZE_I2S, 0);
    rightDesc = rightXfer;
    // rightDesc.xfer.size = ldmaCtrlSizeByte;

    // Trigger interrupts on right microphone transfers
    rightDesc.xfer.doneIfs = 1; // 0= no trigger 1= trigger
    rightDesc.xfer.ignoreSrec = 0;

    // Start left and right transfers
    LDMA_StartTransfer(0, (void *)&leftCfg, (void *)&leftDesc);
    LDMA_StartTransfer(1, (void *)&rightCfg, (void *)&rightDesc);
}

void initCMU(void) {
    // Set HF clock to 72MHz
    CMU_HFRCOBandSet(cmuHFRCOFreq_72M0Hz);
    // CMU_AUXHFRCOBandSet(cmuHFRCOFreq_2M0Hz);
    // CMU_USHFRCOBandSet(cmuHFRCOFreq_2M0Hz);
}

void Return_Left_buffer(int16_t *Mic_Left_Buffer) {
    for (int i = 0; i < BUFFER_SIZE_I2S; i++) {
        uint32_t temp = Swap_Endian(leftBuffer[i]);
        Mic_Left_Buffer[i] = temp >> 16;
    }
}

void Return_Right_buffer(int16_t *Mic_Right_Buffer) {
    for (int i = 0; i < BUFFER_SIZE_I2S; i++) {
        uint32_t temp = Swap_Endian(rightBuffer[i]);
        Mic_Right_Buffer[i] = temp >> 16;
    }
}
uint32_t Swap_Endian(uint32_t num) {
    uint32_t swapped = ((num >> 24) & 0xff) |      // move byte 3 to byte 0
                       ((num << 8) & 0xff0000) |   // move byte 1 to byte 2
                       ((num >> 8) & 0xff00) |     // move byte 2 to byte 1
                       ((num << 24) & 0xff000000); // byte 0 to byte 3
    return swapped;
}
