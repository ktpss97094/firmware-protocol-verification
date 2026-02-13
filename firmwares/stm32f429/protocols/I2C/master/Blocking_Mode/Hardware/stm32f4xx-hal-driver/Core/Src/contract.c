#include "stm32f4xx_hal.h"
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#define MAX_MODEL_CHECK_RETRIES 10
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
typedef struct {
    bool flag_set;      // 是否曾經偵測到 Flag 被 Set
    int check_counter;  // 檢查 Flag 的次數
    int max_check_counter;
} VerificationState;

extern bool nondet_bool(void);
extern unsigned int nondet_uint(void);

VerificationState ADDR_vs, TxE_vs, BTF_vs;

FlagStatus Stub_I2C_Get_Flag(I2C_HandleTypeDef *hi2c, uint32_t Flag) {
    uwTick++;  // ARM SysTick，由於 FUV 內所有等待行為都一定會呼叫這個函式，所以可以這樣抽象化
    
    switch (Flag) {
        case I2C_FLAG_ADDR:
            ADDR_vs.check_counter++;

            if (ADDR_vs.check_counter > MAX_MODEL_CHECK_RETRIES) {
                uwTick += 10000;  // 強制 timeout
                return RESET;
            }

            if (nondet_bool()) {
                ADDR_vs.flag_set = true;
                return SET;
            }
            return RESET;

        case I2C_FLAG_TXE:
            TxE_vs.check_counter++;
            TxE_vs.max_check_counter = MAX(TxE_vs.check_counter, TxE_vs.max_check_counter);

            if (TxE_vs.check_counter > MAX_MODEL_CHECK_RETRIES) {
                uwTick += 10000;  // 強制 timeout
                return RESET;
            }

            if (nondet_bool()) {
                TxE_vs.flag_set = true;
                TxE_vs.check_counter = 0;
                return SET;
            }
            return RESET;

        case I2C_FLAG_BTF:
            BTF_vs.check_counter++;
            BTF_vs.max_check_counter = MAX(BTF_vs.check_counter, BTF_vs.max_check_counter);

            if (BTF_vs.check_counter > MAX_MODEL_CHECK_RETRIES) {
                uwTick += 10000;  // 強制 timeout
                return RESET;
            }

            if (nondet_bool()) {
                BTF_vs.flag_set = true;
                TxE_vs.check_counter = 0;
                return SET;
            }
            return RESET;

        case I2C_FLAG_SB:
        case I2C_FLAG_ADD10:
            return SET;
        
        case I2C_FLAG_BUSY:
        case I2C_FLAG_AF:
            return RESET;

        default:  // 沒有用到的 flag
            return nondet_bool() ? SET : RESET;
    }
}

#ifdef __HAL_I2C_GET_FLAG
#undef __HAL_I2C_GET_FLAG
#define __HAL_I2C_GET_FLAG(__HANDLE__, __FLAG__) Stub_I2C_Get_Flag(__HANDLE__, __FLAG__)
#endif

#include "../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_i2c.c"
#include "main.c"

void contract_requirement_1() {
    /* Initial values */
    memset(&ADDR_vs, 0, sizeof(VerificationState));
    memset(&TxE_vs, 0, sizeof(VerificationState));
    memset(&BTF_vs, 0, sizeof(VerificationState));
    
    /* Preconditions */
    // HAL_I2C_Master_Transmit() **必要** 的 Precondition
    hi2c1.State = HAL_I2C_STATE_READY;
    hi2c1.Lock = HAL_UNLOCKED;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;

    /* FUV */
    // uint8_t data[3] = {0x75, 0x76, 0x24};
    // HAL_StatusTypeDef result = HAL_I2C_Master_Transmit(&hi2c1, 0x42 << 1, data, 3, 300);
    uint8_t data[1] = {0x75};
    HAL_StatusTypeDef result = HAL_I2C_Master_Transmit(&hi2c1, 0x42 << 1, data, 1, 300);

    /* Postconditions */
    /* 代表 I2C 通訊順利完成 */
    if (result == HAL_OK) {
        /* 
         * assertion success: 
         * 有等到直到 ADDR flag set，表示有處理 clock stretching
         * 
         * assertion failure: 
         * 沒有等待直到 ADDR flag set 就直接下一步。
         * 即使結果是 HAL_OK 的，還是表示沒有處理 clock stretching
         */
        assert(ADDR_vs.flag_set);

        assert(TxE_vs.flag_set);

        assert(BTF_vs.flag_set);
    } else if (result == HAL_TIMEOUT || result == HAL_ERROR) {
        if (!ADDR_vs.flag_set) {
            /*
             * assertion success:
             * 表示有確實多次檢查 ADDR flag，但其皆為 RESET，
             * 表示可能是真正的 timeout，還是會處理 clock stretching
             * 
             * assertion failure:
             * 沒有多次檢查 ADDR flag (或甚至不檢查)，就直接下一步，
             * 表示沒有處理 clock stretching
             */
            assert(ADDR_vs.check_counter > MAX_MODEL_CHECK_RETRIES);
        } else if (!TxE_vs.flag_set) {
            assert(TxE_vs.max_check_counter > MAX_MODEL_CHECK_RETRIES);
        } else if (!BTF_vs.flag_set) {
            assert(BTF_vs.max_check_counter > MAX_MODEL_CHECK_RETRIES);
        }
    }
}
