#include "stm32f4xx_hal.h"
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#define MAX_MODEL_CHECK_RETRIES 10

extern bool nondet_bool(void);

I2C_TypeDef Virtual_I2C1_BASE;
bool hardware_actually_became_set = 0;
int wait_counter = 0;

FlagStatus Stub_I2C_Get_Flag(I2C_HandleTypeDef *hi2c, uint32_t Flag) {
    uwTick++;  // ARM SysTick
    wait_counter++;

    if (wait_counter > MAX_MODEL_CHECK_RETRIES) {
        uwTick += 10000;

        return RESET;
    }
    
    if (Flag == I2C_FLAG_ADDR) {
        if (nondet_bool()) {
            hardware_actually_became_set = true;
            return SET;
        }
        return RESET;
    }

    if (Flag == I2C_FLAG_AF) {
        return RESET;
    }
    
    // 其他 flag
    return nondet_bool() ? SET : RESET;
}

#ifdef __HAL_I2C_GET_FLAG
#undef __HAL_I2C_GET_FLAG
#define __HAL_I2C_GET_FLAG(__HANDLE__, __FLAG__) Stub_I2C_Get_Flag(__HANDLE__, __FLAG__)
#endif

#include "../../Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal_i2c.c"
#include "main.c"

void contract_requirement_1() {
    /* Initial values */
    memset(&Virtual_I2C1_BASE, 0, sizeof(I2C_TypeDef));
    hi2c1.Instance = &Virtual_I2C1_BASE;  // 改成 CBMC 可以 access 的位址
    uwTick = 0;
    hardware_actually_became_set = 0;
    wait_counter = 0;
    
    /* Preconditions */
    // HAL_I2C_Master_Transmit() **必要** 的 Precondition
    hi2c1.State = HAL_I2C_STATE_READY;
    hi2c1.Lock = HAL_UNLOCKED;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;

    /* FUV */
    uint8_t data = 0x75;
    HAL_StatusTypeDef result = HAL_I2C_Master_Transmit(&hi2c1, 0x68 << 1, &data, 1, 100);

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
        assert(hardware_actually_became_set == 1);
    } else {
        if (hardware_actually_became_set == 0) {
            /*
             * assertion success:
             * 表示有確實多次檢查 ADDR flag，但其皆為 RESET，
             * 表示可能是真正的 timeout，還是會處理 clock stretching
             * 
             * assertion failure:
             * 沒有多次檢查 ADDR flag (或甚至不檢查)，就直接下一步，
             * 表示沒有處理 clock stretching
             */
            assert(wait_counter > 5);
        }
    }
}
