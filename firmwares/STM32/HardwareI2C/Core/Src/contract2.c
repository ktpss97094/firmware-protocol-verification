#include <stdint.h>

// 定義硬體地址
#define I2C_SR1_ADDR 0x40005414
#define I2C_DR_ADDR  0x40005410
#define ADDR_FLAG_BIT (1 << 1)

extern unsigned int nondet_uint(void);

int __cprover_state_addr_polled = 0;

// 模擬硬體讀取行為
// CBMC 會自動將程式中所有對指標的 dereference 導向這裡 (如果該地址未被 malloc)
// 參考文件: modeling-mmio.md
uint32_t __CPROVER_mm_io_r(void *addr, unsigned size) {
    if ((unsigned long)addr == I2C_SR1_ADDR) {
        __CPROVER_assert(0, "DEBUG: __CPROVER_mm_io_r called!");
        // 模擬硬體行為：非確定性地回傳狀態 (可能是 0 也可能是 ADDR=1)
        uint32_t value = nondet_uint();
        
        // 關鍵邏輯：如果是軟體讀到了 ADDR 為 1，我們就標記狀態為「已確認」
        if (value & ADDR_FLAG_BIT) {
            __cprover_state_addr_polled = 1;
        } else {
            // 如果讀到 ADDR 為 0，表示還沒 Ready，狀態應重置或保持
            // (視具體硬體行為而定，通常讀到 0 代表還不能下一步)
            __cprover_state_addr_polled = 0; 
        }
        return value;
    }
    // 其他地址回傳非確定值
    return nondet_uint();
}

// 模擬硬體寫入行為
void __CPROVER_mm_io_w(void *addr, unsigned size, uint32_t value) {
    __CPROVER_assert(0, "DEBUG: __CPROVER_mm_io_w called!");
    if ((unsigned long)addr == I2C_DR_ADDR) {
        // 這裡就是您的「驗證標準」！
        // 當程式試圖寫入 DR (進行接下來的 transaction) 時，
        // 檢查之前是否已經讀到了 ADDR=1
        // __CPROVER_assert(__cprover_state_addr_polled == 1, 
        //                  "Violation: Hardware accessed before ADDR flag polling!");

        // 寫入後重置狀態 (視 I2C 規範而定)
        __cprover_state_addr_polled = 0;
    }
}

int main_spec(void) 
__CPROVER_ensures(__cprover_state_addr_polled == 1)
{
}