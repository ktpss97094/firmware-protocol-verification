#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/i2c.h>
#include <stddef.h>

#define I2C_PORT      I2C1
#define SYMBOL_MARKER(name) __asm__ volatile (".global " #name "\n" #name ":")

static void clock_setup(void) {
    rcc_osc_on(RCC_HSI);
    rcc_wait_for_osc_ready(RCC_HSI);
    rcc_set_sysclk_source(RCC_CFGR_SW_HSI);
    rcc_set_hpre(RCC_CFGR_HPRE_DIV_NONE);
    rcc_set_ppre1(RCC_CFGR_PPRE_DIV_NONE);
    rcc_set_ppre2(RCC_CFGR_PPRE_DIV_NONE);
    
    rcc_periph_clock_enable(RCC_I2C1);
    rcc_periph_clock_enable(RCC_GPIOB);
}

static void i2c_setup(void) {
    gpio_set_af(GPIOB, GPIO_AF4, GPIO6 | GPIO7);
    gpio_set_output_options(GPIOB, GPIO_OTYPE_OD, GPIO_OSPEED_50MHZ, GPIO6 | GPIO7);
    gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO6 | GPIO7);

    i2c_peripheral_disable(I2C_PORT);

    i2c_set_speed(I2C_PORT, i2c_speed_fm_400k, 16); 

    i2c_peripheral_enable(I2C_PORT);
}

int main(void) {
    clock_setup();
    i2c_setup();

    uint8_t data[65536];
    i2c_transfer7(I2C_PORT, 0x68, data, 1, NULL, 0);

    while (1) {}

    return 0;
}