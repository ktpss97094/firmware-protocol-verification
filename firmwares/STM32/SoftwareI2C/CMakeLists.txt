cmake_minimum_required(VERSION 3.13)
project(blink C ASM)

# 1. 目標系統與處理器
set(CMAKE_SYSTEM_NAME Generic)  # 因為是 bare-metal，設定 Generic 不會假設目標系統有任何標準的系統庫
set(CMAKE_SYSTEM_PROCESSOR cortex-m4)

# 2. 找出 cross-compiler 工具
find_program(ARM_GCC NAMES arm-none-eabi-gcc)
find_program(ARM_OBJCOPY NAMES arm-none-eabi-objcopy)
if(NOT ARM_GCC)
  message(FATAL_ERROR "arm-none-eabi-gcc not found")
endif()

# 3. 編譯器設定
set(CMAKE_C_COMPILER   ${ARM_GCC})
set(CMAKE_ASM_COMPILER ${ARM_GCC})
set(OPT_FLAGS "")
# set(OPT_FLAGS "-O2")
# (1) -mthumb: cortex-m4 不支援傳統 32 位元 ARM 指令集，故需使用 thumb-2 指令集
# (2) -mfpu=fpv4-sp-d16: 配備 cortex-m4 的 FPU 來執行浮點運算，使用 ARM 的 FPv4 浮點架構、single precision、16 個 double-word 浮點暫存器
# (3) -mfloat-abi=hard: 指定浮點應用程式二進位介面 (ABI) 為硬浮點 (hard float)，這意味著浮點運算會使用硬體 FPU，而不是軟體模擬。這樣可以提高浮點運算的效能
set(MCU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
set(CMAKE_C_FLAGS "${OPT_FLAGS} ${MCU_FLAGS} -Wall -g -DSTM32F429xx -DUSE_HAL_DRIVER")
set(CMAKE_ASM_FLAGS "${MCU_FLAGS}")

# 4. include 路徑
include_directories(
  Core/Inc
  Drivers/STM32F4xx_HAL_Driver/Inc
  Drivers/CMSIS/Device/ST/STM32F4xx/Include
  Drivers/CMSIS/Include
)

# 5. Source codes
file(GLOB HAL_SOURCES "Drivers/STM32F4xx_HAL_Driver/Src/*.c")
list(FILTER HAL_SOURCES EXCLUDE REGEX ".*template\\.c$")

file(GLOB CORE_SOURCES "Core/Src/*.c")

set(SOURCES
  ${CORE_SOURCES}
  startup_stm32f429xx.s
  ${HAL_SOURCES}
)

# 6. make 指令
add_executable(${PROJECT_NAME}.elf ${SOURCES})

# 7. 指定 linker
target_link_libraries(${PROJECT_NAME}.elf
  "-T${CMAKE_SOURCE_DIR}/STM32F429XX_FLASH.ld"
)

# 8. 將 elf 檔轉為 bin 檔 (使用 POST_BUILD 表示 elf 建構完成後立即執行此 command)
add_custom_command(TARGET ${PROJECT_NAME}.elf POST_BUILD
  COMMAND ${ARM_OBJCOPY} -O binary $<TARGET_FILE:${PROJECT_NAME}.elf> ${PROJECT_NAME}.bin
)

# 9. 找 st-flash 工具
find_program(FLASH_TOOL NAMES st-flash)
if(NOT FLASH_TOOL)
  message(FATAL_ERROR "st-flash not found")
endif()

# 10. make flash 指令
add_custom_target(flash
  DEPENDS ${PROJECT_NAME}.elf
  COMMAND ${FLASH_TOOL} --serial 066CFF363355373043053837 write ${CMAKE_BINARY_DIR}/${PROJECT_NAME}.bin 0x8000000  # MCU flash 起始位址為 0x8000000 (reference manual p75)
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  COMMENT "Flashing ${PROJECT_NAME}.bin to STM32 at 0x8000000"
)

# 11. 找 st-util 工具
find_program(GDB_SERVER_TOOL NAMES st-util)
if(NOT GDB_SERVER_TOOL)
  message(FATAL_ERROR "st-util not found")
endif()

# 12. make gdb-server 指令
add_custom_target(gdb-server
  COMMAND ${GDB_SERVER_TOOL}
  COMMENT "Starting GDB server"
)