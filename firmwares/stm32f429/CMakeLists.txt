cmake_minimum_required(VERSION 3.15)
project(firmware)

include(ExternalProject)

set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(MCU_FLAGS -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 --specs=nosys.specs)

add_library(cortex_m4_flags INTERFACE)
target_compile_options(cortex_m4_flags INTERFACE ${MCU_FLAGS} -Wall -g)
target_link_options(cortex_m4_flags INTERFACE ${MCU_FLAGS})

add_library(cmsis INTERFACE)
target_include_directories(cmsis INTERFACE
    "${LIB_DIR}/CMSIS_5/CMSIS/Core/Include"
    "${LIB_DIR}/cmsis-device-f4/Include"
)
target_sources(cmsis INTERFACE
    "${LIB_DIR}/cmsis-device-f4/Source/Templates/gcc/startup_stm32f429xx.s"
)
target_compile_definitions(cmsis INTERFACE STM32F429xx)

add_library(stm32f4xx_hal INTERFACE)
file(GLOB STM32F4XX_HAL_SOURCES "${LIB_DIR}/stm32f4xx-hal-driver/Src/*.c")
list(FILTER STM32F4XX_HAL_SOURCES EXCLUDE REGEX ".*template\\.c$")
target_sources(stm32f4xx_hal INTERFACE ${STM32F4XX_HAL_SOURCES})
target_include_directories(stm32f4xx_hal INTERFACE
    "${LIB_DIR}/stm32f4xx-hal-driver/Inc"
)
target_compile_definitions(stm32f4xx_hal INTERFACE USE_HAL_DRIVER)
target_link_libraries(stm32f4xx_hal INTERFACE cortex_m4_flags cmsis)

add_library(stm32_bitbang_i2c INTERFACE)
target_include_directories(stm32_bitbang_i2c INTERFACE "${LIB_DIR}/stm32_bitbang_i2c")
file(GLOB STM32_BITBANG_I2C_SOURCES CONFIGURE_DEPENDS "${LIB_DIR}/stm32_bitbang_i2c/*.c")
target_sources(stm32_bitbang_i2c INTERFACE ${STM32_BITBANG_I2C_SOURCES})
target_compile_definitions(stm32_bitbang_i2c INTERFACE STM32F4)
target_link_libraries(stm32_bitbang_i2c INTERFACE stm32f4xx_hal)

ExternalProject_Add(
    libopencm3_build
    PREFIX "${CMAKE_BINARY_DIR}/libopencm3"
    SOURCE_DIR "${LIB_DIR}/libopencm3"
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make TARGETS=stm32/f4
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS "${LIB_DIR}/libopencm3/lib/libopencm3_stm32f4.a"
    BUILD_ALWAYS 1
)
add_library(libopencm3 STATIC IMPORTED GLOBAL)
add_dependencies(libopencm3 libopencm3_build)
set_target_properties(libopencm3 PROPERTIES
    IMPORTED_LOCATION "${LIB_DIR}/libopencm3/lib/libopencm3_stm32f4.a"
    INTERFACE_INCLUDE_DIRECTORIES "${LIB_DIR}/libopencm3/include"
    INTERFACE_LINK_OPTIONS "-L${LIB_DIR}/libopencm3/lib"
    INTERFACE_COMPILE_DEFINITIONS "STM32F4"
)
target_link_libraries(libopencm3 INTERFACE cortex_m4_flags)

function(add_firmware TARGET_NAME)
    set_target_properties(${TARGET_NAME} PROPERTIES 
        OUTPUT_NAME ${CMAKE_PROJECT_NAME}
        SUFFIX ".elf"
    )
    
    add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:${TARGET_NAME}> $<TARGET_FILE_DIR:${TARGET_NAME}>/${CMAKE_PROJECT_NAME}.bin
        COMMENT "Generating ${CMAKE_PROJECT_NAME}.bin"
    )

    if(FLASH_TOOL)
        add_custom_target(${TARGET_NAME}-flash
            DEPENDS ${TARGET_NAME}
            COMMAND ${FLASH_TOOL} write $<TARGET_FILE_DIR:${TARGET_NAME}>/${CMAKE_PROJECT_NAME}.bin 0x8000000
            COMMENT "Flashing ${CMAKE_PROJECT_NAME}.bin for target ${TARGET_NAME}"
        )
    endif()

endfunction()

add_subdirectory(protocols/I2C/master/Blocking_Mode/Hardware/stm32f4xx-hal-driver)
add_subdirectory(protocols/I2C/master/Blocking_Mode/Hardware/libopencm3)
add_subdirectory(protocols/I2C/master/Blocking_Mode/Software/stm32_bitbang_i2c)
add_subdirectory(protocols/I2C/master/Interrupt_Mode/stm32f4xx-hal-driver)
add_subdirectory(protocols/I2C/master/DMA_Mode/stm32f4xx-hal-driver)