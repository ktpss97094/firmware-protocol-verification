cmake_minimum_required(VERSION 3.15)
project(firmware C ASM)

set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")

set(MCU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
set(CMAKE_C_FLAGS "${OPT_FLAGS} ${MCU_FLAGS} -Wall -g -DSTM32F429xx -DUSE_HAL_DRIVER")
set(CMAKE_ASM_FLAGS "${MCU_FLAGS}")

function(add_firmware TARGET_NAME)
    file(GLOB HAL_SOURCES "${LIB_DIR}/stm32f4xx-hal-driver/Src/*.c")
    list(FILTER HAL_SOURCES EXCLUDE REGEX ".*template\\.c$")
    set(STARTUP_SOURCE "${LIB_DIR}/cmsis-device-f4/Source/Templates/gcc/startup_stm32f429xx.s")
    file(GLOB CORE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/Core/Src/*.c")
    list(FILTER CORE_SOURCES EXCLUDE REGEX "contract.*\\.c$")

    add_executable(${TARGET_NAME}
        ${HAL_SOURCES}
        ${STARTUP_SOURCE}
        ${CORE_SOURCES}
    )

    set_target_properties(${TARGET_NAME} PROPERTIES 
        OUTPUT_NAME ${CMAKE_PROJECT_NAME}
        SUFFIX ".elf"
    )

    target_include_directories(${TARGET_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/Core/Inc"
        "${LIB_DIR}/stm32f4xx-hal-driver/Inc"
        "${LIB_DIR}/cmsis-device-f4/Include"
        "${LIB_DIR}/CMSIS_5/CMSIS/Core/Include"
    )

    target_link_libraries(${TARGET_NAME}
        "-T${CMAKE_CURRENT_SOURCE_DIR}/STM32F429XX_FLASH.ld"
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
add_subdirectory(protocols/I2C/master/Blocking_Mode/Software/stm32_bitbang_i2c)
add_subdirectory(protocols/I2C/master/Interrupt_Mode/stm32f4xx-hal-driver)
add_subdirectory(protocols/I2C/master/DMA_Mode/stm32f4xx-hal-driver)