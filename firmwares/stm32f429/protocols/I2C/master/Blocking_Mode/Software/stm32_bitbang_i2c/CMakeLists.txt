project(i2c_master_blocking_sw_bitbang C)

add_firmware(${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PRIVATE 
    "${LIB_DIR}/stm32_bitbang_i2c"
)

target_compile_definitions(${PROJECT_NAME} PRIVATE 
    STM32F4
)

file(GLOB BITBANG_SOURCES 
    CONFIGURE_DEPENDS 
    "${LIB_DIR}/stm32_bitbang_i2c/*.c"
)
target_sources(${PROJECT_NAME} PRIVATE 
    ${BITBANG_SOURCES}
)