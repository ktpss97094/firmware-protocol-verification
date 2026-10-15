project(i2c_master_blocking_hw_opencm3 C)

add_executable(${PROJECT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")

target_link_libraries(${PROJECT_NAME} PRIVATE libopencm3)
target_link_options(${PROJECT_NAME} PRIVATE "-T${CMAKE_CURRENT_SOURCE_DIR}/stm32f429.ld" -nostartfiles)

add_firmware(${PROJECT_NAME})