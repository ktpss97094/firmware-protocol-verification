# STM32F429 Firmware

## Environment

* arm-none-eabi-gcc 13.2.1 20231009

## Prerequisite

1. Install CMake
    ```sh
    sudo apt update
    sudo apt install cmake
    ```
2. Install GNU Arm Embedded Toolchain
    ```sh
    sudo apt update
    sudo apt install gcc-arm-none-eabi
    ```
3. Install stlink
    ```sh
    sudo apt update
    sudo apt install stlink-tools
    ```

## Build

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/arm-none-eabi.cmake -B build
```

## Compile

```sh
cd build
make
```

## Program

```sh
make <cmake project name>-flash
```