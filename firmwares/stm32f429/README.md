# STM32F429 Firmware

## Prerequisite

```sh
sudo apt update
sudo apt install cmake gcc-arm-none-eabi binutils-arm-none-eabi
```

## Build

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-none-eabi-toolchain.cmake -B build
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