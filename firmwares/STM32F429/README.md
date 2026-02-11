# Build

```sh
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-none-eabi-toolchain.cmake -B build
```

# Compile

```sh
cd build
make
```

# Flash

```sh
make <cmake project name>-flash
```