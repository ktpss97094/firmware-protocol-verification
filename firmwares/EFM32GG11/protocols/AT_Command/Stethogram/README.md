# Stethogram (COPD 2023)

* Thesis: https://hdl.handle.net/11296/25jnqe
* Document Portal: https://docs.epl.tw/portal-copd

## Environment

Ubuntu 24.04

## Prerequisite

* commander
    1. Install [commander](https://www.silabs.com/software-and-tools/simplicity-studio/simplicity-commander?tab=getting-started)
    2. Set udev rules
        ```sh
        # In commander-cli/
        sudo cp 99-jlink.rules /etc/udev/rules.d/
        sudo udevadm control --reload-rules
        sudo udevadm trigger
        ```

## Compile

```sh
cd copd-master/
make -f Makefile.COPD
```

## Program

```sh
make flash -f Makefile.COPD
```