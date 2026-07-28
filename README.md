# Firmware Protocol Verification

## Environment

Ubuntu 24.04 LTS

## Prerequisite

1. Install [uv](https://github.com/astral-sh/uv)
2. Install [avatar2](https://github.com/avatartwo/avatar2) dependencies
    ```sh
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-setuptools python3-dev cmake build-essential gdb-multiarch
    ```
3. Install OpenOCD
    ```sh
    sudo apt update
    sudo apt install openocd
    ```
4. Install [Renode](https://github.com/renode/renode)

## Build

```sh
uv sync
```

## Verify

```sh
uv run verify <spec file>
```

## Utilities

### Renode

```sh
cd renode
renode <renode script>
```

### Remote OpenOCD

Open two terminals.

1. First terminal:
    ```sh
    openocd -f <interface script> -f <target script>
    ```
2. Second terminal:
    ```sh
    ssh -R 3333:localhost:3333 <user>@<IP>
    ```
    and [verify](#verify) using `--gdb` parameter.

### [angr-management](https://github.com/angr/angr-management)

Can help to find loop entry block addresses using a GUI.

```sh
uv run angr-management <firmware file>
```

> [!TIP]
> 1. Use the search bar to locate the position.
> 2. Use the tab key to switch between assembly and disassembly code.