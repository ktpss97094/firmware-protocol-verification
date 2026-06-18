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
3. Install [Renode](https://github.com/renode/renode)

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
    and [verify](#verify) using `--debug` parameter.

### angr-management

可協助找 loop entry block address
1. 可視覺化顯示 control-flow graph
2. 按 Tab 可切換 assembly 與 disassembly 對照