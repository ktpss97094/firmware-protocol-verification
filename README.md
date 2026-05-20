## Prerequisite

1. Install [uv](https://github.com/astral-sh/uv)
2. Install [avatar2](https://github.com/avatartwo/avatar2) dependencies
    ```sh
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-setuptools python3-dev cmake build-essential gdb-multiarch
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

## angr-management

可協助找 loop entry block address
1. 可視覺化顯示 control-flow graph
2. 按 Tab 可切換 assembly 與 disassembly 對照