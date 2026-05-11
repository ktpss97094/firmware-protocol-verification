> [!WARNING]
> If the firmware under verification is compiled with optimization enabled, it may cause symbol recognition failures and may lead to incorrect verification results.

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