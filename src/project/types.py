class MemoryRegion:
    def __init__(
        self,
        start: int,
        size: int,
        map_addr: int | None = None,
        name: str = "",
    ):
        self.start = start
        self.size = size
        self.map_addr = map_addr if map_addr is not None else start
        self.name = name

    def in_region_read(self, state):
        try:
            addr = state.solver.eval(state.inspect.mem_read_address)
            return self.start <= addr < self.start + self.size
        except Exception:
            return False

    def in_region_write(self, state):
        try:
            addr = state.solver.eval(state.inspect.mem_write_address)
            return self.start <= addr < self.start + self.size
        except Exception:
            return False


class MMIOMemoryRegion(MemoryRegion):
    pass


class VariableMemoryRegion(MemoryRegion):
    pass
