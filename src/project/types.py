class MemoryRegion:
    def __init__(
        self,
        start: int,
        size: int,
        map_addr: int | None = None,
        name: str = "",
    ):
        super().__init__()

        self.start = start
        self.size = size
        self.map_addr = map_addr if map_addr is not None else start
        self.name = name
        self.symbolic_masks = {}

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

    def set_symbolic_mask(self, global_symbolic_mask):
        """
        只挑出屬於此 memory region 的 symbolic mask
        """

        for addr, mask in global_symbolic_mask.items():
            if self.start <= addr < (self.start + self.size):
                self.symbolic_masks[addr] = mask


class MMIOMemoryRegion(MemoryRegion):
    pass


class VariableMemoryRegion(MemoryRegion):
    pass


class BaseSpecs:
    def __init__(self, proj):
        super().__init__()

        self.proj = proj
        self.SYMBOLIC_MASKS = {}
        self.MEMORY_REGIONS = {}
        self.BEGIN_ADDR = None
        self.END_ADDRS = []

        self._define_specs()

        self._apply_symbolic_masks()

    def _define_specs(self):
        pass

    def _apply_symbolic_masks(self):
        for memory_region in self.MEMORY_REGIONS.values():
            memory_region.set_symbolic_mask(self.SYMBOLIC_MASKS)
