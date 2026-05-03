class HWRegister:
    """Proxy for a single hardware register.
    - .addr gives the address (from the original dict)
    - .value reads/writes the register (triggers self.read32 / self.write32)
    - Direct assignment on the parent map also works for convenience
    """
    def __init__(self, read32, write32, addr, name, offset):
        self.addr = addr          # the address from regs
        self.offset = offset      # the register offset
        self.name = name          # optional, for debugging
        self._read32 = read32     # bound method or function
        self._write32 = write32

    def read(self):
        """Explicit read"""
        return self._read32(self.addr)

    def write(self, value):
        """Explicit write"""
        self._write32(self.addr, value)

    @property
    def value(self):
        """Read the register (used for val = regs.SSR_BASE.value)"""
        return self.read()

    @value.setter
    def value(self, val):
        """Write the register (used for regs.SSR_BASE.value = 12)"""
        self.write(val)

    def __repr__(self):
        return f"<HWRegister {self.name} @ 0x{self.addr:08x}>"

class RegisterMap:
    """Turns your regs dict into a dot-accessible register map.
    - regs.SSR_BASE = 12          → calls self.write32(addr, 12)
    - val = regs.SSR_BASE.value   → calls self.read32(addr)
    - addr = regs.SSR_BASE.addr   → returns the address (0x0000)
    - The original dict values (addresses) are still accessible via . _regs if needed
    """
    def __init__(self, regs:dict, read32_func, write32_func, base_addr:int=0):
        # Store the original dict so you can still retrieve raw addresses if you want
        self._regs = dict(regs)   # copy
        self._read32 = read32_func
        self._write32 = write32_func
        self._base_addr = base_addr

    def __getattr__(self, name):
        """Called when you do regs.SSR_BASE (or .addr, .value, .offset, etc.)"""
        if name in self._regs:
            addr = self._regs[name] + self._base_addr
            offset = self._regs[name]
            return HWRegister(self._read32, self._write32, addr, name, offset)
        raise AttributeError(f"Register '{name}' not found in regs")

    def __setattr__(self, name, value):
        """Intercept assignment regs.SSR_BASE = 12 → write to hardware"""
        if name.startswith('_') or name in ('_regs', '_read32', '_write32', '_baseaddr'):
            # Private attributes of the map itself – normal Python behaviour
            super().__setattr__(name, value)
            return

        if name in self._regs:
            # This is a register assignment → trigger write32
            proxy = self.__getattr__(name)   # get the HWRegister proxy
            proxy.write(value)
            return

        # Any other attribute you set on the map
        super().__setattr__(name, value)

    # Optional helper if you still want the raw address without creating a proxy
    def addr(self, name):
        """regs.addr('SSR_BASE') → returns the address directly"""
        if name in self._regs:
            return self._regs[name] + self._base_addr
        raise KeyError(name)

    def offset(self, name):
        """regs.offset('SSR_BASE') → returns the offset of the register"""
        if name in self._regs:
            return self._regs[name]
        raise KeyError(name)
