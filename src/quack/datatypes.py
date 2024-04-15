import ida_typeinf
from dataclasses import dataclass, field
from typing import List, Any, Callable, Dict

@dataclass
class Function:
    param_count: int
    calling_convention: int
    start_address: int
    memory_mappings: Dict[int, bytes] = field(default_factory=dict)

class Pointer:
    def __init__(self, address: int, emulator) -> None:
        self.address = address
        self.__emulator = emulator
    
    # TODO enable reading of compound types
    def get_pointed(self, size: int) -> bytearray:
        return self.__emulator.read_mem(self.address, size)

@dataclass
class Test:
    params: List[Any]
    condition: Callable
    
@dataclass
class Tests:
    prototype: ida_typeinf.func_type_data_t
    tests: List[Test] = field(default_factory=list)
