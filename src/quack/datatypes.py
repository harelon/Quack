from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Any, Callable, Dict

@dataclass
class Function:
    param_count: int
    calling_convention: int
    start_address: int
    memory_mappings: Dict[int, bytes] = field(default_factory=dict)

class ParamType(Enum):
    VOID = auto()
#   VARIADIC = auto()
    INT8 = auto()
    UINT8 = auto()
    INT16 = auto()
    UINT16 = auto()
    INT32 = auto()
    UINT32 = auto()
    INT64 = auto()
    UINT64 = auto()
    INT = auto()
    UINT = auto()
    BYTES = auto()
    COMPOUND = auto()
    
    @property
    def is_signed(self) -> bool:
        return self in frozenset((ParamType.INT8, ParamType.INT16, ParamType.INT32, ParamType.INT64, ParamType.INT))
    
    @property
    def size(self) -> int:
        if self in frozenset((ParamType.INT, ParamType.UINT)):
            return -1
        elif self == ParamType.VOID:
            return 0
        elif self in frozenset((ParamType.INT8, ParamType.UINT8)):
            return 1
        elif self in frozenset((ParamType.INT16, ParamType.UINT16)):
            return 2
        elif self in frozenset((ParamType.INT32, ParamType.UINT32)):
            return 4
        elif self in frozenset((ParamType.INT64, ParamType.UINT64)):
            return 8
        else:
            raise ValueError("Shouldn't pass int as a bytes param")

# class ParamTypeSigness(Enum):
#     UNSIGNED = {ParamType.UINT8, ParamType.UINT16, ParamType.UINT32, ParamType.UINT64}
#     SIGNED = {ParamType.INT8, ParamType.INT16, ParamType.INT32, ParamType.INT64}


@dataclass
class FunctionPrototype:
    return_type: ParamType
    types_array: List[ParamType] = field(default_factory=list)

    def __getitem__(self, index):
        return self.types_array[index]

    def __len__(self):
        return len(self.types_array)

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
    prototype: FunctionPrototype
    tests: List[Test] = field(default_factory=list)
