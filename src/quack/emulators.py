import unicorn

import ida_idp
import ida_idaapi
import ida_typeinf

from enum import Enum, auto
from typing import List, Dict, Tuple, Any
from contextlib import contextmanager
from dataclasses import dataclass

from quack.datatypes import Function, ParamType, FunctionPrototype, Pointer

def round_offset_to_page(address: int, up: bool=True) -> int:
    return 4096 * (round(address//4096) + (1 if up else 0))

def mask_value(value: int, size: int) -> int:
    return value & ((1 << size * 8) - 1)

@dataclass
class MapRange:
    start: int
    end: int

def get_wanted_pages(data: Dict[int, bytes]) -> List[MapRange]:
    page_mapping_list: List[MapRange] = []
    for address, content in data.items():
        min_mapping = round_offset_to_page(address, False)
        max_mapping = round_offset_to_page(address + len(content), True)
        is_contained = False
        for item in page_mapping_list:
            # range is contained entirely
            if item.start <= min_mapping and max_mapping <= item.end:
                is_contained = True

            # we expand the min_mapping
            if min_mapping <= item.start <= max_mapping:
                is_contained = True
                item.start = min_mapping
            
            # we expand the max_mapping
            if min_mapping <= item.end <= max_mapping:
                is_contained = True
                item.end = max_mapping
            
            # if they are right next to each other
            if min_mapping == item.end:
                is_contained = True
                item.end = max_mapping
            
            if max_mapping == item.start:
                is_contained = True
                item.start = min_mapping
                max_mapping = item.end

        if not is_contained:
            page_mapping_list.append(MapRange(min_mapping, max_mapping))

    return page_mapping_list

class LocationType(Enum):
    arg = auto()
    result = auto()
    
class Emulator:
    def __init__(self) -> None:
        inf_struct = ida_idaapi.get_inf_structure()
        self.bitness = 64 if inf_struct.is_64bit() else (32 if inf_struct.is_32bit() else 16)
        self.arch = ida_idp.ph_get_id()
        unicorn_arch, mode, self.stack_register, self.pointer_size = arch_info[self.arch][self.bitness]
        self.endianess = inf_struct.is_be()
        self.endianess_string = "big" if self.endianess else "little"
        # TODO init global offset table for mips
        self.mu: unicorn.Uc = unicorn.Uc(unicorn_arch, mode | (unicorn.UC_MODE_BIG_ENDIAN if self.endianess else unicorn.UC_MODE_LITTLE_ENDIAN))
        self.param_address = 0x1000_0000
        self.stack_address = 0x2000_0000
        self.mapped_vars: List[int, int] = []
        self.mu.mem_map(self.stack_address, 4096 * 10)
        self.stack_address = self.stack_address + 4096 * 5
    
    @contextmanager
    def init_function(self, function: Function) -> None:
        memory_mappings: List[Tuple(int, int)] = []
        try:
            self.param_counter = 0
            self.function = function
            mappings = get_wanted_pages(function.memory_mappings)
            # print([hex(map.start) + " " + hex(map.end) for map in  mappings])
            # print({hex(key): len(value) for key, value in function.memory_mappings.items()})
            for map in mappings:
                size = map.end - map.start
                memory_mappings.append((map.start, size))
                self.mu.mem_map(map.start, size)
            for address, content in function.memory_mappings.items():
                self.mu.mem_write(address, content)
            yield
        finally:
            for mapped_memory in memory_mappings:
                self.mu.mem_unmap(*mapped_memory)
            memory_mappings.clear()
    
    def __resolve_param(self, param: ParamType, content: Any):
        if param in frozenset((ParamType.INT, ParamType.UINT)):
            return self.pointer_size, mask_value(content, self.pointer_size)
        elif param == ParamType.VOID:
            return 0, None
        elif param in frozenset((ParamType.INT8, ParamType.UINT8)):
            return 1, mask_value(content, 1)
        elif param in frozenset((ParamType.INT16, ParamType.UINT16)):
            return 2, mask_value(content, 2)
        elif param in frozenset((ParamType.INT32, ParamType.UINT32)):
            return 4, mask_value(content, 4)
        elif param in frozenset((ParamType.INT64, ParamType.UINT64)):
            return 8, mask_value(content, 8)
        elif param == ParamType.BYTES:
            return len(content), content.encode("ascii") + b"\0" if type(content) == str else content
        
    def __init_param(self, index: int, param_type: ParamType, content: Any) -> None:
        args = self.calling_convention[self.function.calling_convention][LocationType.arg]
        param_size, param_content = self.__resolve_param(param_type, content)
        if index >= len(args):
            size = param_size
            value = param_content
            if param_type == ParamType.BYTES:
                param_size = round_offset_to_page(param_size)
                self.mu.mem_map(self.param_address, param_size)
                self.mapped_vars.append((self.param_address, param_size))
                self.out_params.append(Pointer(self.param_address, self))
                self.mu.mem_write(self.param_address, param_content)
                value = self.param_address
                self.param_address += param_size
                size = self.pointer_size
            else:
                self.out_params.append(content)
            self.mu.mem_write(self.stack_address, value.to_bytes(size, self.endianess_string))
            self.stack_address += self.pointer_size
        else:
            current_param_reg: int = args[index]
            if param_type == ParamType.BYTES:
                param_size = round_offset_to_page(param_size)
                self.mu.mem_map(self.param_address, param_size)
                self.mapped_vars.append((self.param_address, param_size))
                self.out_params.append(Pointer(self.param_address, self))
                self.mu.mem_write(self.param_address, param_content)
                self.mu.reg_write(current_param_reg, self.param_address)
                self.param_address += param_size
            else:
                self.out_params.append(None)
                self.mu.reg_write(current_param_reg, param_content)

    @contextmanager
    def run(self, prototype: FunctionPrototype, params: List[Any]) -> None:
        try:
            self.calling_convention: Dict[int, Dict[LocationType, List[int]]] = calling_conventions[self.arch][self.bitness][ida_typeinf.default_compiler()]
        except KeyError:
            print("The current compiler has no suitable calling convention for the current architecture")
        try:
            self.result = 0
            self.out_params: List[Any] = []
            self.params = params
            original_stack_address = self.stack_address
            for i, param in enumerate(params):
                self.__init_param(i, prototype[i], param)
            stack_size = self.stack_address - original_stack_address
            try:
                # print(hex(self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RDI)))
                # print(hex(self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSI)))
                # print(hex(self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RDX)))
                # rsi_reg = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSI)
                # print(hex(rsi_reg))
                # print(self.mu.mem_read(rsi_reg, 3))
                # print("starting emulator")
                self.mu.reg_write(self.stack_register, original_stack_address - self.pointer_size)
                # print(hex(self.function.start_address))
                # print(self.mu.mem_read(self.function.start_address, 0x40))
                self.mu.emu_start(self.function.start_address, -1)
            except unicorn.UcError as e:
                # print(e)
                # print(hex(self.function.address))
                # 0xa8eb0
                # rsi_reg = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RSI)
                # print(hex(rsi_reg))
                # print(self.mu.mem_read(rsi_reg, 3))
                #rip_reg = self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RIP)
                # rip_reg = self.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
                # print(hex(rip_reg))
                # reg_result = self.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_V0)
                # print(hex(reg_result))
                #print(self.mu.mem_read(rip_reg, 3))
                # print(hex(self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RCX)))
                #print(hex(self.mu.reg_read(unicorn.x86_const.UC_X86_REG_RAX)))
                pass
            reg = self.calling_convention[self.function.calling_convention][LocationType.result][0]
            self.result = self.mu.reg_read(reg)
            if prototype.return_type.is_signed:
                size, value = self.__resolve_param(prototype.return_type, self.result)
                self.result = value | (-(value & 0x80 << (8 * (size - 1))))
            yield
        finally:
            self.result = 0
            self.out_params: List[Any] = []
            self.params = None
            for mapped_var in self.mapped_vars:
                self.mu.mem_unmap(*mapped_var)
            self.mapped_vars.clear()
            self.mu.mem_write(original_stack_address, b"\x00" * stack_size)
            self.stack_address = original_stack_address
            self.param_address = 0x1000_0000
    
    def read_mem(self, offset: int, size: int) -> bytearray:
        return self.mu.mem_read(offset, size)

    def get_result(self, size) -> int:
        if size == -1:
            size = self.pointer_size
        reg = self.calling_convention[self.function.calling_convention][LocationType.result][0]
        result = self.mu.reg_read(reg)
        return mask_value(result, size)

arch_info = {
    ida_idp.PLFM_386 :{
        32:  (unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, unicorn.x86_const.UC_X86_REG_ESP, 4),
        64: (unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, unicorn.x86_const.UC_X86_REG_RSP, 8)
    },
    ida_idp.PLFM_ARM :{
        32: (unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM, unicorn.arm_const.UC_ARM_REG_SP, 4),
        64: (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, unicorn.arm64_const.UC_ARM64_REG_SP, 8)
    },
    ida_idp.PLFM_MIPS :{
        32: (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS32, unicorn.mips_const.UC_MIPS_REG_SP, 4),
        64: (unicorn.UC_ARCH_MIPS, unicorn.UC_MODE_MIPS64, unicorn.mips_const.UC_MIPS_REG_SP, 8)
    }
}

calling_conventions = {
    ida_idp.PLFM_386: {
        32: {
            ida_typeinf.COMP_MS: {
                ida_typeinf.CM_CC_CDECL : {
                    LocationType.arg :[
                    ],
                    LocationType.result :[
                        unicorn.x86_const.UC_X86_REG_EAX
                    ]
                },
            }
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg : [
                        unicorn.x86_const.UC_X86_REG_RDI,
                        unicorn.x86_const.UC_X86_REG_RSI,
                        unicorn.x86_const.UC_X86_REG_RDX,
                        unicorn.x86_const.UC_X86_REG_RCX,
                        unicorn.x86_const.UC_X86_REG_R8,
                        unicorn.x86_const.UC_X86_REG_R9
                    ],
                    LocationType.result :[
                        unicorn.x86_const.UC_X86_REG_RAX
                    ]
                }
            },
            ida_typeinf.COMP_MS: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg :[
                        unicorn.x86_const.UC_X86_REG_RCX,
                        unicorn.x86_const.UC_X86_REG_RDX,
                        unicorn.x86_const.UC_X86_REG_R8,
                        unicorn.x86_const.UC_X86_REG_R9
                    ],
                    LocationType.result :[
                        unicorn.x86_const.UC_X86_REG_RAX
                    ]
                },
                ida_typeinf.CM_CC_CDECL : {
                    LocationType.arg :[
                        unicorn.x86_const.UC_X86_REG_RCX,
                        unicorn.x86_const.UC_X86_REG_RDX,
                        unicorn.x86_const.UC_X86_REG_R8,
                        unicorn.x86_const.UC_X86_REG_R9
                    ],
                    LocationType.result :[
                        unicorn.x86_const.UC_X86_REG_RAX
                    ]
                },
            }
        }
    },
    ida_idp.PLFM_ARM: {
        32: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg : [
                        unicorn.arm_const.UC_ARM_REG_R0,
                        unicorn.arm_const.UC_ARM_REG_R1,
                        unicorn.arm_const.UC_ARM_REG_R2,
                        unicorn.arm_const.UC_ARM_REG_R3,
                    ],
                    LocationType.result :[
                        unicorn.arm_const.UC_ARM_REG_R0,
                    ]
                }
            },
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg : [
                        unicorn.arm64_const.UC_ARM64_REG_X0,
                        unicorn.arm64_const.UC_ARM64_REG_X1,
                        unicorn.arm64_const.UC_ARM64_REG_X2,
                        unicorn.arm64_const.UC_ARM64_REG_X3,
                    ],
                    LocationType.result :[
                        unicorn.arm64_const.UC_ARM64_REG_X0,
                    ]
                }
            },
        }
    },
    ida_idp.PLFM_MIPS: {
        32: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg : [
                        unicorn.mips_const.UC_MIPS_REG_A0,
                        unicorn.mips_const.UC_MIPS_REG_A1,
                        unicorn.mips_const.UC_MIPS_REG_A2,
                        unicorn.mips_const.UC_MIPS_REG_A3
                        
                    ],
                    LocationType.result :[
                        unicorn.mips_const.UC_MIPS_REG_V0
                    ]
                },
                ida_typeinf.CM_CC_UNKNOWN : {
                    LocationType.arg : [
                        unicorn.mips_const.UC_MIPS_REG_A0,
                        unicorn.mips_const.UC_MIPS_REG_A1,
                        unicorn.mips_const.UC_MIPS_REG_A2,
                        unicorn.mips_const.UC_MIPS_REG_A3
                        
                    ],
                    LocationType.result :[
                        unicorn.mips_const.UC_MIPS_REG_V0
                    ]
                },
                ida_typeinf.CM_CC_CDECL : {
                    LocationType.arg : [
                        unicorn.mips_const.UC_MIPS_REG_A0,
                        unicorn.mips_const.UC_MIPS_REG_A1,
                        unicorn.mips_const.UC_MIPS_REG_A2,
                        unicorn.mips_const.UC_MIPS_REG_A3
                        
                    ],
                    LocationType.result :[
                        unicorn.mips_const.UC_MIPS_REG_V0
                    ]
                }
            },
        },
        64: {
            ida_typeinf.COMP_GNU: {
                ida_typeinf.CM_CC_FASTCALL : {
                    LocationType.arg : [
                        unicorn.mips_const.UC_MIPS_REG_A0,
                        unicorn.mips_const.UC_MIPS_REG_A1,
                        unicorn.mips_const.UC_MIPS_REG_A2,
                        unicorn.mips_const.UC_MIPS_REG_A3
                        
                    ],
                    LocationType.result :[
                        unicorn.mips_const.UC_MIPS_REG_V0
                    ]
                }
            },
        }
    }
}

def get_emulator() -> Emulator:
    return Emulator()
    