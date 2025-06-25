import unicorn

import ida_pro
import ida_idp
import ida_idaapi
import ida_hexrays
import ida_typeinf

if ida_pro.IDA_SDK_VERSION < 850:
    pass
else:
    import ida_ida

from typing import List, Dict, Tuple, Any
from contextlib import contextmanager
from dataclasses import dataclass

from quack.unicorn_2_ida_consts import calling_conventions, x86_x64_reg_map, arch_info, LocationType
from quack.datatypes import Function, Pointer

def round_offset_to_page(address: int, up: bool=True) -> int:
    return 4096 * (round(address//4096) + (1 if up else 0))

def mask_value(value: int, size: int) -> int:
    return value & ((1 << size * 8) - 1)

@dataclass
class MapRange:
    start: int
    end: int

def get_wanted_pages(data: Dict[int, int]) -> List[MapRange]:
    page_mapping_list: List[MapRange] = []
    sorted_keys = list(data.keys())
    sorted_keys.sort()
    for address in sorted_keys:
        content_len = data[address]
        min_mapping = round_offset_to_page(address, False)
        max_mapping = round_offset_to_page(address + content_len, True)
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

    
class Emulator:
    def __init__(self) -> None:
        if ida_pro.IDA_SDK_VERSION < 850:
            inf_struct = ida_idaapi.get_inf_structure()
            self.bitness = 64 if inf_struct.is_64bit() else (32 if inf_struct.is_32bit() else 16)
            self.endianess = inf_struct.is_be()
        else:
            self.bitness = 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16)
            self.endianess = ida_ida.inf_is_be()

        self.arch = ida_idp.ph_get_id()
        unicorn_arch, mode, self.stack_register, self.pointer_size = arch_info[self.arch][self.bitness]
        self.endianess_string = "big" if self.endianess else "little"
        # TODO init global offset table for mips
        # TODO Map imports to zero
        # TODO implement memcpy and memcmp for use instead of imports
        self.mu: unicorn.Uc = unicorn.Uc(unicorn_arch, mode | (unicorn.UC_MODE_BIG_ENDIAN if self.endianess else unicorn.UC_MODE_LITTLE_ENDIAN))
        self.param_address = 0x1000_0000
        self.stack_address = 0x2000_0000
        self.mapped_vars: List[int, int] = []
        self.stack_size = 4096 * 10
        self.mu.mem_map(self.stack_address, 4096 * 10)
        self.stack_pointer = self.stack_address + 4096 * 5
    
    @contextmanager
    def init_function(self, function: Function) -> None:
        memory_mappings: List[Tuple[int, int]] = []
        try:
            self.param_counter = 0
            self.function = function
            mappings = get_wanted_pages({address: len(content) for address, content in function.memory_mappings.items()})
            #print([hex(map.start) + " " + hex(map.end) for map in  mappings])
            for map in mappings:
                size = map.end - map.start
                memory_mappings.append((map.start, size))
                self.mu.mem_map(map.start, size)
            for address, content in function.memory_mappings.items():
                self.mu.mem_write(address, content)
            self.__setup_calling_convention(function)
            yield
        finally:
            for mapped_memory in memory_mappings:
                self.mu.mem_unmap(*mapped_memory)
            memory_mappings.clear()

    def __setup_calling_convention(self, function: Function):
        if function.calling_convention != ida_typeinf.CM_CC_SPECIAL:
            try:
                self.calling_convention: Dict[int, Dict[LocationType, List[int]]] = \
                    calling_conventions[self.arch][self.bitness][ida_typeinf.default_compiler()][function.calling_convention]
            except KeyError:
                print("The current compiler has no suitable calling convention for the current architecture")
        elif self.arch == ida_idp.PLFM_386:
            # TODO Research how the ida_typeinf.idc_get_type_raw_works() to save decompiling and enable emulating user call without decompiler
            func = ida_hexrays.decompile(function.start_address)
            func_data = ida_typeinf.func_type_data_t()
            func.type.get_func_details(func_data)
            self.calling_convention: Dict[LocationType, List[int]]= {
                LocationType.arg : [

                ],
                LocationType.result : [

                ]
            }
            item: ida_typeinf.argloc_t = None
            regname = ida_idp.get_reg_name(func_data.retloc.reg1(), 8)
            self.calling_convention[LocationType.result].append(x86_x64_reg_map[regname][func_data.rettype.get_size()])
            for item in func_data:
                if item.argloc.atype() == ida_typeinf.ALOC_REG1:
                    item_regname = ida_idp.get_reg_name(item.argloc.reg1(), 8)
                    self.calling_convention[LocationType.arg].append(x86_x64_reg_map[item_regname][item.type.get_size()])
        else:
            raise ValueError("There shouldn't be a usercall in non intel platform")
            

    def __init_param(self, index: int, param_type: ida_typeinf.tinfo_t, content: Any, calling_convention: List[int]) -> None:
        allocated = False
        if param_type.is_ptr():
            allocated = True
            param_size = len(content)
            param_content = content
            if type(param_content) == str:
                param_content = param_content.encode("ascii") + b"\0"   
        else:
            param_content = content
            param_size = param_type.get_size()
        if index >= len(calling_convention):
            size = param_size
            value = param_content
            if allocated:
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
            self.mu.mem_write(self.stack_pointer, value.to_bytes(size, self.endianess_string))
            self.stack_pointer += self.pointer_size
        else:
            current_param_reg: int = calling_convention[index]
            if allocated:
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
    def run(self, prototype: ida_typeinf.func_type_data_t, params: List[Any]) -> None:
        try:
            self.result = 0
            self.out_params: List[Any] = []
            self.params = params
            original_stack_pointer = self.stack_pointer
            for i, param in enumerate(params):
                self.__init_param(i, prototype[i].type, param, self.calling_convention[LocationType.arg])
            try:
                self.mu.reg_write(self.stack_register, original_stack_pointer - self.pointer_size)
                self.mu.emu_start(self.function.start_address, -1)
            except unicorn.UcError as e:
                pass
            reg = self.calling_convention[LocationType.result][0]
            self.result = self.mu.reg_read(reg)
            rettype = prototype.rettype
            if rettype.is_signed():
                size = rettype.get_size()
                value_mask = (1 << ((size * 8) + 1)) - 1
                self.result &= value_mask
                self.result = self.result | (-(self.result & 0x80 << (8 * (size - 1))))
            yield
        finally:
            self.result = 0
            self.out_params: List[Any] = []
            self.params = None
            for mapped_var in self.mapped_vars:
                self.mu.mem_unmap(*mapped_var)
            self.mapped_vars.clear()
            self.mu.mem_write(self.stack_address, b"\x00" * self.stack_size)
            self.stack_pointer = original_stack_pointer
            self.param_address = 0x1000_0000
    
    def read_mem(self, offset: int, size: int) -> bytearray:
        return self.mu.mem_read(offset, size)


def get_emulator() -> Emulator:
    return Emulator()
    