import unicorn

import ida_idp
import ida_idaapi
import ida_hexrays
import ida_typeinf

from typing import List, Dict, Tuple, Any
from contextlib import contextmanager
from dataclasses import dataclass

from quack.unicorn_2_ida_consts import calling_conventions, x86_x64_reg_map, arch_info, LocationType
from quack.datatypes import Function, ParamType, FunctionPrototype, Pointer

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
        inf_struct = ida_idaapi.get_inf_structure()
        self.bitness = 64 if inf_struct.is_64bit() else (32 if inf_struct.is_32bit() else 16)
        self.arch = ida_idp.ph_get_id()
        unicorn_arch, mode, self.stack_register, self.pointer_size = arch_info[self.arch][self.bitness]
        self.endianess = inf_struct.is_be()
        self.endianess_string = "big" if self.endianess else "little"
        # TODO init global offset table for mips
        # TODO Map imports to zero
        # TODO implement usercall
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
            mappings = get_wanted_pages({address: len(content) for address, content in function.memory_mappings.items()})
            #print([hex(map.start) + " " + hex(map.end) for map in  mappings])
            #print({hex(key): len(value) for key, value in function.memory_mappings.items()})
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
            #func.get_func_details(func_data)
            item: ida_typeinf.argloc_t = None
            self.calling_convention[LocationType.result].append(x86_x64_reg_map[func_data.retloc.reg1()][func_data.rettype.get_size()])
            for item in func_data:
                if item.argloc.atype() == ida_typeinf.ALOC_REG1:
                    self.calling_convention[LocationType.arg].append(x86_x64_reg_map[item.argloc.reg1()][item.type.get_size()])
        else:
            raise ValueError("There shouldn't be a usercall in non intel platform")

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
        elif param == ParamType.COMPOUND:
            size = 0
            for param_type, _ in content:
                if param_type == ParamType.COMPOUND:
                    param_type, content = ParamType.INT, 0
                param_size, _ = self.__resolve_param(param_type, content)
                size += param_size
            return size, None
            

    def __init_param(self, index: int, param_type: ParamType, content: Any, calling_convention: List[int]) -> None:
        if param_type == ParamType.COMPOUND:
            saved_param = self.param_address
            item_queue = [(self.param_address, param_type, content)]
            while len(item_queue) > 0:
                ea, param_type, param_content = item_queue.pop()
                param_size, param_content = self.__resolve_param(param_type, param_content)
                if param_type == ParamType.COMPOUND:
                    param_size = round_offset_to_page(param_size)
                    self.mu.mem_map(self.param_address, param_size)
                    current_offset = 0
                    for param_type, compound_param_content in param_content:
                        item_queue.append((self.param_address + current_offset, param_type, compound_param_content))
                        current_offset += self.__resolve_param(param_type, param_content)
                    self.param_address += param_size
                else:
                    self.mu.mem_write(ea, param_content)
            param_type = ParamType.UINT
            param_content = saved_param

        param_size, param_content = self.__resolve_param(param_type, content)
        if index >= len(calling_convention):
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
            current_param_reg: int = calling_convention[index]
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
            self.result = 0
            self.out_params: List[Any] = []
            self.params = params
            original_stack_address = self.stack_address
            for i, param in enumerate(params):
                self.__init_param(i, prototype[i], param, self.calling_convention[LocationType.arg])
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
            reg = self.calling_convention[LocationType.result][0]
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


def get_emulator() -> Emulator:
    return Emulator()
    