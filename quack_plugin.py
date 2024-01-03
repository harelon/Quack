from quack import test_manager, datatypes, emulators

from idc import BADADDR
import ida_ua
import ida_xref
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_typeinf
import ida_hexrays

from typing import Dict

def get_string_list_count(string_list: bytes):
    current_offset = 0
    string_counter = 0
    while current_offset < len(string_list):
        current_offset += string_list[current_offset]
        string_counter += 1
    return string_counter

class QuackPlugin(ida_idaapi.plugin_t):
    flags = 0
    max_depth = 2
    wanted_name = "Quack"
    wanted_hotkey = "Shift-Q"
    
    def init(self):
        self.__manager = test_manager.TestManager()
        self.emulator = emulators.get_emulator()
        return ida_idaapi.PLUGIN_KEEP

    def __generate_memory_mappings(self, current_func: ida_funcs.func_t) -> Dict[int, bytes] | None:
        current_insn = ida_ua.insn_t()
        memory_mappings = {}
        # map data used by the function such as jump tables
        # iterate each address in the function and its tails
        iterate_parts = [(0, True, current_func)]
        while len(iterate_parts) > 0:
            depth, is_func, current_item = iterate_parts.pop()
            ea = current_item.start_ea
            if ea in memory_mappings.keys():
                continue
            current_tails = current_item.tails
            if None in current_tails:
                print("Cannot calculate function dependencies, please reanalyze program")
                return None
            tails = {} if not is_func else {tail.start_ea: tail for tail in current_tails}
            current_disas = ea
            while current_disas < current_item.end_ea:
                data = ida_xref.get_first_dref_from(current_disas)
                if data != BADADDR and data not in memory_mappings.keys():
                    memory_mappings[data] = ida_bytes.get_bytes(data, ida_bytes.get_item_size(data))
                # add code references if we haven't passed the max depth
                if depth < QuackPlugin.max_depth:
                    # get code xrefs
                    cref = ida_xref.get_first_cref_from(current_disas)
                    while cref != BADADDR:
                        # if the xref is not inside the current function
                        if not current_item.start_ea <= cref <= current_item.end_ea:
                            
                            # we don't want to map a function without its tails
                            if cref in tails.keys():
                                iterate_parts.append((depth, False, tails[cref]))
                            # add 1 to depth if it is not a tail and insert the function to the list
                            else:
                                iterate_parts.append((depth + 1, True, ida_funcs.get_func(cref)))
                        cref = ida_xref.get_next_cref_from(current_disas, cref)

                current_disas += ida_ua.decode_insn(current_insn, current_disas)

            memory_mappings[ea] = ida_bytes.get_bytes(ea, current_item.size())
        
        return memory_mappings

    def run(self, arg):
        current_ea = ida_kernwin.get_screen_ea()
        current_func: ida_funcs.func_t = ida_funcs.get_func(current_ea)
        if current_func is None:
            return 0

        # get the calling convention and amount of params for the function
        # try to use caching instead of decompiling the function again which may take some time
        result = ida_typeinf.idc_get_type_raw(current_func.start_ea)
        if result is None:
            if ida_hexrays.init_hexrays_plugin():
                func = ida_hexrays.decompile(current_func.start_ea)
                func_data = ida_typeinf.func_type_data_t()
                func.type.get_func_details(func_data)
                args_count = func_data.size()
                cc = func_data.cc & ida_typeinf.CM_CC_MASK
            else:
                print(f"no prototype initialized for function 0x{current_func.start_ea:x} and no decompiler")
                return 0
        # use the cached version
        else:
            convention, args = result[0], result[1]
            cc = convention[1] & ida_typeinf.CM_CC_MASK
            args_count = get_string_list_count(args)

        mappings = self.__generate_memory_mappings(current_func)
        if mappings is not None:
            testing_function = datatypes.Function(args_count, cc, current_func.start_ea, mappings)
            print(f"Suggested name is {self.__manager.test(self.emulator, testing_function)}")
        return 0

    def term(self):
        pass



def PLUGIN_ENTRY():
    return QuackPlugin()