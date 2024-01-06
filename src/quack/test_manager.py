import ida_typeinf

from typing import List, Dict, Any, Callable

from quack.emulators import Emulator
from quack.datatypes import Tests, Function, Test

class TestManager:
    _instance = None
    _testers: Dict[str, Tests] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TestManager, cls).__new__(cls)
        return cls._instance

    def _add_test(self, name: str, prototype_decl: str):
        if not prototype_decl.endswith(";"):
            raise ValueError("Function type definitions end with ';' in ida")
        tinfo = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tinfo, None, prototype_decl, 0)
        if tinfo.is_funcptr():
            raise ValueError("No need for function pointer, use the regular definition")
        if not tinfo.is_func():
            raise ValueError("Define a function please")
        prototype = ida_typeinf.func_type_data_t()
        tinfo.get_func_details(prototype)
        self._testers[name] = Tests(prototype=prototype)
        return self._testers[name]
    
    def test(self, emulator: Emulator, function: Function) -> str | None:
        with emulator.init_function(function):
            for name, tests in self._testers.items():
                if len(tests.prototype) != function.param_count:
                    # print(f"skipped testing function {name}")
                    continue
                # print(f"testing function {name}")
                if all(self.__run(emulator, test, tests.prototype) for test in tests.tests):
                    return name
        return None
    
    def __run(self, emulator: Emulator, test: Test, prototype: ida_typeinf.tinfo_t) -> bool:
        with emulator.run(prototype, test.params):
            condition = test.condition(emulator.result, emulator.params, emulator.out_params)
            # print(condition)
            return condition

def RegisterTester(name: str, prototype: str):
    return TestManager()._add_test(name, prototype)

def TestWrapper(tests: Tests, param_sets: List[Any]) -> Callable:
    def decorator(condition) -> Callable:
        for param_set in param_sets:
            if len(tests.prototype) != len(param_set):
                raise ValueError("Test params lens mismatch")
            tests.tests.append(Test(param_set, condition))
        def wrapper() -> None:
            pass
        return wrapper
    return decorator
