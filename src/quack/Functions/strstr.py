from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester(basename(__file__)[:-3], FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.BYTES]))

@TestWrapper(tester, [("Hello, World!", "World"), ("Programming is fun!", "is"), ("Mississippi", "ss")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address + params[0].find(params[1])

@TestWrapper(tester, [("This is a test", "exam")])
def test_mall(result, params: Any, outs: List[Pointer | None]):
    return result == 0
