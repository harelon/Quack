from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester(basename(__file__)[:-3], FunctionPrototype(ParamType.INT, [ParamType.BYTES]))

@TestWrapper(tester, [("-5",), ("5",), ("37",)])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == int(params[0])

@TestWrapper(tester, [(b"53\x0024",)])
def test_bytes2(result, params: Any, outs: List[Pointer | None]):
    return result == 53
