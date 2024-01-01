from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester(basename(__file__)[:-3], FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.UINT8, ParamType.UINT]))

@TestWrapper(tester, [(b"asdf\x00\x00asdf", ord('a'), 10), (b"asdf\x00\x00asdf", ord('b'), 5)])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address and \
        outs[0].get_pointed(params[2]) == bytes([params[1]]) * params[2]
