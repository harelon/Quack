from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester(basename(__file__)[:-3], FunctionPrototype(ParamType.UINT, [ParamType.BYTES, ParamType.BYTES]))

@TestWrapper(tester, [(b"asdf\x00\x00asdf", b"hi\x00")])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address and \
        outs[0].get_pointed(10) == b"asdfhi\x00sdf"