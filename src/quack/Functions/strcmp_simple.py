from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import ParamType, FunctionPrototype, Pointer

tester = RegisterTester(basename(__file__)[:-3], FunctionPrototype(ParamType.INT8, [ParamType.BYTES, ParamType.BYTES]))

@TestWrapper(tester, [("asdf", "asdf")])
def test_same(result, params: Any, outs: List[Pointer | None]):
    return result == 0

@TestWrapper(tester, [("asdf", "abcd")])
def test_big(result, params: Any, outs: List[Pointer | None]):
    return result == 1

@TestWrapper(tester, [("abcd", "asdf")])
def test_small(result, params: Any, outs: List[Pointer | None]):
    return result == -1

@TestWrapper(tester, [(b"abcd\x00abce", b"abcd\x00abcf")])
def test_small2(result, params: Any, outs: List[Pointer | None]):
    return result == 0