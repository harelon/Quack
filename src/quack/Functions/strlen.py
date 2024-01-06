from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import Pointer

tester = RegisterTester(basename(__file__)[:-3], "size_t strlen(const char *str);")

@TestWrapper(tester, [(b"asdf\x00\x00asdf",)])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == params[0].find(b"\x00")

@TestWrapper(tester, [("a",), ("a2342342343sddssd",)])
def test_small(result, params: Any, outs: List[Pointer | None]):
    return result == len(params[0])
