from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import Pointer

tester = RegisterTester(basename(__file__)[:-3], "void *memchr(const void *str, int c, size_t n);")

@TestWrapper(tester, [(b"asdf\x00\x00asdfe", ord('e'), 11)])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address + len(params[0]) - 1

@TestWrapper(tester, [("abccde", ord('c'), 6)])
def test_small(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address + 2

@TestWrapper(tester, [("abccde", ord('f'), 6)])
def test_mall(result, params: Any, outs: List[Pointer | None]):
    return result == 0
