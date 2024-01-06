from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import Pointer

tester = RegisterTester(basename(__file__)[:-3], "char *strchr(const char *str, int c);")

@TestWrapper(tester, [(b"asdf\x00\x00asdf", ord('a'))])
def test_bytes(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address

@TestWrapper(tester, [("abccde", ord('c'))])
def test_small(result, params: Any, outs: List[Pointer | None]):
    return result == outs[0].address + 3

@TestWrapper(tester, [("abccde", ord('f'))])
def test_mall(result, params: Any, outs: List[Pointer | None]):
    return result == 0
