from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import Pointer

tester = RegisterTester(basename(__file__)[:-3], "int memcmp(const void *str1, const void *str2, size_t n);")

@TestWrapper(tester, [("asdf", "asdf", 4)])
def test_same(result, params: Any, outs: List[Pointer | None]):
    return result == 0

@TestWrapper(tester, [("asdf", "abcd", 2)])
def test_big(result, params: Any, outs: List[Pointer | None]):
    return result == 1

@TestWrapper(tester, [("abcd", "asdf", 2)])
def test_small(result, params: Any, outs: List[Pointer | None]):
    return result == -1

@TestWrapper(tester, [(b"abcd\x00abce", b"abcd\x00abcf", 9)])
def test_small2(result, params: Any, outs: List[Pointer | None]):
    return result == -1
