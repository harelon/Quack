from os.path import basename
from typing import List, Any
from quack.test_manager import RegisterTester, TestWrapper
from quack.datatypes import Pointer

tester = RegisterTester(basename(__file__)[:-3], "char *strcpy(char *dest, const char *src);")

@TestWrapper(tester, [(b"", "asdf"), (b"", "2138912axds")])
def test_same(result, params: Any, outs: List[Pointer | None]):
    return params[1].encode('ascii') + b'\0' == outs[0].get_pointed(len(params[1]) + 1)

@TestWrapper(tester, [(b"", b"asdf\x00asdfasda")])
def test_big(result, params: Any, outs: List[Pointer | None]):
    null_offset = params[1].find(b"\x00")
    is_copied = params[1][:null_offset] == outs[0].get_pointed(null_offset)
    after_zero = outs[0].get_pointed(len(params[1]))[null_offset:]
    is_empty = after_zero == b"\x00" * len(after_zero)
    return is_copied and is_empty
